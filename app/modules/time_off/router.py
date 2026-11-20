"""Time off over HTTP (docs/features/time-off.md, backend). HTTP only: the rules are in
service.py.

    GET  /api/time-off-requests?mine=true                      200  your own requests
    GET  /api/time-off-requests?status=&employee_id=&from=&to= 200  requests in your scope
    GET  /api/time-off-requests/waiting                        200  waiting for my review
    GET  /api/time-off-requests/{id}                           200  one, with affected shifts
    POST /api/time-off-requests  {first_day, last_day, reason} 201  ask for time off
    POST /api/time-off-requests/{id}/cancel                    200  cancel your own
    POST /api/time-off-requests/{id}/approve  {comment}        200  approve as a reviewer
    POST /api/time-off-requests/{id}/deny     {comment}        200  deny as a reviewer

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's), 409
overlapping days, not cancellable now, or already decided, 422 invalid input. Every
change also needs the CSRF token.
"""

import uuid
from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Query
from sqlalchemy import select

# Registers what time-off approval records do, and where a request belongs.
import app.modules.time_off.approval  # noqa: F401
import app.modules.time_off.scope  # noqa: F401
from app.auth.dependencies import Database, SignedInPerson
from app.modules.org.models import User
from app.modules.time_off import service
from app.modules.time_off.models import TimeOffRequest
from app.modules.time_off.schemas import (
    AffectedShift,
    Decision,
    DecisionBody,
    Person,
    Progress,
    Step,
    TimeOffCreate,
    TimeOffDetail,
    TimeOffList,
    TimeOffOut,
)

router = APIRouter(prefix="/api/time-off-requests", tags=["time off"])


def _names(db: Database, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    """Display names by ID, in one query for a whole answer (not one per row)."""
    if not ids:
        return {}
    rows = db.execute(select(User.id, User.display_name).where(User.id.in_(ids)))
    return {person_id: name for person_id, name in rows}


def _names_in(found: dict[uuid.UUID, service.Progress]) -> set[uuid.UUID]:
    """Everyone a set of Progress answers names: who decided and who still has to."""
    return {d.approver_id for p in found.values() for d in p.decided} | {
        person for p in found.values() for person in p.waiting_for
    }


def _progress(found: service.Progress | None, names: dict[uuid.UUID, str]) -> Progress | None:
    """A request's Progress in the answer shape (None once it is settled)."""
    if found is None:
        return None
    return Progress(
        decided=[
            Step(
                approver_id=d.approver_id,
                approver_name=names.get(d.approver_id, "Unknown"),
                decision=d.decision,
            )
            for d in found.decided
        ],
        waiting_for=[
            Person(id=person, display_name=names.get(person, "Unknown"))
            for person in found.waiting_for
        ],
    )


def _out(
    item: TimeOffRequest,
    not_reviewed: bool,
    names: dict[uuid.UUID, str],
    progress: service.Progress | None = None,
) -> TimeOffOut:
    return TimeOffOut(
        id=item.id,
        employee_id=item.employee_id,
        employee_name=names.get(item.employee_id, "Unknown"),
        first_day=item.first_day,
        last_day=item.last_day,
        reason=item.reason,
        status=item.status,
        not_reviewed=not_reviewed,
        created_at=item.created_at,
        decided_at=item.decided_at,
        progress=_progress(progress, names),
    )


def _detail(db: Database, detail: service.Detail) -> TimeOffDetail:
    item = detail.request
    flags = service.not_reviewed(db, [item])
    comments = service.comments(db, item)
    found = service.progress(db, [item])
    names = _names(
        db, {item.employee_id} | {d.approver_id for d in detail.decisions} | _names_in(found)
    )
    return TimeOffDetail(
        **_out(item, flags[item.id], names, found.get(item.id)).model_dump(),
        affected_shifts=[
            AffectedShift(
                id=s.id, department_id=s.department_id, starts_at=s.starts_at, ends_at=s.ends_at
            )
            for s in detail.affected_shifts
        ],
        decisions=[
            Decision(
                approver_id=d.approver_id,
                approver_name=names.get(d.approver_id, "Unknown"),
                decision=d.decision,
                decided_at=d.decided_at,
                comment=comments.get(str(d.approver_id)),
            )
            for d in detail.decisions
        ],
    )


def _list(db: Database, rows: list[TimeOffRequest]) -> TimeOffList:
    flags = service.not_reviewed(db, rows)
    # Where each open request stands, and every name the answer needs, in one lookup.
    found = service.progress(db, rows)
    names = _names(db, {row.employee_id for row in rows} | _names_in(found))
    return TimeOffList(items=[_out(row, flags[row.id], names, found.get(row.id)) for row in rows])


def _one(db: Database, request: TimeOffRequest) -> TimeOffOut:
    return _list(db, [request]).items[0]


@router.get("")
def list_requests(
    current: SignedInPerson,
    db: Database,
    mine: bool = False,
    status: Literal["pending", "escalated", "approved", "denied", "cancelled"] | None = None,
    employee_id: uuid.UUID | None = None,
    first: Annotated[date | None, Query(alias="from")] = None,
    last: Annotated[date | None, Query(alias="to")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> TimeOffList:
    rows = service.list_requests(
        db,
        current.user,
        mine=mine,
        status=status,
        employee_id=employee_id,
        first=first,
        last=last,
        limit=limit,
    )
    return _list(db, rows)


@router.get("/waiting")
def waiting(
    current: SignedInPerson, db: Database, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> TimeOffList:
    rows = service.waiting(db, current.user, limit=limit)
    return _list(db, rows)


@router.get("/{request_id}")
def view_request(request_id: uuid.UUID, current: SignedInPerson, db: Database) -> TimeOffDetail:
    return _detail(db, service.view_request(db, current.user, request_id))


@router.post("", status_code=201)
def ask(body: TimeOffCreate, current: SignedInPerson, db: Database) -> TimeOffDetail:
    request = service.ask(db, current.user, body)
    return _detail(db, service.view_request(db, current.user, request.id))


@router.post("/{request_id}/cancel")
def cancel(request_id: uuid.UUID, current: SignedInPerson, db: Database) -> TimeOffOut:
    request = service.cancel(db, current.user, request_id)
    return _one(db, request)


@router.post("/{request_id}/approve")
def approve(
    request_id: uuid.UUID, current: SignedInPerson, db: Database, body: DecisionBody | None = None
) -> TimeOffOut:
    comment = body.comment if body else None
    request = service.decide_request(db, current.user, request_id, "approve", comment)
    return _one(db, request)


@router.post("/{request_id}/deny")
def deny(
    request_id: uuid.UUID, current: SignedInPerson, db: Database, body: DecisionBody | None = None
) -> TimeOffOut:
    comment = body.comment if body else None
    request = service.decide_request(db, current.user, request_id, "deny", comment)
    return _one(db, request)
