"""Time off over HTTP (docs/features/time-off.md, backend). HTTP only: the rules are in
service.py.

    GET  /api/time-off-requests?mine=true                      200  your own requests
    GET  /api/time-off-requests?status=&employee_id=&from=&to= 200  requests in your scope
    GET  /api/time-off-requests/{id}                           200  one, with affected shifts
    POST /api/time-off-requests  {first_day, last_day, reason} 201  ask for time off
    POST /api/time-off-requests/{id}/cancel                    200  cancel your own

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's), 409
overlapping days or not cancellable now, 422 invalid input. Every change also needs the
CSRF token.
"""

import uuid
from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Query

# Registers what time-off approval records do, and where a request belongs.
import app.modules.time_off.approval  # noqa: F401
import app.modules.time_off.scope  # noqa: F401
from app.auth.dependencies import Database, SignedInPerson
from app.modules.time_off import service
from app.modules.time_off.models import TimeOffRequest
from app.modules.time_off.schemas import (
    AffectedShift,
    Decision,
    TimeOffCreate,
    TimeOffDetail,
    TimeOffList,
    TimeOffOut,
)

router = APIRouter(prefix="/api/time-off-requests", tags=["time off"])


def _out(item: TimeOffRequest, not_reviewed: bool) -> TimeOffOut:
    return TimeOffOut(
        id=item.id,
        employee_id=item.employee_id,
        first_day=item.first_day,
        last_day=item.last_day,
        reason=item.reason,
        status=item.status,
        not_reviewed=not_reviewed,
        created_at=item.created_at,
        decided_at=item.decided_at,
    )


def _detail(db: Database, detail: service.Detail) -> TimeOffDetail:
    item = detail.request
    flags = service.not_reviewed(db, [item])
    return TimeOffDetail(
        **_out(item, flags[item.id]).model_dump(),
        affected_shifts=[
            AffectedShift(
                id=s.id, department_id=s.department_id, starts_at=s.starts_at, ends_at=s.ends_at
            )
            for s in detail.affected_shifts
        ],
        decisions=[
            Decision(approver_id=d.approver_id, decision=d.decision, decided_at=d.decided_at)
            for d in detail.decisions
        ],
    )


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
    flags = service.not_reviewed(db, rows)
    return TimeOffList(items=[_out(row, flags[row.id]) for row in rows])


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
    return _out(request, service.not_reviewed(db, [request])[request.id])
