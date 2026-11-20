"""Time off over HTTP (docs/features/time-off.md, backend). HTTP only: the rules are in
service.py.

    GET  /api/time-off-requests?mine=true                      200  your own requests
    GET  /api/time-off-requests?status=&employee_id=&from=&to= 200  requests in your scope
    GET  /api/time-off-requests/waiting                        200  waiting for my review
    GET  /api/time-off-requests/offerable                      200  coworkers' requests to answer
    GET  /api/time-off-requests/{id}                           200  one, with shifts and offers
    POST /api/time-off-requests  {first_day, last_day, reason, offer_coverage}
                                                               201  ask for time off
    POST /api/time-off-requests/{id}/send-up                   200  send your own up to managers
    PUT  /api/time-off-requests/{id}/offers/{shift_id}  {answer, swap_shift_id}
                                                               200  answer for one shift
    DELETE /api/time-off-requests/{id}/offers/{shift_id}       204  take your answer back
    POST /api/time-off-requests/{id}/cancel                    200  cancel your own
    POST /api/time-off-requests/{id}/approve  {comment}        200  approve as a reviewer
    POST /api/time-off-requests/{id}/deny     {comment}        200  deny as a reviewer

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's), 409
overlapping days, not cancellable now, already decided, too late to ask with offers, offers
closed, or an offer the rules refuse (the message says why; coverage.md), 422 invalid
input. Every
change also needs the CSRF token.
"""

import uuid
from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Response
from sqlalchemy import select

# Registers what time-off approval records do, and where a request belongs.
import app.modules.time_off.approval  # noqa: F401
import app.modules.time_off.scope  # noqa: F401
from app.auth.dependencies import Database, SignedInPerson
from app.modules.org.models import User
from app.modules.schedules.models import Shift
from app.modules.time_off import offers, service
from app.modules.time_off.models import CoverageOffer, TimeOffRequest
from app.modules.time_off.schemas import (
    AffectedShift,
    Decision,
    DecisionBody,
    Offerable,
    OfferableList,
    OfferBody,
    OfferOut,
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
        offers_close_at=item.offers_close_at,
        sent_up_at=item.sent_up_at,
        progress=_progress(progress, names),
    )


def _shift(item: Shift) -> AffectedShift:
    return AffectedShift(
        id=item.id, department_id=item.department_id, starts_at=item.starts_at, ends_at=item.ends_at
    )


def _offers(db: Database, found: list[CoverageOffer]) -> list[OfferOut]:
    """Offers in the answer shape, with the coworkers' names and any swap shift, in two
    queries for the whole list."""
    names = _names(db, {offer.offered_by for offer in found})
    swap_ids = {offer.swap_shift_id for offer in found if offer.swap_shift_id}
    swaps = (
        {s.id: s for s in db.scalars(select(Shift).where(Shift.id.in_(swap_ids)))}
        if swap_ids
        else {}
    )
    return [
        OfferOut(
            id=offer.id,
            shift_id=offer.shift_id,
            offered_by=offer.offered_by,
            offered_by_name=names.get(offer.offered_by, "Unknown"),
            answer=offer.answer,
            swap_shift=_shift(swaps[offer.swap_shift_id]) if offer.swap_shift_id in swaps else None,
            status=offer.status,
            updated_at=offer.updated_at,
        )
        for offer in found
    ]


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
        affected_shifts=[_shift(s) for s in detail.affected_shifts],
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
        offers=_offers(db, detail.offers),
    )


def _detail_for(db: Database, detail: service.Detail) -> TimeOffDetail:
    """The detail, without who is still to decide when seen by a coworker (I10)."""
    answer = _detail(db, detail)
    if detail.as_coworker:
        answer.progress = None
    return answer


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
    status: Literal["collecting", "pending", "escalated", "approved", "denied", "cancelled"]
    | None = None,
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


@router.get("/offerable")
def offerable(current: SignedInPerson, db: Database) -> OfferableList:
    """Coworkers' collecting requests with a shift the user could take (coverage.md)."""
    found = offers.offerable(db, current.user)
    names = _names(db, {item.request.employee_id for item in found})
    return OfferableList(
        items=[
            Offerable(
                request=_out(item.request, False, names),
                shifts=[_shift(s) for s in item.shifts],
                answers=_offers(db, item.answers),
            )
            for item in found
        ]
    )


@router.get("/{request_id}")
def view_request(request_id: uuid.UUID, current: SignedInPerson, db: Database) -> TimeOffDetail:
    return _detail_for(db, service.view_request(db, current.user, request_id))


@router.post("", status_code=201)
def ask(body: TimeOffCreate, current: SignedInPerson, db: Database) -> TimeOffDetail:
    request = service.ask(db, current.user, body)
    return _detail(db, service.view_request(db, current.user, request.id))


@router.post("/{request_id}/send-up")
def send_up(request_id: uuid.UUID, current: SignedInPerson, db: Database) -> TimeOffOut:
    request = service.send_up(db, current.user, request_id)
    return _one(db, request)


@router.put("/{request_id}/offers/{shift_id}")
def answer(
    request_id: uuid.UUID,
    shift_id: uuid.UUID,
    body: OfferBody,
    current: SignedInPerson,
    db: Database,
) -> OfferOut:
    offer = offers.answer(db, current.user, request_id, shift_id, body)
    return _offers(db, [offer])[0]


@router.delete("/{request_id}/offers/{shift_id}", status_code=204)
def withdraw(
    request_id: uuid.UUID, shift_id: uuid.UUID, current: SignedInPerson, db: Database
) -> Response:
    offers.withdraw(db, current.user, request_id, shift_id)
    return Response(status_code=204)


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
