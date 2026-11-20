"""Coworkers' offers on a time-off request asked with "Offer Shift Swap / Coverage"
(docs/features/coverage.md, states and rules).

While a request is collecting, each coworker who could work one of its shifts may answer
for that shift: cover it, swap it for one of their own shifts, or decline. One answer per
coworker per shift; a new answer replaces the old one, and taking it back removes it.
Offers close when the request goes up to the managers.

Who may offer, per shift (offer_problem; checked when offering, and again at approval):
- never the employee themselves;
- someone who could be assigned that shift (the same rule as assigning,
  app/modules/schedules/repository.py, assignable): threat T8;
- cover: no overlapping shift of their own and no approved time off then;
- swap: the shift given is their own, scheduled, not started, in the same department, and
  outside the employee's time off; the employee could work it (no overlap, no approved
  time off then); and after the exchange neither has two overlapping shifts (the two
  traded shifts are left out of that check).

Who sees what (threat I10): a coworker sees the request and only their own answers; the
employee and the people who see the request as managers see every offer.

Locks, in the order every time-off change takes them: the employee's row, the request,
then the coworker's row. Holding the request's row means an offer and sending the request
up take turns, so no offer slips in after the request went up.

Every change is audited (coverage.offered, coverage.withdrawn) and commits once.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.authz.check import authorize, grants
from app.db.base import utcnow
from app.modules.org import repository as people
from app.modules.org.models import User
from app.modules.org.service import Conflict, Invalid, NotFound
from app.modules.schedules import repository as schedules
from app.modules.schedules.models import Shift
from app.modules.time_off.days import days_span, zone_of
from app.modules.time_off.models import CoverageOffer, TimeOffRequest
from app.modules.time_off.review import overlapping_shifts
from app.modules.time_off.schemas import OfferBody

# Why an offer is refused, in words the coworker can act on (409).
OWN_REQUEST = "You cannot offer on your own request."
CLOSED = "This request already went to the managers, so offers are closed."
CANNOT_TAKE = "You cannot be assigned this shift."
BUSY = "You already have a shift at that time."
AWAY = "You have approved time off at that time."
NOT_YOURS = "The shift you give must be one of your own scheduled shifts that has not started."
OTHER_DEPARTMENT = "The shift you give must be in the same department."
DURING = "The shift you give is during the time off."
EMPLOYEE_CANNOT = "The person asking could not work the shift you give."
NO_SWAP_SHIFT = "Choose one of your own shifts to give."


# --- Who may offer ---------------------------------------------------------------------


def takeable(db: Session, user: User, request: TimeOffRequest) -> list[Shift]:
    """The request's shifts the user could be assigned (never on their own request)."""
    if user.id == request.employee_id:
        return []
    return [
        shift
        for shift in overlapping_shifts(db, request)
        if schedules.assignable(db, user, shift.department_id)
    ]


def offer_problem(
    db: Session,
    request: TimeOffRequest,
    shift: Shift,
    coworker: User,
    answer: str,
    swap: Shift | None,
) -> str | None:
    """Why this coworker may not give this answer for this shift, or None if they may.

    The overlap and time-off reads lock the rows they read (FOR SHARE, as assigning
    does), so a change committed meanwhile is seen.
    """
    # Step 1: anyone answering, even declining, must be someone who could work it.
    if coworker.id == request.employee_id:
        return OWN_REQUEST
    if not schedules.assignable(db, coworker, shift.department_id):
        return CANNOT_TAKE
    if answer == "decline":
        return None
    # Step 2: the coworker is free at the requested shift's time (for a swap, the shift
    # they give is left out: it becomes the employee's).
    left_out = swap.id if swap is not None else None
    if schedules.has_overlap(db, coworker.id, shift.starts_at, shift.ends_at, ignore=left_out):
        return BUSY
    if schedules.on_time_off(db, coworker, shift.starts_at, shift.ends_at):
        return AWAY
    if answer == "cover":
        return None
    # Step 3, swaps only: the shift given is the coworker's own, still to come, in the
    # same department, and outside the days the employee asked for.
    if swap is None:
        return NO_SWAP_SHIFT
    if swap.employee_id != coworker.id or swap.status != "scheduled" or swap.starts_at <= utcnow():
        return NOT_YOURS
    if swap.department_id != shift.department_id:
        return OTHER_DEPARTMENT
    employee = db.get(User, request.employee_id)
    if employee is None:  # never deleted
        return EMPLOYEE_CANNOT
    start, end = days_span(zone_of(db, employee), request.first_day, request.last_day)
    if swap.starts_at < end and swap.ends_at > start:
        return DURING
    # Step 4: the employee could work the shift they get, with the shift they give away
    # left out of the overlap check.
    if (
        not schedules.assignable(db, employee, swap.department_id)
        or schedules.has_overlap(
            db, employee.id, swap.starts_at, swap.ends_at, ignore=shift.id, also_ignore=swap.id
        )
        or schedules.on_time_off(db, employee, swap.starts_at, swap.ends_at)
    ):
        return EMPLOYEE_CANNOT
    return None


# --- Seeing offers ---------------------------------------------------------------------


def offers_on(db: Session, request: TimeOffRequest) -> list[CoverageOffer]:
    """Every offer on a request, oldest first (for the employee and managers)."""
    return list(
        db.scalars(
            select(CoverageOffer)
            .where(CoverageOffer.time_off_request_id == request.id)
            .order_by(CoverageOffer.created_at, CoverageOffer.id)
        )
    )


def own_offers(db: Session, user: User, request: TimeOffRequest) -> list[CoverageOffer]:
    """Only the user's own answers on a request (what a coworker sees, threat I10)."""
    return [offer for offer in offers_on(db, request) if offer.offered_by == user.id]


def sees_as_coworker(db: Session, user: User, request: TimeOffRequest) -> bool:
    """Whether a coworker may see the request: they hold coverage.respond_self and either
    answered on it, or it is still collecting and they could work one of its shifts."""
    if user.id == request.employee_id or not grants(db, user, "coverage.respond_self"):
        return False
    if own_offers(db, user, request):
        return True
    return request.status == "collecting" and bool(takeable(db, user, request))


@dataclass
class Offerable:
    """A collecting request the user could answer, with the shifts they could take."""

    request: TimeOffRequest
    shifts: list[Shift]
    answers: list[CoverageOffer]


def offerable(db: Session, user: User) -> list[Offerable]:
    """The collecting requests of others with a shift the user could take, soonest first.
    Requests past their send-up deadline go up first (service.refresh) and are left out."""
    authorize(db, user, "coverage.respond_self")
    # Imported here: service.py imports this module for the request page.
    from app.modules.time_off.service import refresh

    rows = list(
        db.scalars(
            select(TimeOffRequest)
            .where(TimeOffRequest.status == "collecting", TimeOffRequest.employee_id != user.id)
            .order_by(TimeOffRequest.first_day, TimeOffRequest.id)
        )
    )
    refresh(db, rows)
    found = []
    for row in rows:
        if row.status != "collecting":
            continue
        shifts = takeable(db, user, row)
        if shifts:
            found.append(
                Offerable(row, sorted(shifts, key=lambda s: s.starts_at), own_offers(db, user, row))
            )
    return found


# --- Answering -------------------------------------------------------------------------


def _locked_request(db: Session, user: User, request_id: uuid.UUID) -> TimeOffRequest:
    """The request, locked in the time-off order (the employee, then the request), and
    still open for offers. Someone who could not see it as a coworker gets 404 (I10)."""
    from app.modules.time_off.service import send_up_if_due

    found = db.get(TimeOffRequest, request_id)
    if found is None:
        raise NotFound()
    if found.employee_id == user.id:
        raise Conflict(OWN_REQUEST)
    # Only someone who could work one of its shifts, or who answered on it, learns about
    # the request here; anyone else gets 404.
    if not (takeable(db, user, found) or own_offers(db, user, found)):
        raise NotFound()
    people.person(db, found.employee_id, lock=True)
    request = db.get(TimeOffRequest, request_id, populate_existing=True, with_for_update=True)
    if request is None:  # never deleted
        raise NotFound()
    # Past its deadline: it goes up now (as the system), and offers are closed.
    if send_up_if_due(db, request):
        db.commit()
        raise Conflict(CLOSED)
    if request.status != "collecting":
        raise Conflict(CLOSED)
    return request


def _request_shift(db: Session, request: TimeOffRequest, shift_id: uuid.UUID) -> Shift:
    """One of the request's shifts (the employee's, on those days), or 404."""
    for shift in overlapping_shifts(db, request):
        if shift.id == shift_id:
            return shift
    raise NotFound()


def answer(
    db: Session, user: User, request_id: uuid.UUID, shift_id: uuid.UUID, body: OfferBody
) -> CoverageOffer:
    """Give or change the user's answer for one shift of a collecting request."""
    authorize(db, user, "coverage.respond_self")
    request = _locked_request(db, user, request_id)
    shift = _request_shift(db, request, shift_id)
    # The coworker's row after the request's (the lock order), read fresh, so a
    # deactivation committed meanwhile is seen.
    coworker = people.person(db, user.id, lock=True)
    if coworker is None:  # the signed-in person always exists
        raise NotFound()
    swap = None
    if body.swap_shift_id is not None:
        # Unknown, or another company's (the company filter hides it): invalid input.
        swap = db.get(Shift, body.swap_shift_id)
        if swap is None:
            raise Invalid(NO_SWAP_SHIFT)
    problem = offer_problem(db, request, shift, coworker, body.answer, swap)
    if problem is not None:
        raise Conflict(problem)

    # One answer per coworker per shift: change the earlier one, or add it.
    offer = db.scalars(
        select(CoverageOffer).where(
            CoverageOffer.time_off_request_id == request.id,
            CoverageOffer.shift_id == shift.id,
            CoverageOffer.offered_by == user.id,
        )
    ).one_or_none()
    if offer is None:
        offer = CoverageOffer(time_off_request_id=request.id, shift_id=shift.id, offered_by=user.id)
        db.add(offer)
    offer.answer, offer.swap_shift_id, offer.status = body.answer, body.swap_shift_id, "offered"
    db.flush()
    record(
        db,
        actor=Actor.user(user.id),
        action="coverage.offered",
        target_type="time_off_request",
        target_id=request.id,
        details={
            "shift_id": str(shift.id),
            "answer": body.answer,
            "swap_shift_id": str(body.swap_shift_id) if body.swap_shift_id else None,
        },
    )
    db.commit()
    return offer


def withdraw(db: Session, user: User, request_id: uuid.UUID, shift_id: uuid.UUID) -> None:
    """Take back the user's answer for one shift, while the request is collecting."""
    authorize(db, user, "coverage.respond_self")
    request = _locked_request(db, user, request_id)
    offer = db.scalars(
        select(CoverageOffer).where(
            CoverageOffer.time_off_request_id == request.id,
            CoverageOffer.shift_id == shift_id,
            CoverageOffer.offered_by == user.id,
        )
    ).one_or_none()
    if offer is None:
        raise NotFound()
    db.delete(offer)
    record(
        db,
        actor=Actor.user(user.id),
        action="coverage.withdrawn",
        target_type="time_off_request",
        target_id=request.id,
        details={"shift_id": str(shift_id)},
    )
    db.commit()
