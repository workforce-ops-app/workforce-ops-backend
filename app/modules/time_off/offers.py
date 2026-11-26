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

Choosing at approval (choose, then apply_choices from review.approve):
- The reviewer whose approval settles the request chooses: none, or one offer per shift.
  Choices sent with an approval that does not settle it are kept with the approval record
  but never applied (threat E12: only the deciding approval moves shifts).
- A choice must be a cover or swap offer on this request, for that shift (422 otherwise).
  A reviewer may never choose their own offer (403, E12). Choosing needs schedule.edit
  over every shift it changes (403), checked before anything is written.
- Locks, after the time-off ones (lines, employee, request, approval): the coworkers'
  rows in ID order, then every shift involved in ID order (the order of every schedule
  change). Then each chosen offer is checked again with offer_problem, so a coworker
  deactivated, newly busy, or newly away, or a swap shift moved meanwhile, is refused
  with 409 naming the shift, and nothing changes.
- Applied: chosen covers and swaps reassign their shifts (shift.assigned, with the request
  and the offer); the employee's other shifts on those days open, as before. Offers end
  chosen or not_chosen; a declined, cancelled, or not reviewed request drops them.

Every change is audited (coverage.offered, coverage.withdrawn, shift.assigned) and commits
once.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.approvals.service import DecisionError
from app.audit import Actor, record
from app.authz.chain import lock_reporting_lines
from app.authz.check import Forbidden, authorize, grants
from app.db.base import utcnow
from app.modules.org import repository as people
from app.modules.org.models import User
from app.modules.org.service import Conflict, Invalid, NotFound
from app.modules.schedules import repository as schedules
from app.modules.schedules.models import Shift
from app.modules.time_off.days import days_span, zone_of
from app.modules.time_off.models import CoverageOffer, TimeOffRequest
from app.modules.time_off.review import overlapping_shifts
from app.modules.time_off.schemas import Choice, OfferBody

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

# The same reasons, as the reviewer reads them when a chosen offer no longer works.
FOR_THE_REVIEWER = {
    CANNOT_TAKE: "they can no longer be assigned this shift",
    BUSY: "they now have another shift at that time",
    AWAY: "they now have approved time off at that time",
    NOT_YOURS: "the shift they give is no longer theirs to give",
    OTHER_DEPARTMENT: "the shift they give is in another department",
    DURING: "the shift they give is during the time off",
    EMPLOYEE_CANNOT: "the employee could not work the shift they give",
    NO_SWAP_SHIFT: "the shift they give is gone",
    OWN_REQUEST: "it is the employee's own",
}


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
    """The request, locked in the time-off order (the company's lock, the employee, then the
    request; review of #167), and
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
    lock_reporting_lines(db)
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


def _own_offer(
    db: Session, request: TimeOffRequest, shift_id: uuid.UUID, user: User
) -> CoverageOffer | None:
    """The user's answer for one shift of the request, read fresh and locked.

    The caller holds the request's lock, so two answers from the same person take turns.
    The read after it must be a locking read (review of #193): under MySQL's REPEATABLE
    READ an ordinary read answers from the transaction's first snapshot, taken before the
    lock (the checks in _locked_request read the offers already), so the second of two
    answers at the same moment would not see the first one's row and would add a
    duplicate instead of changing it. FOR UPDATE reads what is committed now, and locks
    the row the answer is about to change or remove.
    """
    return db.scalars(
        select(CoverageOffer)
        .where(
            CoverageOffer.time_off_request_id == request.id,
            CoverageOffer.shift_id == shift_id,
            CoverageOffer.offered_by == user.id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()


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
    offer = _own_offer(db, request, shift.id, user)
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
    offer = _own_offer(db, request, shift_id, user)
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


# --- Choosing at approval --------------------------------------------------------------


def choose(
    db: Session, user: User, request: TimeOffRequest, choices: list[Choice]
) -> dict[str, str]:
    """Check the reviewer's choices and take the locks they need; returns them as
    {shift ID: offer ID}, as kept with the approval record. The caller holds the time-off
    locks (lines, employee, request, approval) and has checked the user may decide.

    Nothing is written here: a refused choice (422, 403) leaves everything as it was.
    """
    # Step 1: each choice names one of the request's shifts, once, and a cover or swap
    # offer on this request for that shift.
    shifts = {shift.id: shift for shift in overlapping_shifts(db, request)}
    chosen: dict[uuid.UUID, CoverageOffer] = {}
    for choice in choices:
        if choice.shift_id not in shifts or choice.shift_id in chosen:
            raise Invalid("Choose at most one offer for each of this request's shifts.")
        offer = db.get(CoverageOffer, choice.offer_id)  # another company's: None
        if (
            offer is None
            or offer.time_off_request_id != request.id
            or offer.shift_id != choice.shift_id
            or offer.answer == "decline"
        ):
            raise Invalid("Choose a cover or swap offer made for that shift.")
        if offer.status != "offered":
            raise Conflict("That offer is no longer open.")
        # Threat E12: a reviewer never hands a shift to themselves.
        if offer.offered_by == user.id:
            raise Forbidden()
        chosen[choice.shift_id] = offer
    if not chosen:
        return {}

    # Step 2: the locks, in the order of every schedule change: the coworkers' rows in ID
    # order, then every shift involved (all of the employee's shifts on those days, and
    # the shifts given in swaps) in ID order, read fresh.
    for person_id in sorted({offer.offered_by for offer in chosen.values()}):
        people.person(db, person_id, lock=True)
    involved = set(shifts) | {o.swap_shift_id for o in chosen.values() if o.swap_shift_id}
    locked = {
        shift.id: shift
        for shift in db.scalars(
            select(Shift)
            .where(Shift.id.in_(involved))
            .order_by(Shift.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    }

    # Step 3: moving a shift is a schedule change: schedule.edit over each one it moves.
    for shift_id, offer in chosen.items():
        authorize(db, user, "schedule.edit", locked[shift_id])
        if offer.swap_shift_id is not None and offer.swap_shift_id in locked:
            authorize(db, user, "schedule.edit", locked[offer.swap_shift_id])
    return {str(shift_id): str(offer.id) for shift_id, offer in sorted(chosen.items())}


def _when(db: Session, shift: Shift, employee: User) -> str:
    """When a shift starts, in the employee's workplace zone, for a message."""
    local = shift.starts_at.replace(tzinfo=UTC).astimezone(zone_of(db, employee))
    return f"{local:%a %b} {local.day} at {local:%H:%M}"


def apply_choices(
    db: Session, request: TimeOffRequest, approver: User, choices: dict[str, str]
) -> list[CoverageOffer]:
    """The settling approval: check each chosen offer again and move its shifts; every
    other offer on the request ends not_chosen. Raises DecisionError (409, nothing
    changes) naming the first shift whose offer no longer works. The caller holds the
    locks (choose)."""
    employee = db.get(User, request.employee_id)
    if employee is None:  # never deleted
        raise DecisionError("The employee is missing.")
    applied: list[CoverageOffer] = []
    for shift_id, offer_id in sorted(choices.items()):
        shift = db.get(Shift, uuid.UUID(shift_id))
        offer = db.get(CoverageOffer, uuid.UUID(offer_id))
        if shift is None or offer is None:
            raise DecisionError("A chosen offer is gone; choose again.")
        coworker = db.get(User, offer.offered_by)
        swap = db.get(Shift, offer.swap_shift_id) if offer.swap_shift_id else None
        # Step 1: still the employee's shift, the offer still open, and every rule still
        # met (on fresh, locked reads).
        problem = None
        if offer.status != "offered" or shift.employee_id != employee.id:
            problem = "the offer or the shift changed meanwhile"
        elif coworker is None:
            problem = FOR_THE_REVIEWER[CANNOT_TAKE]
        elif (found := offer_problem(db, request, shift, coworker, offer.answer, swap)) is not None:
            problem = FOR_THE_REVIEWER.get(found, found)
        if problem is not None:
            name = coworker.display_name if coworker is not None else "a coworker"
            raise DecisionError(
                f"The offer from {name} for the shift on {_when(db, shift, employee)} "
                f"can no longer be used: {problem}. Choose another offer or none."
            )
        if coworker is None:  # refused just above; this tells the type checker
            raise DecisionError("A chosen offer is gone; choose again.")
        # Step 2: move the shifts, each audited with the request and the offer.
        _reassign(db, shift, coworker.id, approver, request, offer)
        if swap is not None:
            _reassign(db, swap, employee.id, approver, request, offer)
        db.flush()  # the next offer's checks see this one's moves
        offer.status = "chosen"
        applied.append(offer)
    # Step 3: every other open offer on the request was not chosen.
    _end_open_offers(db, request, "not_chosen")
    return applied


def _reassign(
    db: Session,
    shift: Shift,
    to: uuid.UUID,
    approver: User,
    request: TimeOffRequest,
    offer: CoverageOffer,
) -> None:
    previous, shift.employee_id = shift.employee_id, to
    record(
        db,
        actor=Actor.user(approver.id),
        action="shift.assigned",
        target_type="shift",
        target_id=shift.id,
        details={
            "employee_id": str(to),
            "previous_employee_id": str(previous) if previous else None,
            "time_off_request_id": str(request.id),
            "offer_id": str(offer.id),
        },
    )


def _end_open_offers(db: Session, request: TimeOffRequest, status: str) -> None:
    """Every offer on the request still open ends with this status."""
    db.execute(
        update(CoverageOffer)
        .where(CoverageOffer.time_off_request_id == request.id, CoverageOffer.status == "offered")
        .values(status=status, updated_at=utcnow())
        .execution_options(synchronize_session="fetch")
    )


def drop_offers(db: Session, request: TimeOffRequest) -> None:
    """Declined, cancelled, or not reviewed: the offers stay as a record, dropped."""
    _end_open_offers(db, request, "dropped")
