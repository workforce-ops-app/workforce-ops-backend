"""The rules for asking for time off and following your requests (docs/features/time-off.md,
states and rules). Who reviews a request and what the decisions add up to are in
review.py.

- Asking needs time_off.request_self; cancelling, time_off.cancel_self. Both only ever
  reach your own requests.
- Whole days, both included, at most 30, in the employee's workplace zone (their home
  department's zone, or the company's). The first day is tomorrow or later there, so every
  request can be reviewed before it starts.
- A new request may not overlap your own pending, escalated, or approved requests (409).
  Requests of one person take turns through a lock on their row, so two requests sent at
  once cannot both pass the overlap check.
- Each request opens one approval record (kind "time_off") whose deadline is the start of
  its first day in the workplace zone; the number of approvals comes from the company
  setting time_off.required_approvals (C1). Still undecided at that moment, the request
  is declined as not reviewed, noticed the next time anyone reads or acts on it (the
  shared rule in app/approvals/service.py).
- Asking with offers (offer_coverage, docs/features/coverage.md): the request starts
  "collecting", so coworkers may offer to cover or swap its shifts (offers.py). It goes
  up to the managers when the employee sends it up, or by itself at its send-up deadline:
  the start of the day time_off.offers_close_days before the first day, in the workplace
  zone, fixed when asked (offers_close_at). Asking with offers after that is 409. The
  deadline is noticed the next time anyone reads or acts on the request, and audited as
  the system. While collecting, the request has no reviewers (review.py), so nobody can
  decide it and it is on nobody's waiting list.
- Cancelling: a collecting, pending, or escalated request at any time; an approved one
  only before its first day. Cancelling an approved request does not give the shifts back.
- Seeing requests: your own always; anyone else's with time_off.view covering the employee
  (the scope filter for lists, authorize() for one). Another company's answer 404.
- The reason is kept as typed (at most 500 characters) and shown only as plain text.

- Deciding: only a current reviewer (review.py), checked after taking the locks, so
  somebody who lost their role or their place meanwhile cannot decide. Never the
  employee (AZ7). A comment may go with the decision (plain text, at most 500). An
  approval may choose coworkers' offers (offers.py, choose); only the approval that
  settles the request applies its choices.
- Waiting for me: the requests the user may decide right now.

Every change is audited (time_off.requested, time_off.sent_up, time_off.cancelled,
time_off.approved,
time_off.denied, time_off.escalated, shift.opened) and commits once.
"""

import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalDecision, ApprovalRequest
from app.approvals.service import (
    DecisionError,
    decide,
    handler_for,
    lapse,
    may_decide,
    open_request,
    waits_for,
)
from app.approvals.service import cancel as cancel_approval
from app.audit import Actor, record
from app.authz.chain import lock_reporting_lines
from app.authz.check import Forbidden, authorize, grants, scope_filter
from app.authz.scope import ScopeColumns
from app.db.base import utcnow
from app.modules.org import repository
from app.modules.org.models import User
from app.modules.org.service import Conflict, Invalid, NotFound
from app.modules.schedules.models import Shift
from app.modules.time_off import offers
from app.modules.time_off.days import day_starts, zone_of
from app.modules.time_off.models import HOLDING, OPEN, CoverageOffer, TimeOffRequest
from app.modules.time_off.review import overlapping_shifts
from app.modules.time_off.schemas import Choice, TimeOffCreate
from app.settings.service import (
    TIME_OFF_OFFERS_CLOSE_DAYS,
    TIME_OFF_REQUIRED_APPROVALS,
    department_value,
    setting_value,
)

MAX_DAYS = 30


# --- Keeping requests up to date -------------------------------------------------------


TOO_LATE = "It is too late to ask coworkers for these days; send the request without offers."


def _send_up(db: Session, request: TimeOffRequest, *, actor: Actor, at: datetime) -> None:
    """A collecting request goes up to the managers: offers close, reviewers start."""
    request.status, request.sent_up_at = "pending", at
    record(
        db,
        actor=actor,
        action="time_off.sent_up",
        target_type="time_off_request",
        target_id=request.id,
        details={"by": "employee" if actor.type == "user" else "deadline"},
    )


def send_up_if_due(db: Session, request: TimeOffRequest) -> bool:
    """Send a collecting request up if its deadline has passed; audited as the system, at
    the deadline (not when someone happened to look). The caller holds the request's lock
    and commits. Returns whether it went up now."""
    due = request.offers_close_at
    if request.status != "collecting" or due is None or due > utcnow():
        return False
    _send_up(db, request, actor=Actor.system(), at=due)
    return True


def refresh(db: Session, rows: list[TimeOffRequest]) -> None:
    """Bring requests up to date and save that at once: collecting requests past their
    send-up deadline go up (locked in the usual order: the employee, then the request),
    and requests whose first day has begun undecided are declined as not reviewed (the
    approval layer's lapse; its hook updates the request itself)."""
    changed = False
    now = utcnow()
    for row in rows:
        if row.status == "collecting" and row.offers_close_at and row.offers_close_at <= now:
            repository.person(db, row.employee_id, lock=True)
            fresh = db.get(TimeOffRequest, row.id, populate_existing=True, with_for_update=True)
            if fresh is not None and send_up_if_due(db, fresh):
                changed = True
        if row.status in OPEN:
            approval = db.get(ApprovalRequest, row.approval_request_id)
            if approval is not None and lapse(db, approval):
                changed = True
    if changed:
        db.commit()


def not_reviewed(db: Session, rows: list[TimeOffRequest]) -> dict[uuid.UUID, bool]:
    """For each request, whether it was declined because nobody reviewed it in time."""
    ids = [row.approval_request_id for row in rows]
    if not ids:
        return {}
    flags = dict(
        db.execute(
            select(ApprovalRequest.id, ApprovalRequest.not_reviewed).where(
                ApprovalRequest.id.in_(ids)
            )
        ).all()
    )
    return {row.id: bool(flags.get(row.approval_request_id)) for row in rows}


@dataclass
class Progress:
    """Where a request still open (pending or escalated) stands: who has decided so far,
    and who still has to."""

    decided: list[ApprovalDecision]  # oldest first
    waiting_for: list[uuid.UUID]  # the reviewers who have not decided yet


def progress(db: Session, rows: list[TimeOffRequest]) -> dict[uuid.UUID, Progress]:
    """For each request still open, its Progress (closed requests are left out).

    Found in review: after one of two managers denied a request, it still read "Waiting
    for review", as if nobody had looked at it. A request with several reviewers waits
    for all of them (review.py, outcome), so the screens show who decided and who is
    still to decide.

    Who still has to decide is worked out the same way as for a decision (review.py,
    reviewers, on the lines as they are now), minus everyone who already decided and
    anyone deactivated, so the names match who can actually act.
    """
    # Step 1: only open requests have anyone left to decide.
    open_rows = [row for row in rows if row.status in ("pending", "escalated")]
    if not open_rows:
        return {}
    # Step 2: every decision on those requests, in one query, oldest first.
    approval_ids = [row.approval_request_id for row in open_rows]
    decisions: dict[uuid.UUID, list[ApprovalDecision]] = {i: [] for i in approval_ids}
    for decision in db.scalars(
        select(ApprovalDecision)
        .where(ApprovalDecision.request_id.in_(approval_ids))
        .order_by(ApprovalDecision.decided_at, ApprovalDecision.approver_id)
    ):
        decisions[decision.request_id].append(decision)
    # Step 3: per request, the reviewers now, minus those who decided (and the employee,
    # who never reviews their own), keeping only active people.
    found: dict[uuid.UUID, Progress] = {}
    for row in open_rows:
        approval = db.get(ApprovalRequest, row.approval_request_id)
        if approval is None:  # never deleted
            continue
        made = decisions[approval.id]
        left = handler_for(approval).reviewers(db, approval) - {d.approver_id for d in made}
        left.discard(row.employee_id)
        active = [
            person.id
            for person_id in left
            if (person := db.get(User, person_id)) is not None and person.deactivated_at is None
        ]
        found[row.id] = Progress(decided=made, waiting_for=sorted(active))
    return found


def comments(db: Session, request: TimeOffRequest) -> dict[str, str]:
    """The reviewers' comments on a request, by reviewer ID."""
    approval = db.get(ApprovalRequest, request.approval_request_id)
    return dict(approval.payload.get("comments", {})) if approval is not None else {}


# --- Seeing requests -------------------------------------------------------------------


def list_requests(
    db: Session,
    user: User,
    *,
    mine: bool,
    status: str | None,
    employee_id: uuid.UUID | None,
    first: date | None,
    last: date | None,
    limit: int,
) -> list[TimeOffRequest]:
    """Your own requests (mine), or the requests of people your time_off.view covers;
    newest first, optionally only one status, one employee, or overlapping first..last."""
    query = select(TimeOffRequest)
    if mine:
        authorize(db, user, "time_off.request_self")
        query = query.where(TimeOffRequest.employee_id == user.id)
    else:
        authorize(db, user, "time_off.view")
        query = query.where(
            scope_filter(
                db, user, "time_off.view", ScopeColumns(employee=TimeOffRequest.employee_id)
            )
        )
    if employee_id is not None:
        query = query.where(TimeOffRequest.employee_id == employee_id)
    if first is not None:
        query = query.where(TimeOffRequest.last_day >= first)
    if last is not None:
        query = query.where(TimeOffRequest.first_day <= last)
    rows = list(
        db.scalars(
            query.order_by(TimeOffRequest.created_at.desc(), TimeOffRequest.id.desc()).limit(limit)
        )
    )
    refresh(db, rows)
    return [row for row in rows if status is None or row.status == status]


@dataclass
class Detail:
    request: TimeOffRequest
    affected_shifts: list[Shift]
    decisions: list[ApprovalDecision]
    # The coworkers' offers this user may see: all of them for the employee and the
    # managers, only their own for a coworker (coverage.md, threat I10).
    offers: list[CoverageOffer]
    # Seen as a coworker: the answer leaves out the reviewers' decisions.
    as_coworker: bool = False


def view_request(db: Session, user: User, request_id: uuid.UUID) -> Detail:
    """One request with its affected shifts, decisions, and offers: your own, one your
    time_off.view covers, one you review, or (as a coworker) one you could answer or did
    answer (403 otherwise); another company's or an unknown one is 404."""
    request = db.get(TimeOffRequest, request_id)
    if request is None:
        raise NotFound()
    as_coworker = False
    if request.employee_id != user.id:
        try:
            authorize(db, user, "time_off.view", request)
        except Forbidden:
            # A reviewer sees what they are asked to decide, even without time_off.view
            # over the employee (a shared manager reached through escalation).
            approval = db.get(ApprovalRequest, request.approval_request_id)
            if approval is None or not may_decide(db, user, approval):
                # Last, a coworker asked to cover or swap (coverage.md).
                if not offers.sees_as_coworker(db, user, request):
                    raise
                as_coworker = True
    refresh(db, [request])
    decisions = list(
        db.scalars(
            select(ApprovalDecision)
            .where(ApprovalDecision.request_id == request.approval_request_id)
            .order_by(ApprovalDecision.decided_at)
        )
    )
    shifts = sorted(overlapping_shifts(db, request), key=lambda shift: shift.starts_at)
    if as_coworker:
        # Only their own answers, and none of the reviewers' decisions (threat I10).
        return Detail(request, shifts, [], offers.own_offers(db, user, request), True)
    return Detail(request, shifts, decisions, offers.offers_on(db, request))


# --- Asking ----------------------------------------------------------------------------


def ask(db: Session, user: User, body: TimeOffCreate) -> TimeOffRequest:
    """Ask for whole days off (the rules at the top of this file)."""
    authorize(db, user, "time_off.request_self")
    if body.last_day < body.first_day:
        raise Invalid("The last day cannot be before the first day.")
    if (body.last_day - body.first_day).days + 1 > MAX_DAYS:
        raise Invalid(f"A request covers at most {MAX_DAYS} days.")
    zone = zone_of(db, user)
    today = datetime.now(zone).date()
    if body.first_day <= today:
        raise Invalid("The first day must be tomorrow or later.")

    # Take turns with the person's other requests (their row), then check overlaps on
    # fresh reads, after declining any that have run out of time.
    me = repository.person(db, user.id, lock=True)
    if me is None or me.deactivated_at is not None:
        raise Forbidden()
    holding = list(
        db.scalars(
            select(TimeOffRequest)
            .where(
                TimeOffRequest.employee_id == user.id,
                TimeOffRequest.status.in_(HOLDING),
                TimeOffRequest.first_day <= body.last_day,
                TimeOffRequest.last_day >= body.first_day,
            )
            .with_for_update(read=True)
        )
    )
    for row in holding:
        approval = db.get(ApprovalRequest, row.approval_request_id)
        if approval is not None:
            lapse(db, approval)
    if any(row.status in HOLDING for row in holding):
        raise Conflict("You already asked for some of these days.")

    # Asked with offers: coworkers may answer until the send-up deadline, the start of
    # the day that many days before the first day. Already past it: too late to ask them.
    offers_close_at = None
    if body.offer_coverage:
        # The employee's home department may give reviewers longer than the company.
        days = department_value(db, TIME_OFF_OFFERS_CLOSE_DAYS, me.department_id)
        offers_close_at = day_starts(zone, body.first_day - timedelta(days=days))
        if offers_close_at <= utcnow():
            raise Conflict(TOO_LATE)

    approval = open_request(
        db,
        kind="time_off",
        requested_by=user.id,
        subject_user_id=user.id,
        payload={},
        details={"first_day": body.first_day.isoformat(), "last_day": body.last_day.isoformat()},
        required_approvals=setting_value(db, TIME_OFF_REQUIRED_APPROVALS),
        review_by=day_starts(zone, body.first_day),
    )
    request = TimeOffRequest(
        employee_id=user.id,
        first_day=body.first_day,
        last_day=body.last_day,
        reason=body.reason or None,
        status="collecting" if body.offer_coverage else "pending",
        approval_request_id=approval.id,
        offers_close_at=offers_close_at,
    )
    db.add(request)
    db.flush()
    approval.payload = {"time_off_request_id": str(request.id)}
    record(
        db,
        actor=Actor.user(user.id),
        action="time_off.requested",
        target_type="time_off_request",
        target_id=request.id,
        # The days, never the reason: the log is kept for good, the reason is personal.
        details={
            "first_day": body.first_day.isoformat(),
            "last_day": body.last_day.isoformat(),
            "offer_coverage": body.offer_coverage,
        },
    )
    db.commit()
    return request


# --- Sending up ------------------------------------------------------------------------


def send_up(db: Session, user: User, request_id: uuid.UUID) -> TimeOffRequest:
    """The employee sends their collecting request up to the managers (offers close)."""
    authorize(db, user, "time_off.request_self")
    found = db.get(TimeOffRequest, request_id)
    if found is None or found.employee_id != user.id:
        raise NotFound()  # someone else's request is not yours to send
    # Same order as asking: the person, then the request (fresh and locked).
    repository.person(db, user.id, lock=True)
    request = db.get(TimeOffRequest, request_id, populate_existing=True, with_for_update=True)
    if request is None:
        raise NotFound()
    if send_up_if_due(db, request):
        db.commit()
        raise Conflict("Its deadline passed, so this request already went to your managers.")
    if request.status != "collecting":
        raise Conflict("This request is not waiting for coworkers' offers.")
    _send_up(db, request, actor=Actor.user(user.id), at=utcnow())
    db.commit()
    return request


# --- Cancelling ------------------------------------------------------------------------


def cancel(db: Session, user: User, request_id: uuid.UUID) -> TimeOffRequest:
    """Cancel your own request: waiting ones any time, approved ones before the first day."""
    authorize(db, user, "time_off.cancel_self")
    found = db.get(TimeOffRequest, request_id)
    if found is None or found.employee_id != user.id:
        raise NotFound()  # someone else's request is not yours to know about here
    # Same order as asking: the person, then the request (fresh and locked).
    repository.person(db, user.id, lock=True)
    request = db.get(TimeOffRequest, request_id, populate_existing=True, with_for_update=True)
    if request is None:
        raise NotFound()
    approval = db.get(ApprovalRequest, request.approval_request_id)
    if approval is not None and lapse(db, approval):
        db.commit()
        raise Conflict("Nobody reviewed this request in time, so it was declined.")
    if request.status in ("denied", "cancelled"):
        raise Conflict("This request is no longer waiting or approved.")
    if request.status == "approved":
        today = datetime.now(zone_of(db, user)).date()
        if request.first_day <= today:
            raise Conflict("An approved request can only be cancelled before its first day.")
    elif approval is not None:
        cancel_approval(db, user, approval)  # the approval record stops waiting too

    request.status, request.decided_at = "cancelled", utcnow()
    offers.drop_offers(db, request)  # coverage.md, endings
    record(
        db,
        actor=Actor.user(user.id),
        action="time_off.cancelled",
        target_type="time_off_request",
        target_id=request.id,
    )
    db.commit()
    return request


# --- Reviewing -------------------------------------------------------------------------

NOT_REVIEWED = "Nobody reviewed this request in time, so it was declined."


def waiting(db: Session, user: User, *, limit: int) -> list[TimeOffRequest]:
    """The requests still waiting for the user's decision, soonest first day first. One
    they already decided, still waiting for the other reviewers, is not listed."""
    if not grants(db, user, "time_off.review"):
        return []  # nobody without the permission reviews anything
    rows = list(
        db.scalars(
            select(TimeOffRequest)
            .where(
                # Collecting ones too: any past their send-up deadline go up just below.
                TimeOffRequest.status.in_(OPEN),
                TimeOffRequest.employee_id != user.id,
            )
            .order_by(TimeOffRequest.first_day, TimeOffRequest.id)
        )
    )
    refresh(db, rows)
    found = []
    for row in rows:
        if row.status == "collecting":
            continue  # still with the coworkers: nobody reviews it yet
        approval = db.get(ApprovalRequest, row.approval_request_id)
        if approval is not None and waits_for(db, user, approval):
            found.append(row)
            if len(found) == limit:
                break
    return found


def decide_request(
    db: Session,
    user: User,
    request_id: uuid.UUID,
    decision: str,
    comment: str | None,
    choices: list[Choice] | None = None,
) -> TimeOffRequest:
    """Approve or deny a request the user reviews.

    Locks, in this order: the company's reporting lines (who is above whom stays still
    while the reviewers are worked out), the employee (as every schedule change does
    before touching their shifts), the request, and its approval record. Only then are
    the reviewers worked out, on fresh reads, and the decision recorded.
    """
    authorize(db, user, "time_off.review")
    found = db.get(TimeOffRequest, request_id)
    if found is None:
        raise NotFound()
    lock_reporting_lines(db)
    repository.person(db, found.employee_id, lock=True)
    request = db.get(TimeOffRequest, request_id, populate_existing=True, with_for_update=True)
    approval = db.get(
        ApprovalRequest, found.approval_request_id, populate_existing=True, with_for_update=True
    )
    if request is None or approval is None:  # never deleted
        raise NotFound()
    if lapse(db, approval):
        db.commit()
        raise Conflict(NOT_REVIEWED)
    if request.status == "collecting":
        raise Forbidden()  # still with the coworkers: it has no reviewers yet
    if request.status not in ("pending", "escalated"):
        raise Conflict("This request is no longer waiting for a decision.")
    if not may_decide(db, user, approval):
        raise Forbidden()  # their own, or not (or no longer) one of its reviewers
    if choices and decision == "approve":
        # Checked and locked before anything is written (offers.py, choose); kept with
        # the approval record, keyed by who chose. review.approve applies them only if
        # this approval settles the request.
        chosen = offers.choose(db, user, request, choices)
        kept = {**approval.payload.get("choices", {}), str(user.id): chosen}
        approval.payload = {**approval.payload, "choices": kept}
    if comment:
        # Kept with the approval record, keyed by who wrote it; never in the audit log.
        comments = {**approval.payload.get("comments", {}), str(user.id): comment}
        approval.payload = {**approval.payload, "comments": comments}
    try:
        decide(db, user, approval, decision)
    except DecisionError as error:
        db.rollback()
        raise Conflict(str(error)) from error
    db.commit()
    return request
