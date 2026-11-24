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
- Cancelling: a pending or escalated request at any time; an approved one only before its
  first day. Cancelling an approved request does not give the shifts back.
- Seeing requests: your own always; anyone else's with time_off.view covering the employee
  (the scope filter for lists, authorize() for one). Another company's answer 404.
- The reason is kept as typed (at most 500 characters) and shown only as plain text.

- Deciding: only a current reviewer (review.py), checked after taking the locks, so
  somebody who lost their role or their place meanwhile cannot decide. Never the
  employee (AZ7). A comment may go with the decision (plain text, at most 500).
- Waiting for me: the requests the user may decide right now.

Every change is audited (time_off.requested, time_off.cancelled, time_off.approved,
time_off.denied, time_off.escalated, shift.opened) and commits once.
"""

import uuid
from dataclasses import dataclass
from datetime import date, datetime

from sqlalchemy import Select, select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalDecision, ApprovalRequest
from app.approvals.service import DecisionError, decide, lapse, may_decide, open_request, waits_for
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
from app.modules.time_off.days import day_starts, zone_of
from app.modules.time_off.models import HOLDING, TimeOffRequest
from app.modules.time_off.review import overlapping_shifts
from app.modules.time_off.schemas import TimeOffCreate
from app.settings.service import TIME_OFF_REQUIRED_APPROVALS, setting_value

MAX_DAYS = 30


# --- Keeping requests up to date -------------------------------------------------------


def refresh(db: Session, rows: list[TimeOffRequest]) -> None:
    """Decline the requests whose first day has begun undecided, as not reviewed, and save
    that at once (the approval layer's lapse; its hook updates the request itself).

    Afterwards the transaction always shows what was committed, whoever lapsed a request:
    - this request lapsed one: committing saves it, and the next read starts afresh;
    - another request lapsed one first: this transaction's REPEATABLE READ snapshot is from
      before that, so every later ordinary read in it (the status filter in
      list_requests(), the flags in not_reviewed(), a detail page's decisions) would still
      see "pending". Ending the transaction (a commit with nothing to save) makes the next
      read take a new snapshot, which includes the other request's lapse (review of #166).
    """
    changed = stale = False
    for row in rows:
        if row.status in ("pending", "escalated"):
            approval = db.get(ApprovalRequest, row.approval_request_id)
            if approval is not None and lapse(db, approval):
                changed = True
            elif approval is not None and approval.status != "pending":
                # Another request lapsed it first and its hook declined this row. Read the
                # row again with a locking read, as lapse() does for the approval: an
                # ordinary read would answer from this transaction's old snapshot.
                db.refresh(row, with_for_update={"read": True})
                stale = True
    if changed or stale:
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
    # 1. Lapse the overdue requests among these first (every one, not only the newest), so
    #    their stored status is "denied" before the status filter below looks at it.
    _lapse_overdue(db, query)
    # 2. Then filter by status in the database, BEFORE the limit: limiting first and
    #    filtering after could answer an empty list (the newest rows all another status)
    #    while older requests with this status exist.
    if status is not None:
        query = query.where(TimeOffRequest.status == status)
    return list(
        db.scalars(
            query.order_by(TimeOffRequest.created_at.desc(), TimeOffRequest.id.desc()).limit(limit)
        )
    )


def _lapse_overdue(db: Session, query: Select[TimeOffRequest]) -> None:
    """Lapse every request the query matches that is still open past its deadline.

    The open approval records past their deadline are looked up first, by ID (the company
    filter limits them to this company), and then the query's open requests among them.
    Usually there are none, or a few: each request lapses only once.
    """
    overdue = list(
        db.scalars(
            select(ApprovalRequest.id).where(
                ApprovalRequest.kind == "time_off",
                ApprovalRequest.status == "pending",
                ApprovalRequest.review_by <= utcnow(),
            )
        )
    )
    if not overdue:
        return
    rows = db.scalars(
        query.where(
            TimeOffRequest.status.in_(("pending", "escalated")),
            TimeOffRequest.approval_request_id.in_(overdue),
        )
    )
    refresh(db, list(rows))


@dataclass
class Detail:
    request: TimeOffRequest
    affected_shifts: list[Shift]
    decisions: list[ApprovalDecision]


def view_request(db: Session, user: User, request_id: uuid.UUID) -> Detail:
    """One request with its affected shifts and decisions: your own, or one your
    time_off.view covers (403); another company's or an unknown one is 404."""
    request = db.get(TimeOffRequest, request_id)
    if request is None:
        raise NotFound()
    if request.employee_id != user.id:
        try:
            authorize(db, user, "time_off.view", request)
        except Forbidden:
            # A reviewer sees what they are asked to decide, even without time_off.view
            # over the employee (a shared manager reached through escalation).
            approval = db.get(ApprovalRequest, request.approval_request_id)
            if approval is None or not may_decide(db, user, approval):
                raise
    refresh(db, [request])
    decisions = list(
        db.scalars(
            select(ApprovalDecision)
            .where(ApprovalDecision.request_id == request.approval_request_id)
            .order_by(ApprovalDecision.decided_at)
        )
    )
    shifts = sorted(overlapping_shifts(db, request), key=lambda shift: shift.starts_at)
    return Detail(request, shifts, decisions)


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
        status="pending",
        approval_request_id=approval.id,
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
        details={"first_day": body.first_day.isoformat(), "last_day": body.last_day.isoformat()},
    )
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
                TimeOffRequest.status.in_(("pending", "escalated")),
                TimeOffRequest.employee_id != user.id,
            )
            .order_by(TimeOffRequest.first_day, TimeOffRequest.id)
        )
    )
    refresh(db, rows)
    found = []
    for row in rows:
        approval = db.get(ApprovalRequest, row.approval_request_id)
        if approval is not None and waits_for(db, user, approval):
            found.append(row)
            if len(found) == limit:
                break
    return found


def decide_request(
    db: Session, user: User, request_id: uuid.UUID, decision: str, comment: str | None
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
    if request.status not in ("pending", "escalated"):
        raise Conflict("This request is no longer waiting for a decision.")
    if not may_decide(db, user, approval):
        raise Forbidden()  # their own, or not (or no longer) one of its reviewers
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
