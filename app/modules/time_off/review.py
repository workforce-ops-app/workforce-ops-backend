"""Who reviews a time-off request, and what the decisions add up to (docs/features/time-off.md,
states and rules; decision 0029). Used by approval.py, the handler the shared approval layer
calls.

Who reviews it (worked out again at every decision, on fresh reads, never stored):

1. Pending: the employee's DIRECT managers who can review it (active, and holding
   time_off.review over the employee). If none of them can, the next level up, one level
   at a time; if nobody in the chain can, the company's owners.
2. Escalated (those reviewers disagreed): the NEAREST SHARED MANAGER of the reviewers who
   decided, the lowest person above all of them who can review it. Several equally near
   may each decide, and the first decision settles it. With nobody shared, the owners.

Nobody reviews their own request (AZ7): the employee is never a reviewer, and the shared
layer refuses it again (app/approvals/service.py, may_decide).

What the decisions add up to (outcome, after each decision while pending):

- an approval and a denial: escalated (whatever the count);
- no denial and enough approvals: approved. Enough is the company setting
  time_off.required_approvals, or every reviewer when fewer of them can review;
- denials only, and nobody left to decide: denied;
- anything else: still waiting.

Escalated, the shared manager's decision settles it at once.

On approval, every scheduled shift of the employee that overlaps the approved days becomes
open, each with its own shift.opened audit entry naming the request.

Course topic, SQL JOINs: finding the nearest shared manager. Each step up the chain is one
query joining reporting_lines to the people found so far (direct_managers_fresh); the
walk keeps how many steps up each manager was found, and the shared managers are the ones
every walk found, nearest first. It walks one level per query, not as one recursive
query, because a decision needs the newest committed lines (see is_above_in_chain_fresh).
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalDecision, ApprovalRequest
from app.audit import Actor, record
from app.authz.chain import direct_managers_fresh
from app.authz.check import grants
from app.authz.models import Role, RoleAssignment
from app.authz.scope import covers, person_scope
from app.db.base import utcnow
from app.modules.org.models import User
from app.modules.schedules.models import Shift
from app.modules.time_off.days import days_span, zone_of
from app.modules.time_off.models import TimeOffRequest

# --- Who may review --------------------------------------------------------------------


def request_for(db: Session, approval: ApprovalRequest) -> TimeOffRequest | None:
    """The time-off request an approval record belongs to."""
    return db.scalars(
        select(TimeOffRequest).where(TimeOffRequest.approval_request_id == approval.id)
    ).one_or_none()


def can_review(db: Session, person_id: uuid.UUID, employee: User) -> bool:
    """Whether the person may review this employee's time off: active, not the employee,
    and holding time_off.review somewhere that covers the employee."""
    person = db.get(User, person_id)
    if person is None or person.deactivated_at is not None or person.id == employee.id:
        return False
    scope = person_scope(db, employee)
    return any(covers(grant, scope) for grant in grants(db, person, "time_off.review"))


def owners(db: Session) -> set[uuid.UUID]:
    """The company's active owners (Owner role, company-wide): the last resort."""
    ids = db.scalars(
        select(RoleAssignment.user_id, Role.id)
        .join(Role, Role.id == RoleAssignment.role_id)
        .where(Role.built_in == "owner", RoleAssignment.scope_type == "company")
    )
    return {
        person for person in ids if (found := db.get(User, person)) and found.deactivated_at is None
    }


def first_reviewers(db: Session, employee: User) -> set[uuid.UUID]:
    """Step 1: the nearest level above the employee where somebody can review, or else the
    owners (never the employee)."""
    seen = {employee.id}
    level = direct_managers_fresh(db, {employee.id})
    while level:
        able = {person for person in level if can_review(db, person, employee)}
        if able:
            return able
        # Only people not met before go on, so even a loop in the lines ends the walk.
        seen |= level
        level = direct_managers_fresh(db, level) - seen
    return owners(db) - {employee.id}


def _steps_above(db: Session, person_id: uuid.UUID) -> dict[uuid.UUID, int]:
    """Everyone above the person, with how many steps up each one is (1: a direct manager)."""
    found: dict[uuid.UUID, int] = {}
    seen, level, steps = {person_id}, {person_id}, 0
    while level:
        steps += 1
        managers = direct_managers_fresh(db, level) - seen
        for manager in managers:
            found[manager] = steps
        seen |= managers
        level = managers
    return found


def nearest_shared(db: Session, deciders: set[uuid.UUID], employee: User) -> set[uuid.UUID]:
    """Step 2: the lowest people above every decider who can review, or else the owners.
    Neither the employee nor anyone who already decided is included."""
    walks = [_steps_above(db, person) for person in deciders]
    shared = set.intersection(*(set(walk) for walk in walks)) if walks else set()
    able = {p for p in shared if can_review(db, p, employee)} - deciders
    if not able:
        return owners(db) - {employee.id} - deciders
    # How near a shared manager is: the longest of its distances to the deciders, so the
    # nearest is the one closest to all of them, not just to one.
    distance = {p: max(walk[p] for walk in walks) for p in able}
    nearest = min(distance.values())
    return {p for p, steps in distance.items() if steps == nearest}


def reviewers(db: Session, approval: ApprovalRequest, *, fresh: bool = False) -> set[uuid.UUID]:
    """Who may decide now: nobody while collecting (still with the coworkers,
    coverage.md), step 2 when escalated, otherwise step 1. fresh is part of the shared
    Handler interface (app/approvals/service.py); time off does not use it yet."""
    request = request_for(db, approval)
    employee = db.get(User, approval.subject_user_id)
    if request is None or employee is None or request.status == "collecting":
        return set()
    if request.status == "escalated":
        return nearest_shared(db, _escalated_from(approval), employee)
    return first_reviewers(db, employee)


def _escalated_from(approval: ApprovalRequest) -> set[uuid.UUID]:
    return {uuid.UUID(person) for person in approval.payload.get("escalated_from", [])}


# --- What the decisions add up to ------------------------------------------------------


def _decisions(db: Session, approval: ApprovalRequest) -> dict[uuid.UUID, str]:
    return dict(
        db.execute(
            select(ApprovalDecision.approver_id, ApprovalDecision.decision).where(
                ApprovalDecision.request_id == approval.id
            )
        ).all()
    )


def outcome(db: Session, approval: ApprovalRequest) -> str | None:
    """After a decision: "approved", "denied", or None (waiting, or just escalated)."""
    request = request_for(db, approval)
    employee = db.get(User, approval.subject_user_id)
    if request is None or employee is None:
        return None
    decisions = _decisions(db, approval)

    if request.status == "escalated":
        # The shared manager's decision settles it: the one not among those who disagreed.
        settling = [d for person, d in decisions.items() if person not in _escalated_from(approval)]
        return _denied(db, request, approval) if settling[0] == "deny" else "approved"

    approvals = sum(1 for d in decisions.values() if d == "approve")
    denials = len(decisions) - approvals
    level = first_reviewers(db, employee)
    if approvals and denials:
        _escalate(db, request, approval, set(decisions), employee)
        return None
    # The setting, or every reviewer when fewer can review (and never less than one).
    needed = max(1, min(approval.required_approvals, len(level)))
    if not denials and approvals >= needed:
        return "approved"
    if denials and not (level - set(decisions)):
        return _denied(db, request, approval)
    return None


def _escalate(
    db: Session,
    request: TimeOffRequest,
    approval: ApprovalRequest,
    deciders: set[uuid.UUID],
    employee: User,
) -> None:
    """The reviewers disagreed: send it to their nearest shared manager; audited."""
    request.status = "escalated"
    approval.payload = {
        **approval.payload,
        "escalated_from": sorted(str(person) for person in deciders),
    }
    to = nearest_shared(db, deciders, employee)
    record(
        db,
        actor=Actor.system(),
        action="time_off.escalated",
        target_type="time_off_request",
        target_id=request.id,
        details={"to": sorted(str(person) for person in to)},
    )


def _denied(db: Session, request: TimeOffRequest, approval: ApprovalRequest) -> str:
    request.status, request.decided_at = "denied", utcnow()
    record(
        db,
        actor=Actor.system(),
        action="time_off.denied",
        target_type="time_off_request",
        target_id=request.id,
    )
    return "denied"


# --- Approval --------------------------------------------------------------------------


def overlapping_shifts(db: Session, request: TimeOffRequest, *, lock: bool = False) -> list[Shift]:
    """The employee's scheduled shifts overlapping the requested days (in their zone),
    sorted by ID, so locks are always taken in the same order."""
    employee = db.get(User, request.employee_id)
    if employee is None:
        return []
    start, end = days_span(zone_of(db, employee), request.first_day, request.last_day)
    query = (
        select(Shift)
        .where(
            Shift.employee_id == employee.id,
            Shift.status == "scheduled",
            Shift.starts_at < end,
            Shift.ends_at > start,
        )
        .order_by(Shift.id)
    )
    if lock:
        query = query.with_for_update().execution_options(populate_existing=True)
    return list(db.scalars(query))


def approve(db: Session, approval: ApprovalRequest, approver: User) -> None:
    """Approved: the request says so, and the employee's shifts on those days become open,
    each audited with the request it was opened for. The caller holds the employee's lock.

    The shifts are locked before the first audit entry, the same order as every schedule
    change (people, then shifts, then writes), so the two can never wait on each other."""
    request = request_for(db, approval)
    if request is None:
        return
    shifts = overlapping_shifts(db, request, lock=True)
    request.status, request.decided_at = "approved", utcnow()
    record(
        db,
        actor=Actor.user(approver.id),
        action="time_off.approved",
        target_type="time_off_request",
        target_id=request.id,
    )
    for shift in shifts:
        previous = shift.employee_id
        shift.employee_id, shift.status = None, "open"
        details: dict[str, Any] = {
            "employee_id": None,
            "previous_employee_id": str(previous) if previous else None,
            "time_off_request_id": str(request.id),
        }
        record(
            db,
            actor=Actor.user(approver.id),
            action="shift.opened",
            target_type="shift",
            target_id=shift.id,
            details=details,
        )
