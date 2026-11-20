"""What a "time_off" approval request does (docs/features/time-off.md; decision 0029).

Tells the shared approval layer (app/approvals/service.py) what it needs about a request:
who reviews it and what the decisions add up to (review.py), that deciding needs no
password re-entry, what approval does (the request is approved and the shifts on those
days become open), and what happens when nobody reviewed it before its first day (the
request is declined as not reviewed).

Time-off requests are decided through /api/time-off-requests only, which takes the locks
in the order the shifts need (app/modules/time_off/service.py, decide).
"""

from typing import Any

from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import DecisionError, Handler, register_handler
from app.audit import Actor, record
from app.modules.org.models import User
from app.modules.time_off import review

_request_for = review.request_for


def sensitive(db: Session, approval: ApprovalRequest) -> bool:
    return False  # time off is not an admin-level change: no password re-entry


def apply(db: Session, approval: ApprovalRequest, approver: User) -> None:
    request = _request_for(db, approval)
    if request is None or request.status not in ("pending", "escalated"):
        raise DecisionError("This request is no longer waiting.")
    review.approve(db, approval, approver)


def describe(db: Session, approval: ApprovalRequest) -> dict[str, Any]:
    request = _request_for(db, approval)
    if request is None:
        return {}
    return {
        "time_off_request_id": str(request.id),
        "first_day": request.first_day.isoformat(),
        "last_day": request.last_day.isoformat(),
    }


def lapsed(db: Session, approval: ApprovalRequest) -> None:
    """Its first day began undecided: the request is declined as not reviewed."""
    request = _request_for(db, approval)
    if request is None or request.status not in ("pending", "escalated"):
        return
    request.status, request.decided_at = "denied", approval.decided_at
    record(
        db,
        actor=Actor.system(),
        action="time_off.not_reviewed",
        target_type="time_off_request",
        target_id=request.id,
    )


register_handler(
    "time_off",
    Handler(
        reviewers=review.reviewers,
        sensitive=sensitive,
        apply=apply,
        describe=describe,
        lapsed=lapsed,
        outcome=review.outcome,
    ),
)
