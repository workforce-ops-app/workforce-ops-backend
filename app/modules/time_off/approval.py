"""What a "time_off" approval request does (docs/features/time-off.md; decision 0029).

For now (TO1) this only connects time-off requests to the shared approval layer, so that
a request whose first day begins undecided is declined as not reviewed, and its own row
says so. Who reviews a request, escalation, and opening the shifts on approval arrive with
TO2 (#64); until then nobody can decide one, so none is approved by mistake.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import DecisionError, Handler, register_handler
from app.audit import Actor, record
from app.modules.org.models import User
from app.modules.time_off.models import TimeOffRequest


def _request_for(db: Session, approval: ApprovalRequest) -> TimeOffRequest | None:
    return db.scalars(
        select(TimeOffRequest).where(TimeOffRequest.approval_request_id == approval.id)
    ).one_or_none()


def reviewers(db: Session, approval: ApprovalRequest) -> set[uuid.UUID]:
    return set()  # routing arrives with TO2 (#64)


def sensitive(db: Session, approval: ApprovalRequest) -> bool:
    return False


def apply(db: Session, approval: ApprovalRequest, approver: User) -> None:
    raise DecisionError("Time-off requests cannot be reviewed yet.")


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
        reviewers=reviewers, sensitive=sensitive, apply=apply, describe=describe, lapsed=lapsed
    ),
)
