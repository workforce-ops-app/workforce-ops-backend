"""Response shapes for approval requests (data-model.md, approval_requests)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalDecision, ApprovalRequest
from app.approvals.service import handler_for
from app.modules.org.models import User


class Reviewer(BaseModel):
    """Someone who may decide a request now."""

    id: uuid.UUID
    display_name: str


class ApprovalRequestOut(BaseModel):
    """A request waiting for (or past) approval from above."""

    id: uuid.UUID
    kind: str  # role_assignment for now; features add theirs
    status: str  # pending, approved, denied, cancelled
    requested_by: uuid.UUID
    subject_user_id: uuid.UUID
    payload: dict[str, Any]  # what happens on approval (a role: role_id, scope_type, scope_id)
    required_approvals: int
    review_by: datetime
    not_reviewed: bool  # denied because nobody decided by review_by
    created_at: datetime
    decided_at: datetime | None
    # Who may decide it now (empty once it is decided; never someone who already has),
    # worked out as for a decision; the interface shows "Sent for approval to ...".
    # Only people above the requester, so it shows them nobody they could not find out
    # anyway.
    reviewers: list[Reviewer]


class ApprovalRequestList(BaseModel):
    items: list[ApprovalRequestOut]


def shown(db: Session, item: ApprovalRequest) -> ApprovalRequestOut:
    """A request in the answer shape, with who may decide it now."""
    return ApprovalRequestOut(
        id=item.id,
        kind=item.kind,
        status=item.status,
        requested_by=item.requested_by,
        subject_user_id=item.subject_user_id,
        payload=item.payload,
        required_approvals=item.required_approvals,
        review_by=item.review_by,
        not_reviewed=item.not_reviewed,
        created_at=item.created_at,
        decided_at=item.decided_at,
        reviewers=_reviewers(db, item),
    )


def _reviewers(db: Session, item: ApprovalRequest) -> list[Reviewer]:
    if item.status != "pending":
        return []
    # The same rules as a decision: never the requester or the person it is about, and
    # never someone who already decided it (a request needing several approvals stays
    # pending after the first; decide() refuses a second decision by the same person).
    decided = set(
        db.scalars(
            select(ApprovalDecision.approver_id).where(ApprovalDecision.request_id == item.id)
        )
    )
    ids = handler_for(item).reviewers(db, item) - {item.requested_by, item.subject_user_id}
    ids -= decided
    found = [person for person_id in ids if (person := db.get(User, person_id))]
    return [
        Reviewer(id=person.id, display_name=person.display_name)
        for person in sorted(found, key=lambda p: (p.display_name.lower(), str(p.id)))
        if person.deactivated_at is None
    ]
