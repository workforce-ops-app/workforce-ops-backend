"""Response shapes for approval requests (data-model.md, approval_requests)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.approvals.models import ApprovalRequest


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


class ApprovalRequestList(BaseModel):
    items: list[ApprovalRequestOut]


def shown(item: ApprovalRequest) -> ApprovalRequestOut:
    """A request in the answer shape."""
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
    )
