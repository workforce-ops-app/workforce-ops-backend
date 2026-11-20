"""Response shapes for approval requests (data-model.md, approval_requests)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import handler_for
from app.authz.models import Role
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
    # Who may decide it now (empty once it is decided), worked out fresh as for a
    # decision; the interface shows "Sent for approval to ...". Only people above
    # the requester, so it shows them nobody they could not find out anyway.
    reviewers: list[Reviewer]
    # Who asked, who it is about, and the role (role requests only), so the screens
    # say what is being decided without lookups the viewer may not be allowed to
    # make. Only people the viewer already deals with: the requester and the subject
    # are below every reviewer, and "mine" lists only the viewer's own requests
    # and those about them.
    requested_by_name: str
    subject_name: str
    role_name: str | None


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
        requested_by_name=_name(db, item.requested_by),
        subject_name=_name(db, item.subject_user_id),
        role_name=_role_name(db, item),
    )


def _name(db: Session, person_id: uuid.UUID) -> str:
    person = db.get(User, person_id)
    return person.display_name if person else "Unknown"


def _role_name(db: Session, item: ApprovalRequest) -> str | None:
    """The role a role request would give (payload role_id), else None."""
    role_id = item.payload.get("role_id") if item.kind == "role_assignment" else None
    if not role_id:
        return None
    role = db.get(Role, uuid.UUID(str(role_id)))
    return role.name if role else None


def _reviewers(db: Session, item: ApprovalRequest) -> list[Reviewer]:
    if item.status != "pending":
        return []
    # The same rule as a decision: never the requester or the person it is about.
    ids = handler_for(item).reviewers(db, item) - {item.requested_by, item.subject_user_id}
    found = [person for person_id in ids if (person := db.get(User, person_id))]
    return [
        Reviewer(id=person.id, display_name=person.display_name)
        for person in sorted(found, key=lambda p: (p.display_name.lower(), str(p.id)))
        if person.deactivated_at is None
    ]
