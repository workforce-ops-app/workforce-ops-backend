"""Opening approval requests (authorization.md, delegation limits; decision 0029).

A feature that needs approval from above calls open_request() instead of making the
change. The request grants nothing while it is pending. Deciding requests (approve, deny,
cancel, and lapsing after the deadline) arrives with the approval endpoints.
"""

import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import KINDS, ApprovalRequest
from app.audit import Actor, record
from app.db.base import utcnow

# A role grant, owner change, or account change nobody decides within this long is
# declined as not reviewed (decision 0032). Other kinds set their own deadline.
REVIEW_WITHIN = timedelta(days=7)


def pending_like(
    db: Session, kind: str, subject_user_id: uuid.UUID, payload: dict[str, Any]
) -> ApprovalRequest | None:
    """A pending request of this kind, about this person, asking for the same thing; read
    fresh (FOR SHARE), for callers holding the company's lock. Used to refuse asking twice."""
    rows = db.scalars(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.kind == kind,
            ApprovalRequest.subject_user_id == subject_user_id,
            ApprovalRequest.status == "pending",
        )
        .with_for_update(read=True)
    )
    return next((row for row in rows if row.payload == payload), None)


def open_request(
    db: Session,
    *,
    kind: str,
    requested_by: uuid.UUID,
    subject_user_id: uuid.UUID,
    payload: dict[str, Any],
    details: dict[str, Any],
    required_approvals: int = 1,
) -> ApprovalRequest:
    """Record a request waiting for approval, with its audit entry; the caller commits.

    `payload` is what happens on approval (kept with the request); `details` is what the
    audit entry shows about it (for a role: its name and scope).
    """
    if kind not in KINDS:
        raise ValueError(f"unknown kind of approval request {kind!r}")
    request = ApprovalRequest(
        kind=kind,
        requested_by=requested_by,
        subject_user_id=subject_user_id,
        payload=payload,
        status="pending",
        required_approvals=required_approvals,
        review_by=utcnow() + REVIEW_WITHIN,
        not_reviewed=False,
    )
    db.add(request)
    db.flush()  # gives the request its ID for the audit entry
    record(
        db,
        actor=Actor.user(requested_by),
        action="approval.requested",
        target_type="approval_request",
        target_id=request.id,
        details={"kind": kind, "subject_user_id": str(subject_user_id), **details},
    )
    return request
