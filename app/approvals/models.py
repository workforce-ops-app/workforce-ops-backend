"""The approval tables (data-model.md, approval_requests and approval_decisions).

- approval_requests: one change waiting for approval, with what will happen on approval
  (payload), who asked, whom it is about, and by when it must be decided.
- approval_decisions: one person's approval or denial of one request; each person decides
  a request once.

A pending request grants nothing: for a role, the assignment is created only when the
request is approved. Who may decide is checked again at the moment of each decision.

Company-owned like every company table, with company-aware keys (tenancy.md, layer 2), so
a request or a decision can never point into another company.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    SmallInteger,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps, Timestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned

# The kinds of request. Features add theirs here when they are built (time off, coverage).
KINDS = ("role_assignment", "owner_add", "owner_remove", "account_change", "time_off")

# Where a request is in its life: pending until approved, denied, or cancelled.
STATUSES = ("pending", "approved", "denied", "cancelled")


class ApprovalRequest(IdAndTimestamps, CompanyOwned, Base):
    """Something waiting for approval from people above the requester."""

    __tablename__ = "approval_requests"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: both people belong to this company.
        ForeignKeyConstraint(["company_id", "requested_by"], ["users.company_id", "users.id"]),
        ForeignKeyConstraint(["company_id", "subject_user_id"], ["users.company_id", "users.id"]),
        Index("ix_approval_requests_company_status", "company_id", "status"),
        Index("ix_approval_requests_company_requested_by", "company_id", "requested_by"),
        Index("ix_approval_requests_company_subject", "company_id", "subject_user_id"),
        CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'cancelled')",
            name="approval_requests_status",
        ),
        CheckConstraint("required_approvals >= 1", name="approval_requests_required"),
        # decided_at is set exactly when the request is no longer pending.
        CheckConstraint(
            "(status = 'pending') = (decided_at IS NULL)", name="approval_requests_decided"
        ),
    )

    # role_assignment, owner_add, owner_remove, account_change; features add their own.
    kind: Mapped[str] = mapped_column(String(24))
    # Who asked (for a role: the person giving it).
    requested_by: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # Whom it is about (for a role: the person who would receive it).
    subject_user_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # What happens on approval, checked against the kind (for a role: the role and scope).
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(12), default="pending")
    # How many approvals it needs: 1 for a role at the granter's level.
    required_approvals: Mapped[int] = mapped_column(SmallInteger, default=1)
    # The review deadline; undecided by then, it counts as declined, "not reviewed".
    review_by: Mapped[datetime] = mapped_column(UTC_DATETIME)
    # True when it was declined because nobody decided by review_by.
    not_reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    # When it stopped being pending (null while pending).
    decided_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)


class ApprovalDecision(Timestamps, CompanyOwned, Base):
    """One person's approval or denial of a request."""

    __tablename__ = "approval_decisions"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        # Layer 2: the request belongs to this company.
        ForeignKeyConstraint(
            ["company_id", "request_id"], ["approval_requests.company_id", "approval_requests.id"]
        ),
        Index("ix_approval_decisions_company_request", "company_id", "request_id"),
        CheckConstraint(
            "approver_type IN ('user', 'platform_user')", name="approval_decisions_type"
        ),
        CheckConstraint("decision IN ('approve', 'deny')", name="approval_decisions_decision"),
    )

    request_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
    # user, or platform_user when platform staff decide (a sole owner's account change).
    # No foreign key on approver_id: a platform user is not in the users table. For a
    # user, the service only ever records the signed-in person of this company.
    approver_type: Mapped[str] = mapped_column(String(16), default="user")
    approver_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
    decision: Mapped[str] = mapped_column(String(8))
    decided_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
