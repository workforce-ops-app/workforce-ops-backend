"""Add the approval tables: approval_requests and approval_decisions.

Revision: 0011
Revises: 0010

As in data-model.md and app/approvals/models.py (decisions 0029 and 0032). Shared by every
kind of request that waits for someone above the requester: roles given at the granter's
own level first, time off and coverage later. Company-owned with company-aware keys
(tenancy layer 2): a request's people, and a decision's request, are always of the same
company.

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("requested_by", sa.BINARY(16), nullable=False),
        sa.Column("subject_user_id", sa.BINARY(16), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("required_approvals", sa.SmallInteger(), nullable=False),
        _moment("review_by", False),
        sa.Column("not_reviewed", sa.Boolean(), nullable=False),
        _moment("decided_at", True),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "requested_by"], ["users.company_id", "users.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "subject_user_id"], ["users.company_id", "users.id"]
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'cancelled')",
            name="approval_requests_status",
        ),
        sa.CheckConstraint("required_approvals >= 1", name="approval_requests_required"),
        sa.CheckConstraint(
            "(status = 'pending') = (decided_at IS NULL)", name="approval_requests_decided"
        ),
        sa.Index("ix_approval_requests_company_status", "company_id", "status"),
        sa.Index("ix_approval_requests_company_requested_by", "company_id", "requested_by"),
        sa.Index("ix_approval_requests_company_subject", "company_id", "subject_user_id"),
    )
    op.create_table(
        "approval_decisions",
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("request_id", sa.BINARY(16), primary_key=True),
        sa.Column("approver_type", sa.String(16), nullable=False),
        sa.Column("approver_id", sa.BINARY(16), primary_key=True),
        sa.Column("decision", sa.String(8), nullable=False),
        _moment("decided_at", False),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "request_id"],
            ["approval_requests.company_id", "approval_requests.id"],
        ),
        sa.CheckConstraint(
            "approver_type IN ('user', 'platform_user')", name="approval_decisions_type"
        ),
        sa.CheckConstraint("decision IN ('approve', 'deny')", name="approval_decisions_decision"),
        sa.Index("ix_approval_decisions_company_request", "company_id", "request_id"),
    )


def downgrade() -> None:
    op.drop_table("approval_decisions")
    op.drop_table("approval_requests")
