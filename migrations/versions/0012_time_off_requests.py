"""Add the time_off_requests table.

Revision: 0012
Revises: 0011

As in docs/features/time-off.md and app/modules/time_off/models.py. Each request links to
one approval record (approval_requests, kind "time_off", migration 0011) through a
company-aware key, so the two are always of the same company (tenancy layer 2).

Types are written out here instead of importing them from the app, so this migration keeps
working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "time_off_requests",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("employee_id", sa.BINARY(16), nullable=False),
        sa.Column("first_day", sa.Date(), nullable=False),
        sa.Column("last_day", sa.Date(), nullable=False),
        sa.Column("reason", sa.String(500), nullable=True),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("approval_request_id", sa.BINARY(16), nullable=False),
        _moment("decided_at", True),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "approval_request_id"],
            ["approval_requests.company_id", "approval_requests.id"],
        ),
        sa.UniqueConstraint(
            "company_id", "approval_request_id", name="uq_time_off_requests_approval"
        ),
        sa.CheckConstraint("last_day >= first_day", name="time_off_requests_days"),
        sa.CheckConstraint(
            "status IN ('pending', 'escalated', 'approved', 'denied', 'cancelled')",
            name="time_off_requests_status",
        ),
        sa.Index("ix_time_off_requests_company_employee", "company_id", "employee_id", "first_day"),
    )


def downgrade() -> None:
    op.drop_table("time_off_requests")
