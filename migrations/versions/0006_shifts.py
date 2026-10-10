"""Add the shifts table.

Revision: 0006
Revises: 0005

As in data-model.md and app/modules/schedules/models.py. Company-owned: the department and
the person are linked through (company_id, <x>_id), so a shift can never point into
another company (tenancy layer 2). CHECKs: the end is after the start, and the status
matches the person (open: nobody; scheduled: someone; cancelled: as it was).

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "shifts",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("department_id", sa.BINARY(16), nullable=False),
        sa.Column("employee_id", sa.BINARY(16), nullable=True),
        _moment("starts_at", False),
        _moment("ends_at", False),
        sa.Column("timezone", sa.String(64), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("details", sa.String(200), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("event_name", sa.String(120), nullable=True),
        sa.Column("event_description", sa.Text(), nullable=True),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        sa.ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        sa.Index("ix_shifts_company_department_start", "company_id", "department_id", "starts_at"),
        sa.Index("ix_shifts_company_employee_start", "company_id", "employee_id", "starts_at"),
        sa.CheckConstraint("ends_at > starts_at", name="shifts_times"),
        sa.CheckConstraint(
            "(status = 'open' AND employee_id IS NULL)"
            " OR (status = 'scheduled' AND employee_id IS NOT NULL)"
            " OR status = 'cancelled'",
            name="shifts_status_person",
        ),
    )


def downgrade() -> None:
    op.drop_table("shifts")
