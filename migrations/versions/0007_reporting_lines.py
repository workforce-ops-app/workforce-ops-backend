"""Add the reporting_lines table.

Revision: 0007
Revises: 0006

As in data-model.md (reporting_lines) and app/authz/models.py. Company-owned: both people
are linked through (company_id, <x>_id), so a line can never join people of two companies
(tenancy layer 2). The CHECK stops anyone reporting to themselves; loops through other
people are rejected by the service (app/authz/chain.py), since one row cannot see them.

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "reporting_lines",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("manager_id", sa.BINARY(16), nullable=False),
        sa.Column("employee_id", sa.BINARY(16), nullable=False),
        _moment("ended_at", True),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "manager_id"], ["users.company_id", "users.id"]),
        sa.ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        sa.Index("ix_reporting_lines_company_employee", "company_id", "employee_id"),
        sa.Index("ix_reporting_lines_company_manager", "company_id", "manager_id"),
        sa.CheckConstraint("manager_id <> employee_id", name="reporting_lines_not_self"),
    )


def downgrade() -> None:
    op.drop_table("reporting_lines")
