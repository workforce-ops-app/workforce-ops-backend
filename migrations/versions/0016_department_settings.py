"""Add the department_settings table.

Revision: 0016
Revises: 0015

As in docs/features/coverage.md and app/settings/models.py: a department's own, stricter
value for a setting declared per_department (time_off.offers_close_days for now). Company-
owned, with a company-aware key to the department (tenancy layer 2), so a row can never
belong to another company's department.

Types are written out here instead of importing them from the app, so this migration keeps
working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "department_settings",
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("department_id", sa.BINARY(16), nullable=False),
        sa.Column("module", sa.String(50), nullable=False),
        sa.Column("setting_key", sa.String(80), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.PrimaryKeyConstraint("company_id", "department_id", "module", "setting_key"),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
    )


def downgrade() -> None:
    op.drop_table("department_settings")
