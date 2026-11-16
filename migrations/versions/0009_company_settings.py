"""Add company_settings: each company's chosen values for configurable rules.

Revision: 0009
Revises: 0008

As in docs/architecture/data-model.md (company_settings) and app/settings/models.py.
A company has a row only for a setting it has changed; no row means the platform default,
so existing companies need no rows and keep exactly the rules they had.

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=False
    )


def upgrade() -> None:
    op.create_table(
        "company_settings",
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("module", sa.String(50), nullable=False),
        sa.Column("setting_key", sa.String(80), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        _moment("created_at"),
        _moment("updated_at"),
        # Each company holds at most one value per setting.
        sa.PrimaryKeyConstraint("company_id", "module", "setting_key"),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
    )


def downgrade() -> None:
    op.drop_table("company_settings")
