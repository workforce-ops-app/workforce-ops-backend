"""Add the one_time_tokens table: setup and reset links.

Revision: 0009
Revises: 0008

As in data-model.md and app/auth/models.py (decision 0027). Company-owned like every
company table: the person and the administrator who created the link are both linked
through (company_id, user_id), so a link can only set the password of a person of its own
company, and only someone of that company can have created it (tenancy layer 2). A unique
key on the token's hash, because redeeming finds the link by it.

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


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "one_time_tokens",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("user_id", sa.BINARY(16), nullable=False),
        sa.Column("purpose", sa.String(8), nullable=False),
        sa.Column("token_hash", sa.BINARY(32), nullable=False),
        sa.Column("created_by", sa.BINARY(16), nullable=False),
        _moment("expires_at", False),
        _moment("used_at", True),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        sa.ForeignKeyConstraint(["company_id", "created_by"], ["users.company_id", "users.id"]),
        sa.UniqueConstraint("token_hash"),
        sa.CheckConstraint("purpose IN ('setup', 'reset')", name="one_time_tokens_purpose"),
        sa.Index("ix_one_time_tokens_company_user", "company_id", "user_id"),
        sa.Index("ix_one_time_tokens_company_created_by", "company_id", "created_by"),
    )


def downgrade() -> None:
    op.drop_table("one_time_tokens")
