"""Add the sessions table: one row per signed-in browser.

Revision: 0004
Revises: 0003

As in data-model.md and app/auth/models.py (decision 0027). Company-owned like every
company table: a unique key on the token's hash (each request finds its session by it),
and the person linked through (company_id, user_id), so a session can only belong to a
person of its own company (tenancy layer 2).

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    op.create_table(
        "sessions",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("user_id", sa.BINARY(16), nullable=False),
        sa.Column("token_hash", sa.BINARY(32), nullable=False),
        _moment("expires_at", False),
        _moment("last_seen_at", False),
        _moment("reauth_at", True),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        sa.UniqueConstraint("token_hash"),
        sa.Index("ix_sessions_company_user", "company_id", "user_id"),
    )


def downgrade() -> None:
    op.drop_table("sessions")
