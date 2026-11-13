"""Add the security event tables: security_events and platform_security_events.

Revision: 0008
Revises: 0007

As in docs/features/detection.md and app/modules/security/models.py.
- security_events is company-owned: the person is linked through (company_id, user_id),
  so an event can never name a person of another company (tenancy layer 2).
- platform_security_events has no company_id and no user_id at all (rule DE9).
Both are insert-only, so neither has created_at or updated_at; occurred_at is the time.

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _event_columns() -> list[sa.Column]:
    """The columns both tables share, created fresh for each table."""
    return [
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("pattern_id", sa.String(20), nullable=True),
        sa.Column("field", sa.String(100), nullable=True),
        sa.Column("method", sa.String(10), nullable=True),
        sa.Column("route", sa.String(200), nullable=True),
        sa.Column("client_address", sa.String(45), nullable=True),
        sa.Column("request_id", sa.String(40), nullable=True),
        sa.Column("excerpt", sa.String(200), nullable=True),
        sa.Column("count", sa.Integer(), nullable=False),
        # A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021).
        sa.Column(
            "occurred_at",
            sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"),
            nullable=False,
        ),
    ]


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("user_id", sa.BINARY(16), nullable=False),
        *_event_columns(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        sa.Index("ix_security_events_company_time", "company_id", "occurred_at"),
        sa.Index("ix_security_events_company_kind_time", "company_id", "kind", "occurred_at"),
        sa.Index("ix_security_events_company_user_time", "company_id", "user_id", "occurred_at"),
    )
    op.create_table(
        "platform_security_events",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        *_event_columns(),
        sa.Index("ix_platform_security_events_time", "occurred_at"),
    )


def downgrade() -> None:
    op.drop_table("platform_security_events")
    op.drop_table("security_events")
