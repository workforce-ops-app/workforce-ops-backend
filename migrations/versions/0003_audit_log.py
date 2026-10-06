"""Add the audit log's tables: the chain heads and the entries.

Revision: 0003
Revises: 0002

As in audit-log.md and app/audit/models.py (decision 0018). One chain per company plus
the platform chain; each entry is numbered within its chain and signed together with the
previous entry's signature. The application only ever adds entries; insert-only database
rights follow in T2 (#43), and until then the signatures detect any change.

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def _timestamps() -> list[sa.Column]:
    """created_at and updated_at, on every table."""
    return [_moment("created_at", False), _moment("updated_at", False)]


def upgrade() -> None:
    # audit_chain_heads: where each chain ends (newest number and signature). One per
    # company, plus the platform chain (all-zero ID, no company).
    op.create_table(
        "audit_chain_heads",
        sa.Column("chain_id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=True, unique=True),
        sa.Column("last_seq", sa.BigInteger(), nullable=False),
        sa.Column("last_signature", sa.BINARY(32), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.CheckConstraint(
            "company_id IS NULL OR chain_id = company_id", name="audit_chain_heads_company"
        ),
        sa.CheckConstraint("last_seq >= 0", name="audit_chain_heads_seq"),
    )

    # audit_events: one signed entry per recorded action; (chain_id, seq) unique, so two
    # entries can never share a place in a chain.
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("chain_id", sa.BINARY(16), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("company_id", sa.BINARY(16), nullable=True),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.BINARY(16), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=True),
        sa.Column("target_id", sa.BINARY(16), nullable=True),
        _moment("occurred_at", False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("key_id", sa.String(40), nullable=False),
        sa.Column("prev_signature", sa.BINARY(32), nullable=False),
        sa.Column("signature", sa.BINARY(32), nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["chain_id"], ["audit_chain_heads.chain_id"]),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("chain_id", "seq"),
        sa.CheckConstraint("seq >= 1", name="audit_events_seq"),
        sa.CheckConstraint(
            "(actor_type = 'system' AND actor_id IS NULL)"
            " OR (actor_type IN ('user', 'platform_user') AND actor_id IS NOT NULL)",
            name="audit_events_actor",
        ),
        sa.Index("ix_audit_events_company", "company_id"),
    )


def downgrade() -> None:
    # Entries first: they link to the chain heads.
    op.drop_table("audit_events")
    op.drop_table("audit_chain_heads")
