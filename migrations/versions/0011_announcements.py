"""Add the announcements and announcement_reads tables.

Revision: 0011
Revises: 0010

As in docs/features/announcements.md and app/modules/announcements/models.py. Both are
company-owned: the author, the department, the team, the announcement, and the reader are
all linked through (company_id, <x>_id), so nothing here can point into another company
(tenancy layer 2). A CHECK keeps the audience consistent: a company audience names no
department or team, a department audience exactly its department, a team audience exactly
its team. An index on (company_id, created_at) serves the newest-first lists.

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
        "announcements",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("author_id", sa.BINARY(16), nullable=False),
        sa.Column("audience_type", sa.String(10), nullable=False),
        sa.Column("department_id", sa.BINARY(16), nullable=True),
        sa.Column("team_id", sa.BINARY(16), nullable=True),
        sa.Column("title", sa.String(120), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        _moment("edited_at", True),
        _moment("archived_at", True),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "author_id"], ["users.company_id", "users.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        sa.ForeignKeyConstraint(["company_id", "team_id"], ["teams.company_id", "teams.id"]),
        sa.Index("ix_announcements_company_author", "company_id", "author_id"),
        sa.Index("ix_announcements_company_department", "company_id", "department_id"),
        sa.Index("ix_announcements_company_team", "company_id", "team_id"),
        sa.Index("ix_announcements_company_created", "company_id", "created_at"),
        sa.CheckConstraint(
            "(audience_type = 'company' AND department_id IS NULL AND team_id IS NULL)"
            " OR (audience_type = 'department' AND department_id IS NOT NULL"
            " AND team_id IS NULL)"
            " OR (audience_type = 'team' AND team_id IS NOT NULL AND department_id IS NULL)",
            name="announcements_audience",
        ),
    )
    op.create_table(
        "announcement_reads",
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("announcement_id", sa.BINARY(16), primary_key=True),
        sa.Column("user_id", sa.BINARY(16), primary_key=True),
        _moment("read_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "announcement_id"], ["announcements.company_id", "announcements.id"]
        ),
        sa.ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        sa.Index("ix_announcement_reads_company_announcement", "company_id", "announcement_id"),
        sa.Index("ix_announcement_reads_company_user", "company_id", "user_id"),
    )


def downgrade() -> None:
    # The read marks first: they point at the announcements.
    op.drop_table("announcement_reads")
    op.drop_table("announcements")
