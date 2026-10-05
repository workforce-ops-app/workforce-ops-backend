"""Add the tables for companies, departments, teams, people, and team membership.

Revision: 0002
Revises: 0001

The first real tables (data-model.md, app/modules/org/models.py). Every table except
companies belongs to one company and has a unique key on (company_id, id); links between
rows go through (company_id, <x>_id), so the database itself refuses a link to another
company's row (tenancy layer 2). Each such link has a named index, which MySQL needs for
it (otherwise it would create an unnamed one itself).

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _id() -> sa.Column:
    """The primary key every table except team_members has: a UUIDv7 as 16 bytes."""
    return sa.Column("id", sa.BINARY(16), primary_key=True)


def _company_id() -> sa.Column:
    """The company a row belongs to (required; the company filter uses it)."""
    return sa.Column("company_id", sa.BINARY(16), nullable=False, index=True)


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def _timestamps() -> list[sa.Column]:
    """created_at and updated_at, on every table."""
    return [_moment("created_at", False), _moment("updated_at", False)]


def upgrade() -> None:
    # companies: one customer organization. Not company-owned itself.
    op.create_table(
        "companies",
        _id(),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("timezone", sa.String(64), nullable=False),
        _moment("archived_at", True),
        *_timestamps(),
    )

    # departments: parts of a company; names unique within the company.
    op.create_table(
        "departments",
        _id(),
        _company_id(),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("timezone", sa.String(64), nullable=True),
        _moment("archived_at", True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.UniqueConstraint("company_id", "name"),
    )

    # teams: groups inside one department of the same company.
    op.create_table(
        "teams",
        _id(),
        _company_id(),
        sa.Column("department_id", sa.BINARY(16), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        _moment("archived_at", True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        sa.UniqueConstraint("department_id", "name"),
        sa.Index("ix_teams_company_department", "company_id", "department_id"),
    )

    # users: people who can sign in; one home department in the same company; email
    # unique across the platform and stored in lowercase.
    op.create_table(
        "users",
        _id(),
        _company_id(),
        sa.Column("department_id", sa.BINARY(16), nullable=False),
        # Compared exactly in MySQL (binary collation): the default ignores case and
        # accents, which would defeat the lowercase CHECK and the uniqueness of addresses.
        sa.Column(
            "email",
            sa.String(254).with_variant(mysql.VARCHAR(254, collation="utf8mb4_bin"), "mysql"),
            nullable=False,
            unique=True,
        ),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("display_name", sa.String(120), nullable=False),
        _moment("password_changed_at", True),
        sa.Column("failed_sign_ins", sa.SmallInteger(), nullable=False, server_default="0"),
        _moment("locked_until", True),
        _moment("deactivated_at", True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        sa.CheckConstraint("email = LOWER(email)", name="users_email_lowercase"),
        sa.Index("ix_users_company_department", "company_id", "department_id"),
    )

    # team_members: who is on which team; team and person in the same company.
    op.create_table(
        "team_members",
        sa.Column("team_id", sa.BINARY(16), primary_key=True),
        sa.Column("user_id", sa.BINARY(16), primary_key=True),
        _company_id(),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.ForeignKeyConstraint(["company_id", "team_id"], ["teams.company_id", "teams.id"]),
        sa.ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        sa.Index("ix_team_members_company_team", "company_id", "team_id"),
        sa.Index("ix_team_members_company_user", "company_id", "user_id"),
    )


def downgrade() -> None:
    # Drop in reverse order, so no table is dropped while another still links to it.
    # Dropping a table also drops its indexes and keys (dropping an index first would
    # fail in MySQL while a foreign key still uses it).
    op.drop_table("team_members")
    op.drop_table("users")
    op.drop_table("teams")
    op.drop_table("departments")
    op.drop_table("companies")
