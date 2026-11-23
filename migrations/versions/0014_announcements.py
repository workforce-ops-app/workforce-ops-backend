"""Add the announcements and announcement_reads tables.

Revision: 0014
Revises: 0013

As in docs/features/announcements.md and app/modules/announcements/models.py. Both are
company-owned: the author, the department, the team, the announcement, and the reader are
all linked through (company_id, <x>_id), so nothing here can point into another company
(tenancy layer 2). A CHECK keeps the audience consistent: a company audience names no
department or team, a department audience exactly its department, a team audience exactly
its team. An index on (company_id, created_at) serves the newest-first lists.

It also gives the permission announcement.create to the Owner, Administrator, and Manager
starting roles of every company that already exists (review of #157). New companies get
it from app/authz/roles.py, but the roles of a company made before this migration were
filled with the permissions known then, so without this their managers and
administrators would be refused (403) when they tried to post. The step only adds grants
that are missing and never removes or changes anything else. Company-made roles are left
alone: an administrator gives the permission to them as to any role.

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PERMISSION = "announcement.create"
DESCRIPTION = "Post, edit, and archive announcements for an audience in scope; see who read them"
# The starting roles that grant it (app/authz/roles.py): not Employee.
STARTING_ROLES = ("owner", "administrator", "manager")


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

    # The permission for existing companies (the top of this file). First the permission
    # itself, unless the app already registered it (it does so on start, sync_permissions).
    connection = op.get_bind()
    now = datetime.now(UTC).replace(tzinfo=None)  # stored as UTC without a zone (0021)
    known = connection.execute(
        sa.text("SELECT 1 FROM permissions WHERE code = :code"), {"code": PERMISSION}
    ).first()
    if known is None:
        connection.execute(
            sa.text(
                "INSERT INTO permissions (code, module, description, created_at, updated_at) "
                "VALUES (:code, 'announcements', :description, :now, :now)"
            ),
            {"code": PERMISSION, "description": DESCRIPTION, "now": now},
        )
    # Then a grant on every company's Owner, Administrator, and Manager role that does not
    # have it yet, so running this again, or on an empty database, changes nothing more.
    connection.execute(
        sa.text(
            "INSERT INTO role_permissions "
            "(role_id, permission_code, company_id, created_at, updated_at) "
            "SELECT r.id, :code, r.company_id, :now, :now FROM roles r "
            "WHERE r.built_in IN :roles AND NOT EXISTS ("
            "SELECT 1 FROM role_permissions rp "
            "WHERE rp.role_id = r.id AND rp.permission_code = :code)"
        ).bindparams(sa.bindparam("roles", expanding=True)),
        {"code": PERMISSION, "now": now, "roles": list(STARTING_ROLES)},
    )


def downgrade() -> None:
    # The grants and the permission go first: going back to before announcements removes
    # them from every role (the grants point at the permission).
    connection = op.get_bind()
    connection.execute(
        sa.text("DELETE FROM role_permissions WHERE permission_code = :code"),
        {"code": PERMISSION},
    )
    connection.execute(sa.text("DELETE FROM permissions WHERE code = :code"), {"code": PERMISSION})
    # The read marks first: they point at the announcements.
    op.drop_table("announcement_reads")
    op.drop_table("announcements")
