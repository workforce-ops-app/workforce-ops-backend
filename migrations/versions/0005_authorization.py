"""Add the authorization tables: permissions, roles, role_permissions, role_assignments.

Revision: 0005
Revises: 0004

As in data-model.md and app/authz/models.py (decisions 0017 and 0024). permissions is
global and filled by the code (app/authz/registry.py); the other three are company-owned,
and every link goes through (company_id, <x>_id), so a role, a grant, or a scope can never
point into another company (tenancy layer 2).

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0005"
down_revision: str | None = "0004"
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


def _company_id() -> sa.Column:
    """The company a row belongs to (required; the company filter uses it)."""
    return sa.Column("company_id", sa.BINARY(16), nullable=False, index=True)


def upgrade() -> None:
    # permissions: every action the code can check; the same for all companies.
    op.create_table(
        "permissions",
        sa.Column("code", sa.String(100), primary_key=True),
        sa.Column("module", sa.String(50), nullable=False),
        sa.Column("description", sa.String(255), nullable=False),
        *_timestamps(),
    )

    # roles: named sets of permissions per company; each starting role once per company.
    op.create_table(
        "roles",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        _company_id(),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("built_in", sa.String(16), nullable=True),
        _moment("archived_at", True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.UniqueConstraint("company_id", "name"),
        sa.UniqueConstraint("company_id", "built_in"),
        sa.CheckConstraint(
            "built_in IS NULL OR built_in IN ('owner', 'administrator', 'manager', 'employee')",
            name="roles_built_in",
        ),
    )

    # role_permissions: which permissions each role grants.
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.BINARY(16), primary_key=True),
        sa.Column("permission_code", sa.String(100), primary_key=True),
        _company_id(),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.ForeignKeyConstraint(["company_id", "role_id"], ["roles.company_id", "roles.id"]),
        sa.ForeignKeyConstraint(["permission_code"], ["permissions.code"]),
        sa.Index("ix_role_permissions_company_role", "company_id", "role_id"),
    )

    # role_assignments: who holds which role, and where it applies.
    op.create_table(
        "role_assignments",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        _company_id(),
        sa.Column("user_id", sa.BINARY(16), nullable=False),
        sa.Column("role_id", sa.BINARY(16), nullable=False),
        sa.Column("scope_type", sa.String(12), nullable=False),
        sa.Column("department_id", sa.BINARY(16), nullable=True),
        sa.Column("team_id", sa.BINARY(16), nullable=True),
        sa.Column("employee_id", sa.BINARY(16), nullable=True),
        *_timestamps(),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        sa.ForeignKeyConstraint(["company_id", "role_id"], ["roles.company_id", "roles.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        sa.ForeignKeyConstraint(["company_id", "team_id"], ["teams.company_id", "teams.id"]),
        sa.ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        sa.Index("ix_role_assignments_company_user", "company_id", "user_id"),
        sa.Index("ix_role_assignments_company_role", "company_id", "role_id"),
        sa.Index("ix_role_assignments_company_department", "company_id", "department_id"),
        sa.Index("ix_role_assignments_company_team", "company_id", "team_id"),
        sa.Index("ix_role_assignments_company_employee", "company_id", "employee_id"),
        sa.CheckConstraint(
            "(scope_type = 'company' AND department_id IS NULL AND team_id IS NULL"
            " AND employee_id IS NULL)"
            " OR (scope_type = 'department' AND department_id IS NOT NULL AND team_id IS NULL"
            " AND employee_id IS NULL)"
            " OR (scope_type = 'team' AND team_id IS NOT NULL AND department_id IS NULL"
            " AND employee_id IS NULL)"
            " OR (scope_type = 'employee' AND employee_id IS NOT NULL AND department_id IS NULL"
            " AND team_id IS NULL)",
            name="role_assignments_scope",
        ),
    )


def downgrade() -> None:
    # Reverse order: nothing is dropped while another table still links to it.
    op.drop_table("role_assignments")
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("permissions")
