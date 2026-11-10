"""The authorization tables: permissions, roles, what roles grant, and who holds which role
where (data-model.md, decisions 0017 and 0024).

- permissions: every action the application can check, such as "schedule.edit". The same
  for all companies and maintained by the code (app/authz/registry.py), so it is the one
  table here that is not company-owned.
- roles: a named set of permissions one company defines, such as Manager.
- role_permissions: which permissions each role grants.
- role_assignments: gives a person a role and says WHERE it applies: the whole company,
  one department, one team, or one employee.
- reporting_lines: who reports to whom; decides WHOM a person permission may act on.

Company-owned tables follow the company-aware key convention (tenancy.md, layer 2): every
link goes through (company_id, <x>_id), so a role or a scope can never point into another
company, even if a bug got past the company filter.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Computed,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps, Timestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned

# The four starting roles every company gets; the code finds them by this value even after
# a company renames them.
BUILT_IN_ROLES = ("owner", "administrator", "manager", "employee")

# Where an assignment applies (decision 0017).
SCOPE_TYPES = ("company", "department", "team", "employee")


class Permission(Timestamps, Base):
    """One action the application can check, declared by a module. Not company-owned."""

    __tablename__ = "permissions"

    # "resource.action", lowercase; "_self" at the end for self-service permissions.
    code: Mapped[str] = mapped_column(String(100), primary_key=True)
    # The module that declares it, e.g. "schedules".
    module: Mapped[str] = mapped_column(String(50))
    description: Mapped[str] = mapped_column(String(255))


class Role(IdAndTimestamps, CompanyOwned, Base):
    """A named set of permissions of one company."""

    __tablename__ = "roles"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        UniqueConstraint("company_id", "name"),
        # Each starting role exists once per company (several nulls are allowed).
        UniqueConstraint("company_id", "built_in"),
        CheckConstraint(
            "built_in IS NULL OR built_in IN ('owner', 'administrator', 'manager', 'employee')",
            name="roles_built_in",
        ),
    )

    name: Mapped[str] = mapped_column(String(80))
    # owner, administrator, manager, or employee for a starting role; null for a role the
    # company added.
    built_in: Mapped[str | None] = mapped_column(String(16))
    # Null while active. An archived role grants nothing.
    archived_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)


class RolePermission(Timestamps, CompanyOwned, Base):
    """One permission one role grants."""

    __tablename__ = "role_permissions"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        # Layer 2: the role belongs to this company.
        ForeignKeyConstraint(["company_id", "role_id"], ["roles.company_id", "roles.id"]),
        Index("ix_role_permissions_company_role", "company_id", "role_id"),
    )

    role_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
    permission_code: Mapped[str] = mapped_column(
        String(100), ForeignKey("permissions.code"), primary_key=True
    )


class RoleAssignment(IdAndTimestamps, CompanyOwned, Base):
    """A person holds a role, for one scope: the company, a department, a team, or a person."""

    __tablename__ = "role_assignments"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: the holder, the role, and the scope all belong to this company.
        ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        ForeignKeyConstraint(["company_id", "role_id"], ["roles.company_id", "roles.id"]),
        ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        ForeignKeyConstraint(["company_id", "team_id"], ["teams.company_id", "teams.id"]),
        ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        Index("ix_role_assignments_company_user", "company_id", "user_id"),
        Index("ix_role_assignments_company_role", "company_id", "role_id"),
        Index("ix_role_assignments_company_department", "company_id", "department_id"),
        Index("ix_role_assignments_company_team", "company_id", "team_id"),
        Index("ix_role_assignments_company_employee", "company_id", "employee_id"),
        # Exactly the column that matches scope_type is filled in, and none for company.
        CheckConstraint(
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

    # Who holds the role, and which role.
    user_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    role_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # Where it applies; exactly one of the three columns below matches scope_type.
    scope_type: Mapped[str] = mapped_column(String(12))
    department_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    team_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    employee_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)


class ReportingLine(IdAndTimestamps, CompanyOwned, Base):
    """One person reports to another (data-model.md, reporting_lines; decision 0024).

    Following the lines upwards from a person gives everyone above them
    (app/authz/chain.py). A person may report to several managers, and a manager may have
    many reports, so this is a table of its own rather than a column on users.
    """

    __tablename__ = "reporting_lines"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: both people belong to this company.
        ForeignKeyConstraint(["company_id", "manager_id"], ["users.company_id", "users.id"]),
        ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        # Walking up starts from the employee, walking down from the manager.
        Index("ix_reporting_lines_company_employee", "company_id", "employee_id"),
        Index("ix_reporting_lines_company_manager", "company_id", "manager_id"),
        # Nobody reports to themselves. Loops through other people need the chain, so the
        # service checks those (app/authz/chain.py, add_reporting_line).
        CheckConstraint("manager_id <> employee_id", name="reporting_lines_not_self"),
        # One current line per pair, enforced by the database too (the service checks it
        # first, under a lock). current_line is 1 while the line is current and NULL once
        # it has ended; a unique key allows any number of NULLs, so ended lines (history)
        # never block adding the same line again later.
        UniqueConstraint(
            "company_id",
            "manager_id",
            "employee_id",
            "current_line",
            name="uq_reporting_lines_current",
        ),
    )

    # The person reported to.
    manager_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # The person reporting.
    employee_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # Null while the line is current. Ending a line keeps it as history (decision 0020).
    ended_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
    # Worked out by the database from ended_at, never written by the application: 1 while
    # the line is current, NULL once it has ended (a CASE without ELSE gives NULL). Exists
    # only for the unique key above. CASE rather than MySQL's IF(), so the SQLite the tests
    # use understands it too.
    current_line: Mapped[bool | None] = mapped_column(
        Boolean, Computed("CASE WHEN ended_at IS NULL THEN 1 END", persisted=True)
    )
