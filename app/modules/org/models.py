"""The tables for companies, departments, teams, people, and team membership.

As designed in docs/architecture/data-model.md. Read top to bottom, this file is the
company's structure: a company has departments, a department has teams, every person
belongs to one home department, and people can be on several teams.

Two protections keep companies apart here (tenancy.md):
- Layer 1, the automatic company filter: every table except companies inherits
  CompanyOwned, so every query on it is limited to the session's company; companies
  itself is marked CompanyRecord, so a session sees and changes only its own company.
- Layer 2, company-aware keys: each of those tables has a unique key on
  (company_id, id), and every link to another row goes through (company_id, <x>_id).
  The database itself then refuses a link to another company's row, for example a team
  in company B pointing at a department of company A, even if layer 1 were bypassed.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    ForeignKeyConstraint,
    Index,
    SmallInteger,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps, Timestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned, CompanyRecord

# Email addresses compared exactly in MySQL (binary collation). MySQL's default comparison
# ignores case and accents, which would make the lowercase CHECK below always pass and
# treat "jose@..." and "josé@..." as the same address. Other databases compare exactly
# anyway, so the plain type is used there.
EMAIL = String(254).with_variant(mysql.VARCHAR(254, collation="utf8mb4_bin"), "mysql")


class Company(IdAndTimestamps, CompanyRecord, Base):
    """One customer organization (a tenant). Everything else belongs to exactly one company.

    Not company-owned itself (each row is a company), but protected by the company filter
    as CompanyRecord: a session working for a company sees and changes only its own row.
    Only platform code (for now the seed script, in a session with no company) creates or
    archives companies.
    """

    __tablename__ = "companies"

    name: Mapped[str] = mapped_column(String(200))
    # The workplace time zone, as an IANA name such as "America/Chicago" (decision 0021).
    timezone: Mapped[str] = mapped_column(String(64))
    # Null while the company is active (decision 0020: archive, never delete).
    archived_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)


class Department(IdAndTimestamps, CompanyOwned, Base):
    """A part of a company, such as Kitchen or Front of House."""

    __tablename__ = "departments"
    __table_args__ = (
        # The company exists.
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        # Layer 2: other tables link to a department through (company_id, id), so this
        # pair must be unique.
        UniqueConstraint("company_id", "id"),
        # Two departments of one company cannot share a name.
        UniqueConstraint("company_id", "name"),
    )

    name: Mapped[str] = mapped_column(String(120))
    # Optional: overrides the company's time zone for this department.
    timezone: Mapped[str | None] = mapped_column(String(64))
    archived_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)


class Team(IdAndTimestamps, CompanyOwned, Base):
    """A smaller group inside one department, such as the Weekend Crew."""

    __tablename__ = "teams"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: the department must belong to the same company as the team. The index
        # serves this link (MySQL would otherwise create an unnamed one itself).
        ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        Index("ix_teams_company_department", "company_id", "department_id"),
        # Two teams in one department cannot share a name.
        UniqueConstraint("department_id", "name"),
    )

    department_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    name: Mapped[str] = mapped_column(String(120))
    archived_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)


class User(IdAndTimestamps, CompanyOwned, Base):
    """A person who can sign in: an employee, manager, administrator, or owner of one company.

    The sign-in columns (password and lockout) are part of the design now, so the sign-in
    slices need no migration of their own (authentication.md).
    """

    __tablename__ = "users"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: the home department must belong to the same company as the person.
        ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        Index("ix_users_company_department", "company_id", "department_id"),
        # Emails are stored in lowercase, so the same address typed differently cannot
        # become two accounts.
        CheckConstraint("email = LOWER(email)", name="users_email_lowercase"),
    )

    # The home department: every person has exactly one.
    department_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # Unique across the whole platform, not only the company, so signing in needs only an
    # email and a password (decision 0016).
    email: Mapped[str] = mapped_column(EMAIL, unique=True)
    # Argon2id hash (decision 0027); null until the person sets a password with their
    # setup link. Never the password itself.
    password_hash: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(120))
    password_changed_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
    # Wrong passwords since the last success, for the lockout schedule.
    failed_sign_ins: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    # Null when not locked.
    locked_until: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
    # Null while active; deactivated people cannot sign in (never deleted, decision 0020).
    deactivated_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)

    @validates("email")
    def _lowercase_email(self, key: str, email: str) -> str:
        """Store every email in lowercase, so "Ana@Example.com" and "ana@example.com" are
        one address. Called by SQLAlchemy whenever email is set. The CHECK constraint in
        the database is the backstop if anything ever writes around this."""
        return email.lower()


class TeamMember(Timestamps, CompanyOwned, Base):
    """Who is on which team. Being on a team does not change a person's home department."""

    __tablename__ = "team_members"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        # Layer 2: the team and the person must both belong to this company.
        ForeignKeyConstraint(["company_id", "team_id"], ["teams.company_id", "teams.id"]),
        ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        Index("ix_team_members_company_team", "company_id", "team_id"),
        Index("ix_team_members_company_user", "company_id", "user_id"),
    )

    # Together the key: a person is on a team at most once.
    team_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
