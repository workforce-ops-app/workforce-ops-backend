"""The announcements and announcement_reads tables (docs/features/announcements.md).

An announcement is a title and a body for one audience: the whole company, one
department, or one team. The audience is fixed once posted. Who is in it is worked out
when someone reads, not stored here, so a person who joins the team later sees it too.
Announcements are archived, never deleted (decision 0020).

A read mark says one person has read one announcement. It is added once and never removed
(AN2 adds the endpoint that writes it; the table is created now with the announcements).
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned

AUDIENCE_TYPES = ("company", "department", "team")


class Announcement(IdAndTimestamps, CompanyOwned, Base):
    """One message to one audience. created_at is when it was posted."""

    __tablename__ = "announcements"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        # Layer 2: read marks link to an announcement through (company_id, id).
        UniqueConstraint("company_id", "id"),
        # Layer 2: the author, the department, and the team all belong to the
        # announcement's company. Each link has an index that starts with its columns
        # (MySQL would otherwise create an unnamed one itself).
        ForeignKeyConstraint(["company_id", "author_id"], ["users.company_id", "users.id"]),
        ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        ForeignKeyConstraint(["company_id", "team_id"], ["teams.company_id", "teams.id"]),
        Index("ix_announcements_company_author", "company_id", "author_id"),
        Index("ix_announcements_company_department", "company_id", "department_id"),
        Index("ix_announcements_company_team", "company_id", "team_id"),
        # The lists are newest first.
        Index("ix_announcements_company_created", "company_id", "created_at"),
        # The audience columns match the type: exactly the ID it needs, and no other.
        CheckConstraint(
            "(audience_type = 'company' AND department_id IS NULL AND team_id IS NULL)"
            " OR (audience_type = 'department' AND department_id IS NOT NULL"
            " AND team_id IS NULL)"
            " OR (audience_type = 'team' AND team_id IS NOT NULL AND department_id IS NULL)",
            name="announcements_audience",
        ),
    )

    # Who posted it. Editing or archiving does not change it.
    author_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # "company", "department", or "team" (AUDIENCE_TYPES).
    audience_type: Mapped[str] = mapped_column(String(10))
    # Set for a department audience only.
    department_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    # Set for a team audience only.
    team_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    # Written by people, so always shown as plain text (threat T5). The body's limit of
    # 4,000 characters is checked by the API (schemas.py).
    title: Mapped[str] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text)
    # Null until the text is first corrected.
    edited_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
    # Null while active.
    archived_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)


class AnnouncementRead(CompanyOwned, Base):
    """One person has read one announcement. Their key is the pair: at most one mark each."""

    __tablename__ = "announcement_reads"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        # Layer 2: the announcement and the person both belong to this company.
        ForeignKeyConstraint(
            ["company_id", "announcement_id"], ["announcements.company_id", "announcements.id"]
        ),
        ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        Index("ix_announcement_reads_company_announcement", "company_id", "announcement_id"),
        Index("ix_announcement_reads_company_user", "company_id", "user_id"),
    )

    announcement_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
    read_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
