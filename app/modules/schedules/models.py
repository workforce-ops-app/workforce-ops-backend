"""The shifts table (data-model.md, docs/features/schedules.md).

One scheduled block of work in a department, worked by one person, or by nobody yet (an
open shift). Moments are stored in UTC; the workplace's time zone is copied onto the shift
when it is created and never recalculated, so later settings changes or daylight-saving
rules never move it (decision 0021). Cancelled shifts are kept with status "cancelled",
never deleted (decision 0020).
"""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned

STATUSES = ("scheduled", "open", "cancelled")


class Shift(IdAndTimestamps, CompanyOwned, Base):
    """One block of work in one department, for one person or nobody (open)."""

    __tablename__ = "shifts"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: the department and the person both belong to the shift's company.
        ForeignKeyConstraint(
            ["company_id", "department_id"], ["departments.company_id", "departments.id"]
        ),
        ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        # The week views ask "this department, these days" and "this person, these days".
        Index("ix_shifts_company_department_start", "company_id", "department_id", "starts_at"),
        Index("ix_shifts_company_employee_start", "company_id", "employee_id", "starts_at"),
        CheckConstraint("ends_at > starts_at", name="shifts_times"),
        # Status and person match: an open shift has nobody, a scheduled one has someone;
        # a cancelled shift keeps whatever it had when it was cancelled.
        CheckConstraint(
            "(status = 'open' AND employee_id IS NULL)"
            " OR (status = 'scheduled' AND employee_id IS NOT NULL)"
            " OR status = 'cancelled'",
            name="shifts_status_person",
        ),
    )

    department_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # Null while the shift is open.
    employee_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    starts_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    ends_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    # The workplace zone at creation, e.g. "America/Chicago"; never recalculated.
    timezone: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(12))
    # Written by people, so always shown as plain text (threat T5).
    details: Mapped[str | None] = mapped_column(String(200))
    notes: Mapped[str | None] = mapped_column(Text)
    event_name: Mapped[str | None] = mapped_column(String(120))
    event_description: Mapped[str | None] = mapped_column(Text)
