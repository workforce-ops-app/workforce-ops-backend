"""The time_off_requests table (docs/features/time-off.md, backend).

One request for whole days off, from first_day to last_day, in the employee's workplace
time zone (decision 0021: a day off is a calendar date, not a moment). Each request has one
approval record (approval_requests, kind "time_off") that holds the reviewers' decisions;
this row keeps what the employee asked for and where the request stands.

Company-owned with company-aware keys (tenancy.md, layer 2): the employee and the approval
record are always of the request's own company.
"""

import uuid
from datetime import date, datetime

from sqlalchemy import CheckConstraint, Date, ForeignKeyConstraint, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned

# pending until decided; escalated when the direct managers disagree (TO2); a request
# declined because nobody reviewed it in time is "denied" (its approval record says so).
STATUSES = ("pending", "escalated", "approved", "denied", "cancelled")

# Statuses that still hold the days: a new request may not overlap these.
HOLDING = ("pending", "escalated", "approved")


class TimeOffRequest(IdAndTimestamps, CompanyOwned, Base):
    """Whole days off one employee asked for."""

    __tablename__ = "time_off_requests"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: the employee and the approval record belong to this company.
        ForeignKeyConstraint(["company_id", "employee_id"], ["users.company_id", "users.id"]),
        ForeignKeyConstraint(
            ["company_id", "approval_request_id"],
            ["approval_requests.company_id", "approval_requests.id"],
        ),
        # One request, one approval record.
        UniqueConstraint("approval_request_id", name="uq_time_off_requests_approval"),
        Index("ix_time_off_requests_company_employee", "company_id", "employee_id", "first_day"),
        CheckConstraint("last_day >= first_day", name="time_off_requests_days"),
        CheckConstraint(
            "status IN ('pending', 'escalated', 'approved', 'denied', 'cancelled')",
            name="time_off_requests_status",
        ),
    )

    employee_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # Both days included, in the employee's workplace zone.
    first_day: Mapped[date] = mapped_column(Date)
    last_day: Mapped[date] = mapped_column(Date)
    # Optional, shown as plain text only (threat T5).
    reason: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(12), default="pending")
    approval_request_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # When it was approved, denied, or cancelled (null while it waits).
    decided_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
