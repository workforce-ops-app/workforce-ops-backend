"""The time_off_requests and coverage_offers tables (docs/features/time-off.md and
coverage.md, backend).

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

# collecting while coworkers may offer to cover or swap its shifts (asked with "Offer Shift
# Swap / Coverage", coverage.md); pending until decided; escalated when the direct
# managers disagree (TO2); a request declined because nobody reviewed it in time is
# "denied" (its approval record says so).
STATUSES = ("collecting", "pending", "escalated", "approved", "denied", "cancelled")

# Statuses that still hold the days: a new request may not overlap these.
HOLDING = ("collecting", "pending", "escalated", "approved")

# Still open: nobody has settled it yet.
OPEN = ("collecting", "pending", "escalated")


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
        # One request, one approval record. company_id comes first so this index also
        # serves the company-aware key above; without it MySQL adds an unnamed index of its
        # own, which the migration check reports as a difference.
        UniqueConstraint("company_id", "approval_request_id", name="uq_time_off_requests_approval"),
        Index("ix_time_off_requests_company_employee", "company_id", "employee_id", "first_day"),
        CheckConstraint("last_day >= first_day", name="time_off_requests_days"),
        CheckConstraint(
            "status IN ('collecting', 'pending', 'escalated', 'approved', 'denied', 'cancelled')",
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
    # Asked with offers (coverage.md): when a collecting request goes up to the managers by
    # itself if the employee has not sent it up. Null: asked without offers. Fixed when the
    # request is asked, so a later change of the setting does not move it.
    offers_close_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
    # When it went up to the managers (by the employee, or at offers_close_at). Null while
    # collecting, and for a request asked without offers.
    sent_up_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)


# One coworker's answer about one shift of a request asked with offers (coverage.md).
ANSWERS = ("cover", "swap", "decline")
# offered while the request is open; at the end chosen, not_chosen (approved without it),
# or dropped (declined, cancelled, or not reviewed).
OFFER_STATUSES = ("offered", "chosen", "not_chosen", "dropped")


class CoverageOffer(IdAndTimestamps, CompanyOwned, Base):
    """A coworker's answer about one of the employee's shifts on a time-off request: cover
    it, swap it for one of their own shifts, or decline."""

    __tablename__ = "coverage_offers"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: the request, the shifts, and the coworker belong to this company.
        ForeignKeyConstraint(
            ["company_id", "time_off_request_id"],
            ["time_off_requests.company_id", "time_off_requests.id"],
        ),
        ForeignKeyConstraint(["company_id", "shift_id"], ["shifts.company_id", "shifts.id"]),
        ForeignKeyConstraint(["company_id", "offered_by"], ["users.company_id", "users.id"]),
        ForeignKeyConstraint(["company_id", "swap_shift_id"], ["shifts.company_id", "shifts.id"]),
        # One answer per coworker per shift of a request: a new answer replaces the old one.
        # It also serves the request's company-aware key above (company_id first).
        UniqueConstraint(
            "company_id",
            "time_off_request_id",
            "shift_id",
            "offered_by",
            name="uq_coverage_offers_answer",
        ),
        # An index for each other company-aware key, named, so MySQL adds none of its own.
        Index("ix_coverage_offers_company_shift", "company_id", "shift_id"),
        Index("ix_coverage_offers_company_offered_by", "company_id", "offered_by"),
        Index("ix_coverage_offers_company_swap_shift", "company_id", "swap_shift_id"),
        CheckConstraint("answer IN ('cover', 'swap', 'decline')", name="coverage_offers_answer"),
        CheckConstraint(
            "status IN ('offered', 'chosen', 'not_chosen', 'dropped')",
            name="coverage_offers_status",
        ),
        # A swap names the shift given in exchange; the other answers never do.
        CheckConstraint(
            "(answer = 'swap') = (swap_shift_id IS NOT NULL)", name="coverage_offers_swap"
        ),
    )

    time_off_request_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    shift_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)  # the employee's shift
    offered_by: Mapped[uuid.UUID] = mapped_column(UUIDBinary)  # the coworker
    answer: Mapped[str] = mapped_column(String(8))
    swap_shift_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    status: Mapped[str] = mapped_column(String(10), default="offered")
