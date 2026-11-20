"""Request and response shapes for time off (docs/features/time-off.md).

Requests forbid unknown fields, so a body cannot set a status, an employee, or an
approval record (threat T2): those only change through the rules in service.py.
"""

import uuid
from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, StringConstraints

from app.modules.org.schemas import Strict

# An optional reason: surrounding spaces removed, at most 500 characters (the column).
# Shown as plain text only (threat T5): the interface never renders it as HTML.
Reason = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]


class TimeOffCreate(Strict):
    """Whole days off, both included, in your workplace's time zone."""

    first_day: date
    last_day: date
    reason: Reason | None = None


class Step(BaseModel):
    """One reviewer's decision so far (names only; comments stay on the request page)."""

    approver_id: uuid.UUID
    approver_name: str
    decision: str  # approve or deny


class Person(BaseModel):
    id: uuid.UUID
    display_name: str


class Progress(BaseModel):
    """Where an open request stands."""

    decided: list[Step]  # oldest first
    waiting_for: list[Person]  # reviewers who have not decided yet, by name


class TimeOffOut(BaseModel):
    """A request as its employee and its reviewers see it."""

    id: uuid.UUID
    employee_id: uuid.UUID
    # Who asked, so the review screen names them without a lookup the reviewer may
    # not be allowed to make (#172). Anyone who may see the request may see this.
    employee_name: str
    first_day: date
    last_day: date
    reason: str | None
    status: str  # pending, escalated, approved, denied, cancelled
    not_reviewed: bool  # denied because nobody reviewed it before its first day
    created_at: datetime
    decided_at: datetime | None
    # While the request is open (pending or escalated): who has decided so far and who
    # still has to, so a request one manager already denied does not read as untouched.
    # None once it is settled. The employee already sees these decisions on the request.
    progress: Progress | None = None


class AffectedShift(BaseModel):
    """One of the employee's shifts on the requested days."""

    id: uuid.UUID
    department_id: uuid.UUID
    starts_at: datetime
    ends_at: datetime


class Decision(BaseModel):
    """One reviewer's decision so far."""

    approver_id: uuid.UUID
    approver_name: str  # shown with the request only (#172)
    decision: str  # approve or deny
    decided_at: datetime
    comment: str | None  # plain text, as the reviewer wrote it


class TimeOffDetail(TimeOffOut):
    """One request, with the shifts it affects and the decisions so far."""

    affected_shifts: list[AffectedShift]
    decisions: list[Decision]


class DecisionBody(Strict):
    """An optional comment with an approval or denial."""

    comment: Reason | None = None


class TimeOffList(BaseModel):
    items: list[TimeOffOut]
