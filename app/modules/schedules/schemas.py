"""Request and response shapes for shifts (schedules.md, decision 0026).

The response is exactly the shape agreed with the frontend (#61, frontend #28): names are
included so the week can be shown without separate requests for departments and people.

Requests forbid unknown fields (extra="forbid"): a body that tries to set company_id,
status, or anything else not listed here is refused with 422, so those can only change
through the rules in service.py (threat T2).
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class Strict(BaseModel):
    """A request body: only the listed fields, nothing else."""

    model_config = ConfigDict(extra="forbid")


class ShiftCreate(Strict):
    """POST /api/shifts. Times are moments with an offset (e.g. "2026-10-05T14:00:00Z"):
    the interface converts the workplace's wall-clock time before sending."""

    department_id: uuid.UUID
    employee_id: uuid.UUID | None = None  # none: an open shift
    starts_at: AwareDatetime
    ends_at: AwareDatetime
    details: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=5000)
    event_name: str | None = Field(default=None, max_length=120)
    event_description: str | None = Field(default=None, max_length=5000)


class ShiftUpdate(Strict):
    """PATCH /api/shifts/{id}: only the fields sent are changed. The department, the person,
    and the status change only through their own actions (assign, cancel)."""

    starts_at: AwareDatetime | None = None
    ends_at: AwareDatetime | None = None
    details: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=5000)
    event_name: str | None = Field(default=None, max_length=120)
    event_description: str | None = Field(default=None, max_length=5000)


class ShiftAssign(Strict):
    """POST /api/shifts/{id}/assign: a person, or null to make the shift open."""

    employee_id: uuid.UUID | None


# --- Several shifts at once (POST /api/shifts/batch) ------------------------------------
#
# One body per action. The "action" field picks which one applies (a discriminated union),
# so a create body cannot carry shift_ids and a cancel body cannot carry times: anything
# that does not belong to the chosen action is refused with 422, like any unknown field.

MAX_BATCH = 100  # shifts per request: a whole department's month fits, a runaway loop does not


class ShiftTimes(Strict):
    """One occurrence: the start and end on one day, as moments with an offset."""

    starts_at: AwareDatetime
    ends_at: AwareDatetime


class BatchCreate(Strict):
    """The same shift on several days. The interface turns each chosen day's wall-clock
    times into moments (as for one shift), so daylight-saving days come out right."""

    action: Literal["create"]
    department_id: uuid.UUID
    employee_id: uuid.UUID | None = None  # none: open shifts
    times: list[ShiftTimes] = Field(min_length=1, max_length=MAX_BATCH)
    details: str | None = Field(default=None, max_length=200)
    notes: str | None = Field(default=None, max_length=5000)
    event_name: str | None = Field(default=None, max_length=120)
    event_description: str | None = Field(default=None, max_length=5000)
    confirm_count: int | None = None  # required at 10 or more shifts (service.py)


class BatchCancel(Strict):
    """Cancel the selected shifts."""

    action: Literal["cancel"]
    shift_ids: list[uuid.UUID] = Field(min_length=1, max_length=MAX_BATCH)
    confirm_count: int | None = None


class BatchAssign(Strict):
    """Give the selected shifts to one person, or make them all open (employee_id null).
    employee_id has no default: leaving it out is a mistake, not a request to open."""

    action: Literal["assign"]
    shift_ids: list[uuid.UUID] = Field(min_length=1, max_length=MAX_BATCH)
    employee_id: uuid.UUID | None
    confirm_count: int | None = None


ShiftBatch = Annotated[BatchCreate | BatchCancel | BatchAssign, Field(discriminator="action")]


class DepartmentRef(BaseModel):
    id: uuid.UUID
    name: str


class EmployeeRef(BaseModel):
    id: uuid.UUID
    display_name: str


class ShiftOut(BaseModel):
    """One shift as the screens get it."""

    id: uuid.UUID
    department: DepartmentRef
    employee: EmployeeRef | None
    starts_at: datetime  # UTC
    ends_at: datetime  # UTC
    timezone: str
    status: str
    details: str | None
    notes: str | None
    event_name: str | None
    event_description: str | None


class ShiftPage(BaseModel):
    """A page of shifts; next_cursor fetches the next page, null on the last one."""

    items: list[ShiftOut]
    next_cursor: str | None


class ShiftBatchOut(BaseModel):
    """The shifts a batch created or changed, in the order they were sent."""

    action: str
    count: int
    items: list[ShiftOut]


def utc(moment: datetime) -> datetime:
    """A stored moment (UTC without a zone, as MySQL keeps it) as a UTC moment for JSON."""
    return moment.replace(tzinfo=UTC)
