"""Request and response shapes for organization endpoints (docs/features/organization.md).

Requests forbid unknown fields (extra="forbid"): a body that tries to set company_id,
archived_at, or anything else not listed here is refused with 422, so those can only
change through the rules in service.py (threat T2).
"""

import uuid
from typing import Annotated
from zoneinfo import available_timezones

from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints

# A name as people type it: surrounding spaces removed, 1 to 120 characters (the column).
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]


def _known_zone(zone: str | None) -> str | None:
    """A time zone must be a real IANA name such as "America/Chicago" (decision 0021):
    shifts are converted with it, so a typo would put every shift at the wrong time."""
    if zone is not None and zone not in available_timezones():
        raise ValueError("Unknown time zone. Use a name such as America/Chicago.")
    return zone


Zone = Annotated[str | None, AfterValidator(_known_zone)]


class Strict(BaseModel):
    """A request body: only the listed fields, nothing else."""

    model_config = ConfigDict(extra="forbid")


# --- Departments -----------------------------------------------------------------------


class DepartmentOut(BaseModel):
    """The department fields available to any signed-in person (the list)."""

    id: uuid.UUID
    name: str


class DepartmentPage(BaseModel):
    """A page of departments; next_cursor is null after the last page."""

    items: list[DepartmentOut]
    next_cursor: str | None


class DepartmentDetail(BaseModel):
    """A department as the people who manage it see it (the answer to a change)."""

    id: uuid.UUID
    name: str
    timezone: str | None  # null: the company's time zone applies
    archived: bool


class DepartmentCreate(Strict):
    """POST /api/departments."""

    name: Name
    timezone: Zone = None


class DepartmentUpdate(Strict):
    """PATCH /api/departments/{id}: only the fields sent are changed. Sending timezone as
    null goes back to the company's time zone."""

    name: Name | None = None
    timezone: Zone = None


# --- Teams -----------------------------------------------------------------------------


class TeamOut(BaseModel):
    """A team, with the department it belongs to."""

    id: uuid.UUID
    department_id: uuid.UUID
    name: str
    archived: bool


class TeamPage(BaseModel):
    """A page of teams; next_cursor is null after the last page."""

    items: list[TeamOut]
    next_cursor: str | None


class TeamCreate(Strict):
    """POST /api/teams. A team belongs to one department for good."""

    department_id: uuid.UUID
    name: Name


class TeamUpdate(Strict):
    """PATCH /api/teams/{id}: only the name changes (the department never does)."""

    name: Name


class MemberAdd(Strict):
    """POST /api/teams/{id}/members."""

    user_id: uuid.UUID


class MemberOut(BaseModel):
    """Someone on a team."""

    team_id: uuid.UUID
    user_id: uuid.UUID
