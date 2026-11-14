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


# --- People ----------------------------------------------------------------------------

# An email as people type it: surrounding spaces removed, at most 254 characters (the
# column), with one "@" that has text on both sides and a dot in the part after it. That
# is all the checking it gets: the only real test of an address is whether the person can
# be reached at it, and there is no email delivery yet. It is stored in lowercase
# (models.User).
Email = Annotated[
    str,
    StringConstraints(strip_whitespace=True, max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
]


class UserOut(BaseModel):
    """A person, as the people allowed to see them see them (GET /api/users)."""

    id: uuid.UUID
    display_name: str
    email: str
    # The home department: every person has exactly one.
    department_id: uuid.UUID
    # The teams they are on (archived teams included: the list is history too).
    team_ids: list[uuid.UUID]
    # "invited" (no password yet), "active", or "deactivated" (organization.md, People).
    status: str
    # Whether wrong passwords have locked the account for now.
    locked: bool


class UserPage(BaseModel):
    """A page of people; next_cursor is null after the last page."""

    items: list[UserOut]
    next_cursor: str | None


class UserCreate(Strict):
    """POST /api/users. The account has no password until its setup link is used.

    manager_id is who the new person reports to. It decides who may act on the account
    afterwards (only someone above a person may), so it is required unless the creator is
    an Owner, who is above everyone anyway (organization.md, People).
    """

    display_name: Name
    email: Email
    department_id: uuid.UUID
    manager_id: uuid.UUID | None = None


class UserUpdate(Strict):
    """PATCH /api/users/{id}: only the fields sent are changed."""

    display_name: Name | None = None
    email: Email | None = None
    department_id: uuid.UUID | None = None


class DeactivatedOut(UserOut):
    """The answer to a deactivation: the person, plus the upcoming shifts that are still
    assigned to them, for the administrator to reassign (organization.md, People)."""

    upcoming_shift_ids: list[uuid.UUID]
