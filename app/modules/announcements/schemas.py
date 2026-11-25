"""Request and response shapes for announcements (announcements.md, decision 0026).

Requests forbid unknown fields (extra="forbid"): a body that tries to set the author, the
company, the dates, or anything else not listed here is refused with 422, so those can
only be set by the rules in service.py (threat T2). Editing takes only the title and the
body, so the audience cannot change after posting.

The text is plain text: stored and returned exactly as typed, never HTML (threat T5).
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

# The text as people type it: surrounding spaces (and blank lines) removed, then 1 to 120
# characters for the title and 1 to 4,000 for the body (threat D2). Line breaks inside the
# body are kept.
Title = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Body = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=4000)]


class Strict(BaseModel):
    """A request body: only the listed fields, nothing else."""

    model_config = ConfigDict(extra="forbid")


class AnnouncementCreate(Strict):
    """POST /api/announcements. The audience is the company, one department (department_id),
    or one team (team_id); service.py checks that exactly the right ID is sent."""

    audience_type: Literal["company", "department", "team"]
    department_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    title: Title
    body: Body


class AnnouncementUpdate(Strict):
    """PATCH /api/announcements/{id}: only the fields sent are changed. The audience, the
    author, and the dates are not here, so they cannot be changed (422)."""

    title: Title | None = None
    body: Body | None = None


class AudienceOut(BaseModel):
    """Who an announcement is for, with the names the screens show."""

    type: str
    department_id: uuid.UUID | None
    department_name: str | None
    team_id: uuid.UUID | None
    team_name: str | None


class AuthorRef(BaseModel):
    id: uuid.UUID
    display_name: str


class AnnouncementManagedOut(BaseModel):
    """One announcement as the people who manage it see it, with its read counts."""

    id: uuid.UUID
    audience: AudienceOut
    title: str
    body: str
    author: AuthorRef
    posted_at: datetime  # UTC
    edited_at: datetime | None  # UTC; null until edited
    archived: bool
    # The people in the audience now who have read it, and how many people are in it.
    read_count: int
    audience_count: int


class AnnouncementManagedPage(BaseModel):
    """A page of the managed list; next_cursor fetches the next page, null on the last one."""

    items: list[AnnouncementManagedOut]
    next_cursor: str | None


def utc(moment: datetime) -> datetime:
    """A stored moment (UTC without a zone, as MySQL keeps it) as a UTC moment for JSON."""
    return moment.replace(tzinfo=UTC)
