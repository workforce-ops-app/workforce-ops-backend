"""Response shapes for the security page's endpoints (docs/features/detection.md).

Both endpoints only answer GET requests with query parameters, so there are no request
bodies here; the query parameters are checked in router.py.
"""

import uuid

from pydantic import AwareDatetime, BaseModel


class SecurityEventOut(BaseModel):
    """One security event, as the security page shows it.

    excerpt is attacker text, returned exactly as stored (at most 200 characters). The API
    answers in JSON, never HTML, and the page sets every value with textContent (DE7,
    threat T7), so the text is shown and never run.
    """

    id: uuid.UUID
    # detection.<type>, or detection.summary for the rate cap's summary rows.
    kind: str
    # Which pattern matched (for example "SQLI-02"); null for summary rows.
    pattern_id: str | None
    # Where the value was (for example "body.note"); null for summary rows.
    field: str | None
    method: str | None
    route: str | None
    # The person whose session sent the request, and their name for the page.
    user_id: uuid.UUID
    user_name: str
    client_address: str | None
    request_id: str | None
    excerpt: str | None
    # 1 for an event; for a summary row, how many events it stands for.
    count: int
    occurred_at: AwareDatetime


class SecurityEventPage(BaseModel):
    """A page of events, newest first; next_cursor is null after the last page."""

    items: list[SecurityEventOut]
    next_cursor: str | None


class KindCount(BaseModel):
    """How many events of one kind happened in the last 7 and the last 30 days."""

    kind: str
    last_7_days: int
    last_30_days: int


class SecuritySummary(BaseModel):
    """The counts at the top of the security page: every kind, zero included."""

    kinds: list[KindCount]
