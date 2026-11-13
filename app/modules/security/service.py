"""The rules for reading security events (docs/features/detection.md, "Who can use it").

Both functions check security.view with authorize() first, before anything is read: it is
a company permission, so only a company-wide assignment grants it (Owner and
Administrator by default). Managers and employees get 403, and never see security events,
including their own.

Everything is read in the request's session, which works for the signed-in person's
company, so the company filter limits every query to that company: another company's
events are never loaded, whatever the filters say. Only security_events is read;
platform_security_events (people not signed in) has no endpoint.

Nothing here changes or removes an event, and reading is not audited, like other reads.
"""

import uuid
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.authz.check import authorize
from app.db.base import utcnow
from app.modules.org.models import Company, User
from app.modules.org.repository import decode_cursor, encode_cursor
from app.modules.security import repository
from app.modules.security.models import COMPANY_KINDS, SecurityEvent

# The two windows of the summary (the counts at the top of the security page).
WINDOWS = {"last_7_days": timedelta(days=7), "last_30_days": timedelta(days=30)}


class Invalid(HTTPException):
    """422: the request itself is not acceptable."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=422, detail=detail)


def _midnight(zone: ZoneInfo, day: date) -> datetime:
    """The UTC moment a day begins in a time zone (naive UTC, as the database stores it)."""
    return datetime.combine(day, time(0), zone).astimezone(UTC).replace(tzinfo=None)


def list_events(
    db: Session,
    user: User,
    *,
    kind: str | None,
    user_id: uuid.UUID | None,
    first: date | None,
    last: date | None,
    cursor: str | None,
    limit: int,
) -> tuple[list[SecurityEvent], str | None]:
    """One page of the company's events, newest first, and the next page's bookmark.

    first and last are days in the company's time zone, both included (as the page shows
    dates); either may be left out.
    """
    # 1. Permission first: someone without security.view learns nothing, not even
    #    whether the filters were valid.
    authorize(db, user, "security.view")

    # 2. The filters. An unknown kind would only ever match nothing, but saying so helps
    #    the page, and it keeps typed text out of the query's meaning.
    if kind is not None and kind not in COMPANY_KINDS:
        raise Invalid("Unknown kind of event.")
    if first is not None and last is not None and first > last:
        raise Invalid("The first day must not be after the last day.")
    company = db.get(Company, user.company_id)
    if company is None:  # the session's own company: always there
        raise RuntimeError("the signed-in person's company is missing")
    zone = ZoneInfo(company.timezone)
    start = _midnight(zone, first) if first is not None else None
    end = _midnight(zone, last + timedelta(days=1)) if last is not None else None

    # 3. The bookmark is the last event's ID. It is looked up in this company, so a
    #    bookmark naming another company's event is simply not valid.
    after = None
    if cursor is not None:
        event_id = decode_cursor(cursor)
        found = repository.event(db, event_id) if event_id is not None else None
        if found is None:
            raise Invalid("This cursor is not valid.")
        after = found.occurred_at, found.id

    # 4. One page, plus one more row to tell whether another page exists.
    rows = repository.list_events(
        db, kind=kind, user_id=user_id, start=start, end=end, after=after, limit=limit
    )
    page, more = rows[:limit], len(rows) > limit
    return page, (encode_cursor(page[-1].id) if more else None)


def names_of(db: Session, events: list[SecurityEvent]) -> dict[uuid.UUID, str]:
    """The names of the people in a page of events (one query)."""
    return repository.names(db, {event.user_id for event in events})


def summary(db: Session, user: User) -> dict[str, dict[str, int]]:
    """For every kind, how many events happened in each window, counted back from now.

    Every kind is in the answer, zero included, so the page always shows the same rows.
    """
    authorize(db, user, "security.view")
    now = utcnow()
    counts = {name: repository.counts_since(db, now - span) for name, span in WINDOWS.items()}
    return {kind: {name: counts[name].get(kind, 0) for name in WINDOWS} for kind in COMPANY_KINDS}
