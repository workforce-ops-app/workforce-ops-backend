"""The one writer of security events, with the rate cap (docs/features/detection.md).

The detection layer (DT4, #130) hands every event it finds to EventWriter.write(). The
writer decides which table each event goes to and how many are written as rows:

1. Which table (rule DE9): an event with a company (the request carried a valid session)
   goes to security_events and names the person; one without goes to
   platform_security_events, which has no company and no person.
2. The rate cap (rule DE6, threat D5): an attacker must not be able to fill the table or
   bury real events under noise. So the first 20 events per source (a session, or an
   address when nobody is signed in) in each minute are written as rows. After that they
   are only COUNTED in memory, and when the minute ends one "detection.summary" row is
   inserted with how many were held back. Rows are never updated: a count that keeps
   growing is kept here, not in the database.
3. Bounded memory: at most 10,000 sources are tracked at once. Events from further
   sources are only counted, in one shared overflow counter per minute, written the same
   way (as a platform summary row, since it mixes sources and companies).
4. When the application stops, close() writes every summary still held, so a clean stop
   loses nothing; a sudden crash loses at most one minute of held-back counts.

Rows are only inserted (app/modules/security/repository.py), never changed. The writer is
used from one worker thread; a lock still guards its counters, so close() can safely run
from another thread at shutdown.
"""

import threading
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import Engine

from app.db.base import utcnow
from app.modules.security import repository
from app.modules.security.models import DROPPED, SUMMARY

PER_MINUTE = 20  # rows per source per minute (DE6)
MAX_SOURCES = 10_000  # sources tracked at once (bounded memory)
RETENTION = timedelta(days=365)  # rows are kept for 1 year (data model, retention)


@dataclass(frozen=True)
class Event:
    """One event to record, as the detection layer describes it."""

    kind: str  # detection.<type>, for example "detection.xss"
    source: str  # who the rate cap counts it against: "session:<id>" or "address:<ip>"
    occurred_at: datetime  # UTC
    pattern_id: str | None = None
    field: str | None = None
    method: str | None = None
    route: str | None = None
    client_address: str | None = None
    request_id: str | None = None
    excerpt: str | None = None
    # Both set (a valid session's company and person) or neither (no session): DE9.
    company_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        # Half a session is a bug in the caller: never guess which table it belongs to.
        if (self.company_id is None) != (self.user_id is None):
            raise ValueError("an event has both a company and a person, or neither")


@dataclass
class _Counter:
    """What the rate cap knows about one source in one minute."""

    company_id: uuid.UUID | None
    user_id: uuid.UUID | None
    client_address: str | None
    written: int = 0  # rows written so far this minute (at most PER_MINUTE)
    held: int = 0  # events counted but not written (they go into the summary row)


def _minute(moment: datetime) -> datetime:
    """The start of the minute a moment falls in."""
    return moment.replace(second=0, microsecond=0)


class EventWriter:
    """Writes security events with the rate cap. One instance for the whole application."""

    def __init__(
        self,
        engine: Engine,
        *,
        per_minute: int = PER_MINUTE,
        max_sources: int = MAX_SOURCES,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._engine = engine
        self._per_minute = per_minute
        self._max_sources = max_sources
        self._clock = clock  # replaceable in tests, so minutes can end on demand
        self._lock = threading.Lock()
        # (source, minute) -> counter. Holds at most max_sources entries.
        self._counters: dict[tuple[str, datetime], _Counter] = {}
        # minute -> events from sources past max_sources.
        self._overflow: dict[datetime, int] = defaultdict(int)

    def write(self, events: Iterable[Event]) -> None:
        """Record events: write them as rows, or count them, by the rate cap (DE6)."""
        with self._lock:
            # 1. A minute that has ended gets its summary rows first, so its counters are
            #    freed before new sources are added (the 10,000 limit counts live ones).
            self._flush(before=_minute(self._clock()))

            # 2. Each event: written while its source is under the cap, otherwise counted.
            rows: list[Event] = []
            for event in events:
                key = (event.source, _minute(event.occurred_at))
                counter = self._counters.get(key)
                if counter is None:
                    if len(self._counters) >= self._max_sources:
                        # Too many sources at once: only count it, in the shared counter.
                        self._overflow[key[1]] += 1
                        continue
                    counter = _Counter(event.company_id, event.user_id, event.client_address)
                    self._counters[key] = counter
                if counter.written < self._per_minute:
                    counter.written += 1
                    rows.append(event)
                else:
                    counter.held += 1

            # 3. Insert the rows that passed the cap.
            self._insert(rows)

    def flush_due(self) -> None:
        """Write the summary rows of every minute that has ended. The detection worker
        calls this each time it takes a request copy, and at least every 10 seconds."""
        with self._lock:
            self._flush(before=_minute(self._clock()))

    def close(self) -> None:
        """Write every summary still held (the application is stopping)."""
        with self._lock:
            self._flush(before=datetime.max)

    def record_dropped(self, count: int) -> None:
        """Record that a full queue dropped `count` request copies (DE11). The detection
        layer counts the drops and calls this once a minute; nothing is written for 0."""
        if count <= 0:
            return
        now = self._clock()
        row = Event(kind=DROPPED, source="platform", occurred_at=now)
        repository.insert_platform_events(self._engine, [_row(row, count=count)])

    def _flush(self, *, before: datetime) -> None:
        """Turn every counter of a minute before `before` into a summary row (if anything
        was held back), and forget it. The caller holds the lock."""
        summaries: list[tuple[Event, int]] = []
        for (source, minute), counter in list(self._counters.items()):
            if minute >= before:
                continue
            del self._counters[(source, minute)]
            if counter.held:
                # One row for everything held back from this source in this minute,
                # dated at the end of the minute.
                summary = Event(
                    kind=SUMMARY,
                    source=source,
                    occurred_at=minute + timedelta(minutes=1),
                    client_address=counter.client_address,
                    company_id=counter.company_id,
                    user_id=counter.user_id,
                )
                summaries.append((summary, counter.held))
        for minute, held in list(self._overflow.items()):
            if minute >= before:
                continue
            del self._overflow[minute]
            # Mixed sources and companies, so a platform row without an address.
            overflow = Event(
                kind=SUMMARY, source="overflow", occurred_at=minute + timedelta(minutes=1)
            )
            summaries.append((overflow, held))
        self._insert([event for event, _ in summaries], counts=[held for _, held in summaries])

    def _insert(self, events: list[Event], counts: list[int] | None = None) -> None:
        """Insert events as rows: each company's in its own session, the rest as platform
        rows. `counts` gives each row's count (1 when not given)."""
        counts = counts or [1] * len(events)
        by_company: dict[uuid.UUID, list[dict]] = defaultdict(list)
        platform: list[dict] = []
        for event, count in zip(events, counts, strict=True):
            if event.company_id is not None:
                by_company[event.company_id].append(_row(event, count=count, with_user=True))
            else:
                platform.append(_row(event, count=count))
        for company_id, rows in by_company.items():
            repository.insert_company_events(self._engine, company_id, rows)
        if platform:
            repository.insert_platform_events(self._engine, platform)


def _row(event: Event, *, count: int, with_user: bool = False) -> dict:
    """The column values of one row. company_id is never included: the company filter
    fills it in from the session (tenancy layer 1)."""
    row: dict = {
        "kind": event.kind,
        "pattern_id": event.pattern_id,
        "field": event.field,
        "method": event.method,
        "route": event.route,
        "client_address": event.client_address,
        "request_id": event.request_id,
        "excerpt": event.excerpt,
        "count": count,
        "occurred_at": event.occurred_at,
    }
    if with_user:
        row["user_id"] = event.user_id
    return row


def remove_old_events(engine: Engine, now: datetime | None = None) -> tuple[int, int]:
    """Delete security events older than a year from both tables (data model, retention).

    Run nightly by scripts/remove_old_security_events.py. Returns (company rows, platform
    rows) removed.
    """
    return repository.remove_events_before(engine, (now or utcnow()) - RETENTION)
