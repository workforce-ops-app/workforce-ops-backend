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
   "Each minute" is the minute the writer HANDLES the events in, by its own clock, not the
   minute they happened in. Events reach the writer through a queue, so some arrive after
   their minute has ended; counted by their own minute, each late batch would find that
   minute's counter already written and forgotten, start a fresh one, and get 20 more
   rows. Counted by the minute they are handled in, a late event shares the current
   minute's cap, so no source gets more than 20 rows in any minute of writing.
3. Bounded memory: at most 10,000 sources are tracked at once. Events from further
   sources are only counted, in one shared overflow counter per minute, written the same
   way (as a platform summary row, since it mixes sources and companies).
4. When the application stops, close() writes every summary still held, so a clean stop
   loses nothing; a sudden crash loses at most one minute of held-back counts.
5. A failed insert (the database is unreachable, or refuses a row) loses no counts. The
   counters change only after their rows are saved: a summary's counter is forgotten only
   once its summary row is in the database (otherwise the next flush tries again), and an
   event uses up a place under the cap only once its row is saved. write() then raises
   EventWriteError naming exactly the events that were not saved, so the caller can hand
   those, and only those, to write() again without using up the cap twice.
   Each company's rows, and the platform's, are saved in a transaction of their own, so a
   failure in one leaves the others saved; that is why the error names events, not just
   "something failed".

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
from sqlalchemy.exc import SQLAlchemyError

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


class EventWriteError(Exception):
    """Some events could not be saved. `unsaved` lists them; none of them has used up a
    place under the rate cap, so they can be given to write() again as they are. The
    database's own error is attached as the cause (raise ... from)."""

    def __init__(self, unsaved: list["Event"]) -> None:
        super().__init__(f"{len(unsaved)} security event(s) could not be saved")
        self.unsaved = unsaved


# One row waiting to be inserted: the event, the row's count (1, or how many a summary
# stands for), and what to do once it is saved (update the counters; None: nothing).
_Pending = tuple["Event", int, Callable[[], None] | None]


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
        """Record events: write them as rows, or count them, by the rate cap (DE6).

        Raises EventWriteError if some rows could not be saved (see rule 5 at the top).
        """
        events = list(events)
        with self._lock:
            # 1. The minute this batch is handled in: the cap's minute for every event in
            #    it, however late an event arrives (see rule 2 at the top).
            minute = _minute(self._clock())

            # 2. A minute that has ended gets its summary rows first, so its counters are
            #    freed before new sources are added (the 10,000 limit counts live ones).
            #    If that fails, nothing of this batch has been counted yet, so all of it
            #    can be written again.
            try:
                self._flush(before=minute)
            except EventWriteError as error:
                raise EventWriteError(events) from error.__cause__

            # 3. Decide for each event: a row while its source is under the cap, otherwise
            #    only counted. A row's place under the cap is only RESERVED here (in
            #    `reserved`) and taken once the row is saved, in step 4.
            pending: list[_Pending] = []
            reserved: dict[tuple[str, datetime], int] = defaultdict(int)
            for event in events:
                key = (event.source, minute)
                counter = self._counters.get(key)
                if counter is None:
                    if len(self._counters) >= self._max_sources:
                        # Too many sources at once: only count it, in the shared counter.
                        self._overflow[minute] += 1
                        continue
                    counter = _Counter(event.company_id, event.user_id, event.client_address)
                    self._counters[key] = counter
                if counter.written + reserved[key] < self._per_minute:
                    reserved[key] += 1
                    pending.append((event, 1, self._taker(counter)))
                else:
                    counter.held += 1

            # 4. Insert the rows; each saved row takes its place under the cap.
            self._save(pending)

    @staticmethod
    def _taker(counter: _Counter) -> Callable[[], None]:
        """What to do once a row counted against `counter` is saved: take its place."""

        def take() -> None:
            counter.written += 1

        return take

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
        # No counter depends on it, so a failure is simply raised (EventWriteError) and
        # the detection layer keeps its drop count to try again next minute.
        self._save([(row, count, None)])

    def _flush(self, *, before: datetime) -> None:
        """Turn every counter of a minute before `before` into a summary row (if anything
        was held back), and forget it once that row is saved. The caller holds the lock.

        Raises EventWriteError if a summary row could not be saved; its counter is kept,
        so the next flush tries again with the same count.
        """
        pending: list[_Pending] = []
        # 1. Each source's counter for a minute that has ended.
        for key, counter in list(self._counters.items()):
            source, minute = key
            if minute >= before:
                continue
            if not counter.held:
                # Nothing held back: no summary to write, so it is forgotten at once.
                del self._counters[key]
                continue
            # One row for everything held back from this source in this minute, dated at
            # the end of the minute. Its counter is forgotten only once the row is saved.
            summary = Event(
                kind=SUMMARY,
                source=source,
                occurred_at=minute + timedelta(minutes=1),
                client_address=counter.client_address,
                company_id=counter.company_id,
                user_id=counter.user_id,
            )
            pending.append((summary, counter.held, self._forgetter(self._counters, key)))
        # 2. The shared overflow counter of each minute that has ended.
        for minute, held in list(self._overflow.items()):
            if minute >= before:
                continue
            # Mixed sources and companies, so a platform row without an address.
            overflow = Event(
                kind=SUMMARY, source="overflow", occurred_at=minute + timedelta(minutes=1)
            )
            pending.append((overflow, held, self._forgetter(self._overflow, minute)))
        # 3. Insert them; each saved summary forgets its counter.
        self._save(pending)

    @staticmethod
    def _forgetter(counters: dict, key: object) -> Callable[[], None]:
        """What to do once a summary row is saved: forget the counter it was made from."""

        def forget() -> None:
            del counters[key]

        return forget

    def _save(self, pending: list[_Pending]) -> None:
        """Insert rows, one transaction per company plus one for the platform rows, and run
        each saved row's follow-up (updating the counters). Rows of a transaction that
        fails are not saved and their follow-ups do not run, so the counters still say
        what is really in the database. Raises EventWriteError naming those rows' events
        after trying every transaction.
        """
        # 1. Group the rows by where they go: a company's table (by company), or the
        #    platform table (None).
        groups: dict[uuid.UUID | None, list[_Pending]] = defaultdict(list)
        for item in pending:
            groups[item[0].company_id].append(item)

        # 2. Each group in its own transaction. A failure is remembered, not raised yet,
        #    so the other groups are still saved.
        unsaved: list[Event] = []
        first_error: SQLAlchemyError | None = None
        for company_id, items in groups.items():
            try:
                if company_id is None:
                    rows = [_row(event, count=count) for event, count, _ in items]
                    repository.insert_platform_events(self._engine, rows)
                else:
                    rows = [_row(event, count=count, with_user=True) for event, count, _ in items]
                    repository.insert_company_events(self._engine, company_id, rows)
            except SQLAlchemyError as error:
                unsaved.extend(event for event, _, _ in items)
                first_error = first_error or error
                continue
            # 3. Saved: now the counters may change.
            for _, _, after_saved in items:
                if after_saved is not None:
                    after_saved()

        # 4. Report what was not saved, with the database's error as the cause.
        if first_error is not None:
            raise EventWriteError(unsaved) from first_error


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
