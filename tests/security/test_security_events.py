"""Security events: the two tables and their one writer (docs/features/detection.md, DT2).

From the attacker's side, what must hold:
- DE9: an event lands in a company only through a valid session; without one it lands in
  the platform table, which has no company or person columns at all. A person of another
  company can never be named (the database refuses it).
- DE6 (threat D5): one source cannot fill the table or bury real events. After 20 events
  in a minute it gets exactly ONE summary row with the right count, and rows are never
  updated, only inserted.
- Memory stays bounded: past the source limit, events are only counted.
- Retention: rows older than a year are removed from both tables, in every company.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.registry import import_all_models
from app.modules.org.models import Company, Department, User
from app.modules.security.models import DROPPED, SUMMARY, PlatformSecurityEvent, SecurityEvent
from app.modules.security.writer import Event, EventWriter, remove_old_events
from app.tenancy.context import set_company

NOON = datetime(2026, 11, 11, 12, 0, 0)


def _enforce_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    """SQLite checks foreign keys only when asked; MySQL always does."""
    dbapi_connection.execute("PRAGMA foreign_keys = ON")


@dataclass
class Clock:
    """A clock the test moves by hand, so a minute ends exactly when the test says."""

    now: datetime = NOON

    def __call__(self) -> datetime:
        return self.now


@dataclass
class Setup:
    engine: Engine
    clock: Clock
    companies: dict[str, uuid.UUID] = field(default_factory=dict)
    people: dict[str, uuid.UUID] = field(default_factory=dict)

    def writer(self, **limits: int) -> EventWriter:
        return EventWriter(self.engine, clock=self.clock, **limits)  # type: ignore[arg-type]

    def company_rows(self, company: str) -> list[SecurityEvent]:
        """Every row the company's own session can see, oldest first."""
        with Session(self.engine) as db:
            set_company(db, self.companies[company])
            return list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at)))

    def platform_rows(self) -> list[PlatformSecurityEvent]:
        with Session(self.engine) as db:
            return list(db.scalars(select(PlatformSecurityEvent)))


@pytest.fixture
def setup() -> Iterator[Setup]:
    """Two companies, Northwind (A) and Summit (B), with one person each."""
    import_all_models()
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    event.listen(engine, "connect", _enforce_foreign_keys)
    Base.metadata.create_all(engine)
    result = Setup(engine=engine, clock=Clock())
    for name, person in (("a", "ana"), ("b", "bea")):
        with Session(engine) as platform:
            company = Company(name=f"Company {name}", timezone="UTC")
            platform.add(company)
            platform.commit()
            result.companies[name] = company.id
        with Session(engine) as db:
            set_company(db, result.companies[name])
            department = Department(name="Kitchen")
            db.add(department)
            db.flush()
            user = User(
                email=f"{person}@{name}.example", display_name=person, department_id=department.id
            )
            db.add(user)
            db.commit()
            result.people[person] = user.id
    yield result
    engine.dispose()


def xss(
    setup: Setup, *, company: str | None = "a", source: str = "session:1", at: datetime = NOON
) -> Event:
    """An XSS event from a person of `company`, or from nobody signed in (company=None)."""
    person = {"a": "ana", "b": "bea"}.get(company or "")
    return Event(
        kind="detection.xss",
        source=source,
        occurred_at=at,
        pattern_id="XSS-01",
        field="body.note",
        method="POST",
        route="/api/shifts",
        client_address="198.51.100.7",
        request_id="req-1",
        excerpt="<script>alert(1)</script>",
        company_id=setup.companies[company] if company else None,
        user_id=setup.people[person] if person else None,
    )


# --- DE9: which table ------------------------------------------------------------------


def test_an_event_with_a_session_goes_to_that_company_only(setup: Setup) -> None:
    setup.writer().write([xss(setup, company="a")])
    [row] = setup.company_rows("a")
    assert row.company_id == setup.companies["a"]
    assert row.user_id == setup.people["ana"]
    assert row.excerpt == "<script>alert(1)</script>"  # stored as sent, plain text
    assert setup.company_rows("b") == []  # the other company sees nothing
    assert setup.platform_rows() == []


def test_an_event_without_a_session_goes_to_the_platform_table_only(setup: Setup) -> None:
    setup.writer().write([xss(setup, company=None, source="address:198.51.100.7")])
    [row] = setup.platform_rows()
    assert row.kind == "detection.xss"
    assert setup.company_rows("a") == [] and setup.company_rows("b") == []


def test_the_platform_table_cannot_name_a_company_or_a_person() -> None:
    import_all_models()
    columns = set(PlatformSecurityEvent.__table__.columns.keys())
    assert "company_id" not in columns and "user_id" not in columns


@pytest.mark.parametrize("half", ["company only", "person only"])
def test_half_a_session_is_refused(setup: Setup, half: str) -> None:
    with pytest.raises(ValueError):
        Event(
            kind="detection.xss",
            source="session:1",
            occurred_at=NOON,
            company_id=setup.companies["a"] if half == "company only" else None,
            user_id=setup.people["ana"] if half == "person only" else None,
        )


def test_a_person_of_another_company_cannot_be_named(setup: Setup) -> None:
    # Company A's event naming Summit's Bea: the (company_id, user_id) key refuses it.
    forged = Event(
        kind="detection.xss",
        source="session:1",
        occurred_at=NOON,
        company_id=setup.companies["a"],
        user_id=setup.people["bea"],
    )
    with pytest.raises(IntegrityError):
        setup.writer().write([forged])
    assert setup.company_rows("a") == [] and setup.company_rows("b") == []


# --- DE6: the rate cap -----------------------------------------------------------------


def test_after_20_events_a_source_gets_exactly_one_summary_row(setup: Setup) -> None:
    writer = setup.writer()
    # 25 events from one session within one minute.
    writer.write([xss(setup, at=NOON + timedelta(seconds=n)) for n in range(25)])
    rows = setup.company_rows("a")
    assert len(rows) == 20 and all(row.kind == "detection.xss" for row in rows)

    # The minute ends: one summary row for the 5 held back, dated at the minute's end.
    setup.clock.now = NOON + timedelta(minutes=1, seconds=5)
    writer.flush_due()
    rows = setup.company_rows("a")
    summaries = [row for row in rows if row.kind == SUMMARY]
    assert len(rows) == 21 and len(summaries) == 1
    assert summaries[0].count == 5
    assert summaries[0].occurred_at == NOON + timedelta(minutes=1)
    assert summaries[0].user_id == setup.people["ana"]

    # Nothing more to write: a second flush adds no row.
    writer.flush_due()
    assert len(setup.company_rows("a")) == 21


def test_each_source_has_its_own_cap(setup: Setup) -> None:
    writer = setup.writer()
    writer.write([xss(setup, source="session:1") for _ in range(20)])
    writer.write([xss(setup, source="session:2") for _ in range(20)])
    assert len(setup.company_rows("a")) == 40  # neither session held back the other


def test_a_new_minute_starts_a_new_cap(setup: Setup) -> None:
    writer = setup.writer()
    writer.write([xss(setup) for _ in range(20)])
    setup.clock.now = NOON + timedelta(minutes=1)
    writer.write([xss(setup, at=setup.clock.now) for _ in range(20)])
    assert len(setup.company_rows("a")) == 40


def test_rows_are_only_ever_inserted(setup: Setup) -> None:
    """DE6: a count that keeps growing is kept in memory, never by updating a row."""
    statements: list[str] = []
    event.listen(setup.engine, "before_cursor_execute", lambda *a: statements.append(a[2]))
    writer = setup.writer()
    writer.write([xss(setup, at=NOON + timedelta(seconds=n)) for n in range(40)])
    writer.write([xss(setup, company=None, source="address:x") for _ in range(30)])
    setup.clock.now = NOON + timedelta(minutes=2)
    writer.flush_due()
    writer.record_dropped(3)
    writer.close()
    writes = [sql.lstrip().split()[0].upper() for sql in statements if "security_events" in sql]
    assert "INSERT" in writes
    assert set(writes) <= {"INSERT", "SELECT"}, writes


def test_past_the_source_limit_events_are_only_counted(setup: Setup) -> None:
    """Bounded memory: with room for 2 sources, a third one's events are counted in the
    shared overflow counter and written as one platform summary row."""
    writer = setup.writer(max_sources=2)
    writer.write([xss(setup, source="session:1"), xss(setup, source="session:2")])
    writer.write([xss(setup, source=f"session:{n}") for n in range(3, 10)])
    assert len(setup.company_rows("a")) == 2
    setup.clock.now = NOON + timedelta(minutes=1)
    writer.flush_due()
    [overflow] = setup.platform_rows()
    assert overflow.kind == SUMMARY and overflow.count == 7
    assert overflow.client_address is None  # it mixes many sources


def test_stopping_writes_every_summary_still_held(setup: Setup) -> None:
    writer = setup.writer()
    writer.write([xss(setup) for _ in range(23)])
    writer.close()  # the minute has not ended, but the application is stopping
    [summary] = [row for row in setup.company_rows("a") if row.kind == SUMMARY]
    assert summary.count == 3


def test_dropped_request_copies_are_recorded_as_one_platform_row(setup: Setup) -> None:
    writer = setup.writer()
    writer.record_dropped(0)
    assert setup.platform_rows() == []  # nothing dropped, nothing written
    writer.record_dropped(12)
    [row] = setup.platform_rows()
    assert row.kind == DROPPED and row.count == 12


# --- Retention -------------------------------------------------------------------------


def test_rows_older_than_a_year_are_removed_from_both_tables_in_every_company(setup: Setup) -> None:
    old, recent = NOON - timedelta(days=400), NOON - timedelta(days=30)
    writer = setup.writer()
    for company in ("a", "b"):
        writer.write([xss(setup, company=company, source=f"{company}-old", at=old)])
        writer.write([xss(setup, company=company, source=f"{company}-new", at=recent)])
    writer.write([xss(setup, company=None, source="anon-old", at=old)])
    writer.write([xss(setup, company=None, source="anon-new", at=recent)])

    assert remove_old_events(setup.engine, now=NOON) == (2, 1)
    for company in ("a", "b"):
        assert [row.occurred_at for row in setup.company_rows(company)] == [recent]
    assert [row.occurred_at for row in setup.platform_rows()] == [recent]


def test_a_companys_session_counts_only_its_own_events(setup: Setup) -> None:
    writer = setup.writer()
    writer.write([xss(setup, company="a", source="s-a") for _ in range(3)])
    writer.write([xss(setup, company="b", source="s-b") for _ in range(5)])
    with Session(setup.engine) as db:
        set_company(db, setup.companies["a"])
        assert db.scalar(select(func.count(SecurityEvent.id))) == 3
