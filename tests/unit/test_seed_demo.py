"""The demo seed script (scripts/seed_demo.py): two alike companies with two weeks of
shifts, same result every run.

Runs on SQLite in memory with the org and shift tables, the way the script runs on MySQL.
"""

import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from argon2 import PasswordHasher
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.orm import Session

from app.audit.models import AuditChainHead, AuditEvent
from app.auth import passwords
from app.auth.passwords import PasswordRejected, verify_password
from app.authz.models import Permission, Role, RoleAssignment, RolePermission
from app.core.config import get_settings
from app.db.base import Base
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.modules.schedules.models import Shift
from app.tenancy.context import set_company
from scripts import seed_demo
from tests.audit_data import TEST_KEY, use_key

# The tables the seed fills: the company's structure and people, its roles, its shifts, and
# the audit log their creation is written to.
ORG_TABLES = [
    model.__table__
    for model in (
        Company,
        Department,
        Team,
        User,
        TeamMember,
        Permission,
        Role,
        RolePermission,
        RoleAssignment,
        AuditChainHead,
        AuditEvent,
        Shift,
    )
]

# Two weeks of the weekly pattern.
SHIFTS_PER_COMPANY = 2 * len(seed_demo.WEEK_PATTERN)
# Parts of the summary line the script prints for each company.
ADDED = f"{SHIFTS_PER_COMPANY} shifts added"
NO_PASSWORD = "no DEMO_PASSWORD, so no one can sign in"
WAITING = "shifts wait for passwords"

DEMO_PASSWORD = "a calm river bends at dusk"


@pytest.fixture(autouse=True)
def quick_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cheap Argon2 settings for these tests, so hashing 16 accounts takes no time. The
    real settings are tested in tests/unit/test_passwords.py."""
    monkeypatch.setattr(
        passwords, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )


@pytest.fixture(autouse=True)
def audit_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """A test signing key: creating roles writes audit entries. Settings are read again
    after each test, without this test's environment."""
    use_key(monkeypatch, tmp_path, TEST_KEY)
    yield
    get_settings.cache_clear()


@pytest.fixture
def engine() -> Iterator[Engine]:
    """An empty in-memory database with the org tables."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=ORG_TABLES)
    yield engine
    engine.dispose()


def company_ids(engine: Engine) -> dict[str, uuid.UUID]:
    """Every company's ID by name, read by platform code (no company on the session)."""
    with Session(engine) as platform:
        return {c.name: c.id for c in platform.scalars(select(Company))}


def count(engine: Engine, company_id: uuid.UUID, model: type) -> int:
    """How many rows of a company-owned table belong to one company.

    Counts a model column (company_id), so the company filter applies; a count that only
    names the model in select_from would be refused by the filter as unsafe.
    """
    with Session(engine) as session:
        set_company(session, company_id)
        return session.scalar(select(func.count(model.company_id))) or 0  # type: ignore[attr-defined]


def test_it_creates_two_alike_companies(engine: Engine) -> None:
    lines = seed_demo.seed(engine)

    assert lines == [
        f"Northwind Cafe: created; {NO_PASSWORD}; {WAITING}",
        f"Summit Outfitters: created; {NO_PASSWORD}; {WAITING}",
    ]
    ids = company_ids(engine)
    assert set(ids) == {"Northwind Cafe", "Summit Outfitters"}

    # Built alike on purpose: the same numbers of everything in both companies.
    for company_id in ids.values():
        assert count(engine, company_id, Department) == 3
        assert count(engine, company_id, Team) == 4
        assert count(engine, company_id, User) == 8
        assert count(engine, company_id, TeamMember) == 8

    # And the same department names, so a leak between the two is obvious.
    names = []
    for company_id in ids.values():
        with Session(engine) as session:
            set_company(session, company_id)
            names.append(sorted(session.scalars(select(Department.name))))
    assert names[0] == names[1] == ["Front of House", "Kitchen", "Office"]


def test_running_it_twice_changes_nothing(engine: Engine) -> None:
    seed_demo.seed(engine, DEMO_PASSWORD)
    lines = seed_demo.seed(engine, DEMO_PASSWORD)

    assert lines == [
        "Northwind Cafe: already there; demo password set for 0 accounts; 0 shifts added",
        "Summit Outfitters: already there; demo password set for 0 accounts; 0 shifts added",
    ]
    assert len(company_ids(engine)) == 2
    for company_id in company_ids(engine).values():
        assert count(engine, company_id, User) == 8
        assert count(engine, company_id, Shift) == SHIFTS_PER_COMPANY


def test_a_failure_part_way_leaves_nothing_behind_and_a_rerun_completes(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Fail while creating the people: after the company row and the departments exist,
    # before the company is finished.
    def broken_email(person: seed_demo.Person, domain: str) -> str:
        raise RuntimeError("simulated failure part way through")

    real_email_for = seed_demo.email_for
    monkeypatch.setattr(seed_demo, "email_for", broken_email)
    with pytest.raises(RuntimeError, match="simulated"):
        seed_demo.seed(engine)

    # Nothing was saved, not even the company row: otherwise the next run would find the
    # name, report "already there", and never finish the company.
    assert company_ids(engine) == {}

    # Once the cause is gone, the next run creates both companies completely.
    # (Only this one patch is undone: the signing key from the fixture stays set.)
    monkeypatch.setattr(seed_demo, "email_for", real_email_for)
    lines = seed_demo.seed(engine)
    assert [line.split(";")[0] for line in lines] == [
        "Northwind Cafe: created",
        "Summit Outfitters: created",
    ]
    for company_id in company_ids(engine).values():
        assert count(engine, company_id, Department) == 3
        assert count(engine, company_id, User) == 8


def test_emails_use_the_reserved_domains(engine: Engine) -> None:
    seed_demo.seed(engine)
    ids = company_ids(engine)

    with Session(engine) as session:
        set_company(session, ids["Northwind Cafe"])
        northwind = session.scalars(select(User)).all()
    with Session(engine) as session:
        set_company(session, ids["Summit Outfitters"])
        summit = session.scalars(select(User)).all()

    assert all(u.email.endswith("@example.com") for u in northwind)
    assert all(u.email.endswith("@example.org") for u in summit)
    assert "ana.diaz@example.com" in {u.email for u in northwind}
    # Without DEMO_PASSWORD nobody has a password, so nobody can sign in.
    assert all(u.password_hash is None for u in [*northwind, *summit])


def all_users(engine: Engine) -> list[User]:
    """Every demo account, read company by company."""
    users: list[User] = []
    for company_id in company_ids(engine).values():
        with Session(engine) as session:
            set_company(session, company_id)
            users.extend(session.scalars(select(User)))
    return users


def test_a_demo_password_is_hashed_for_every_account(engine: Engine) -> None:
    lines = seed_demo.seed(engine, DEMO_PASSWORD)

    assert lines == [
        f"Northwind Cafe: created; demo password set for 8 accounts; {ADDED}",
        f"Summit Outfitters: created; demo password set for 8 accounts; {ADDED}",
    ]
    users = all_users(engine)
    # Stored as hashes that verify, each with its own salt, never as the password itself.
    assert all(u.password_hash and verify_password(u.password_hash, DEMO_PASSWORD) for u in users)
    assert len({u.password_hash for u in users}) == len(users)
    assert all(u.password_changed_at is not None for u in users)


def test_a_rerun_only_fills_in_missing_passwords(engine: Engine) -> None:
    # Seeded before passwords existed, then again with DEMO_PASSWORD: the accounts get it.
    seed_demo.seed(engine)
    lines = seed_demo.seed(engine, DEMO_PASSWORD)
    hashes = {u.id: u.password_hash for u in all_users(engine)}

    assert lines[0] == f"Northwind Cafe: already there; demo password set for 8 accounts; {ADDED}"
    # A third run changes nothing: everyone already has a password, and the shifts exist.
    assert seed_demo.seed(engine, DEMO_PASSWORD)[0] == (
        "Northwind Cafe: already there; demo password set for 0 accounts; 0 shifts added"
    )
    assert {u.id: u.password_hash for u in all_users(engine)} == hashes


@pytest.mark.parametrize("weak", ["too short", "000000000000000", "Northwind Cafe all day long"])
def test_a_weak_demo_password_changes_nothing(engine: Engine, weak: str) -> None:
    # Checked against the rules for every demo person before anything is created.
    with pytest.raises(PasswordRejected):
        seed_demo.seed(engine, weak)
    assert company_ids(engine) == {}


def test_the_people_cover_the_cases_later_slices_need() -> None:
    for plan in seed_demo.DEMO_COMPANIES:
        roles = [person.role for person in plan.people]
        teams = [person.teams for person in plan.people]

        # Every starting role (assigned in Z1).
        assert set(roles) == {"owner", "administrator", "manager", "employee"}
        # Someone on two teams, and someone on none.
        assert any(len(t) == 2 for t in teams)
        assert any(len(t) == 0 for t in teams)


def test_main_refuses_to_run_in_production(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    get_settings.cache_clear()
    try:
        assert seed_demo.main() == 1
    finally:
        get_settings.cache_clear()
    assert "refusing" in capsys.readouterr().out


def test_main_seeds_the_configured_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Run in an empty folder, so a developer's own .env cannot change the settings.
    monkeypatch.chdir(tmp_path)
    # A database file with the tables in place, as migrations would leave it (forward
    # slashes: SQLite URLs do not accept Windows backslashes).
    url = f"sqlite:///{(tmp_path / 'demo.db').as_posix()}"
    setup = create_engine(url)
    Base.metadata.create_all(setup, tables=ORG_TABLES)
    setup.dispose()

    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.delenv("DATABASE_PASSWORD", raising=False)
    get_settings.cache_clear()
    try:
        assert seed_demo.main() == 0
    finally:
        get_settings.cache_clear()
    assert "Northwind Cafe: created" in capsys.readouterr().out


def test_main_refuses_a_weak_demo_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("DEMO_PASSWORD", "too short")
    get_settings.cache_clear()
    try:
        assert seed_demo.main() == 1
    finally:
        get_settings.cache_clear()
    assert "refusing DEMO_PASSWORD" in capsys.readouterr().out


# Shifts (SD1)


def shifts_of(engine: Engine, company_id: uuid.UUID) -> list[Shift]:
    """A company's shifts, in time order, read in a session working for that company."""
    with Session(engine) as session:
        set_company(session, company_id)
        return list(session.scalars(select(Shift).order_by(Shift.starts_at)))


def test_each_company_gets_two_alike_weeks_of_shifts(engine: Engine) -> None:
    seed_demo.seed(engine, DEMO_PASSWORD)

    summaries = []
    for _name, company_id in sorted(company_ids(engine).items()):
        shifts = shifts_of(engine, company_id)
        with Session(engine) as session:
            set_company(session, company_id)
            departments = {d.id: d.name for d in session.scalars(select(Department))}
        summaries.append(
            (
                len(shifts),
                sum(s.status == "open" for s in shifts),
                sorted({departments[s.department_id] for s in shifts}),
            )
        )
        # This week and the next: the first shift is on this week's Monday, in the
        # company's own time zone (stored moments are UTC without a zone).
        zone = ZoneInfo(shifts[0].timezone)
        first_local = shifts[0].starts_at.replace(tzinfo=UTC).astimezone(zone)
        assert first_local.date() == seed_demo.week_start(shifts[0].timezone)

    # Built alike: the same number of shifts and open shifts, in the same two departments.
    assert summaries[0] == summaries[1]
    assert summaries[0] == (SHIFTS_PER_COMPANY, 6, ["Front of House", "Kitchen"])


def test_shifts_start_at_local_times_in_each_company_zone(engine: Engine) -> None:
    # A fixed Monday in October (daylight-saving time in both zones).
    monday = date(2026, 10, 5)
    for plan in seed_demo.DEMO_COMPANIES:
        seed_demo.seed_company(engine, plan)
        seed_demo.set_demo_passwords(engine, plan, DEMO_PASSWORD)
        seed_demo.seed_shifts(engine, plan, monday)
    ids = company_ids(engine)

    northwind = shifts_of(engine, ids["Northwind Cafe"])[0]
    summit = shifts_of(engine, ids["Summit Outfitters"])[0]
    # 7:00 in Chicago (UTC-5) and 7:00 in Denver (UTC-6), stored in UTC.
    assert northwind.starts_at == datetime(2026, 10, 5, 12, 0)
    assert northwind.timezone == "America/Chicago"
    assert summit.starts_at == datetime(2026, 10, 5, 13, 0)
    assert summit.timezone == "America/Denver"


def test_local_times_follow_daylight_saving() -> None:
    # Clocks in Chicago fall back on November 1, 2026: 7:00 is 12:00 UTC before, 13:00 after.
    assert seed_demo.local_to_utc(date(2026, 10, 30), "07:00", "America/Chicago") == datetime(
        2026, 10, 30, 12, 0
    )
    assert seed_demo.local_to_utc(date(2026, 11, 2), "07:00", "America/Chicago") == datetime(
        2026, 11, 2, 13, 0
    )


def test_week_start_is_the_monday_of_the_week() -> None:
    assert seed_demo.week_start("America/Chicago", date(2026, 10, 7)) == date(2026, 10, 5)
    assert seed_demo.week_start("America/Chicago", date(2026, 10, 5)) == date(2026, 10, 5)
    assert seed_demo.week_start("America/Chicago", date(2026, 10, 11)) == date(2026, 10, 5)


def test_demo_shifts_follow_the_rules_the_api_enforces(engine: Engine) -> None:
    seed_demo.seed(engine, DEMO_PASSWORD)

    for company_id in company_ids(engine).values():
        shifts = shifts_of(engine, company_id)
        with Session(engine) as session:
            set_company(session, company_id)
            users = {u.id: u for u in session.scalars(select(User))}
            homes = {u.id: u.department_id for u in users.values()}
            team_departments: dict[uuid.UUID, set[uuid.UUID]] = {}
            for member, department_id in session.execute(
                select(TeamMember.user_id, Team.department_id).join(
                    Team, Team.id == TeamMember.team_id
                )
            ):
                team_departments.setdefault(member, set()).add(department_id)

        for shift in shifts:
            # At most 12 hours, ending after it starts.
            assert timedelta(0) < shift.ends_at - shift.starts_at <= timedelta(hours=12)
            # Open shifts have nobody; scheduled ones have someone.
            assert (shift.status == "open") == (shift.employee_id is None)
            # Only someone whose home department it is, or who is on a team in it, who has
            # set up their account and is not deactivated.
            if shift.employee_id is not None:
                worker = users[shift.employee_id]
                assert worker.password_hash is not None
                assert worker.deactivated_at is None
                allowed = {homes[shift.employee_id], *team_departments.get(shift.employee_id, ())}
                assert shift.department_id in allowed

        # Nobody is booked on two shifts at the same time.
        by_person: dict[uuid.UUID, list[Shift]] = {}
        for shift in shifts:
            if shift.employee_id is not None:
                by_person.setdefault(shift.employee_id, []).append(shift)
        for own in by_person.values():
            for earlier, later in zip(own, own[1:], strict=False):
                assert earlier.ends_at <= later.starts_at


def test_notes_and_events_appear_in_the_first_week_only(engine: Engine) -> None:
    seed_demo.seed(engine, DEMO_PASSWORD)
    shifts = shifts_of(engine, company_ids(engine)["Northwind Cafe"])
    first_week_end = min(s.starts_at for s in shifts) + timedelta(days=7)

    with_text = [s for s in shifts if s.notes or s.event_name]
    assert len(with_text) == 2
    assert all(s.starts_at < first_week_end for s in with_text)


def test_every_demo_shift_is_in_the_audit_log(engine: Engine) -> None:
    seed_demo.seed(engine, DEMO_PASSWORD)

    for company_id in company_ids(engine).values():
        with Session(engine) as session:
            set_company(session, company_id)
            created = session.scalars(
                select(AuditEvent).where(
                    AuditEvent.action == "shift.created", AuditEvent.company_id == company_id
                )
            ).all()
        shift_ids = {s.id for s in shifts_of(engine, company_id)}
        # Each company's entries are in that company's own chain, one per shift.
        assert {event.target_id for event in created} == shift_ids
        # Added by the system, not by a person.
        assert all(event.actor_type == "system" for event in created)


def test_a_company_seeded_before_shifts_gets_them_on_the_next_run(engine: Engine) -> None:
    # As if seeded by the script before SD1: companies and people, no shifts.
    for plan in seed_demo.DEMO_COMPANIES:
        seed_demo.seed_company(engine, plan)

    lines = seed_demo.seed(engine, DEMO_PASSWORD)

    assert lines[0] == f"Northwind Cafe: already there; demo password set for 8 accounts; {ADDED}"
    for company_id in company_ids(engine).values():
        assert count(engine, company_id, Shift) == SHIFTS_PER_COMPANY


def test_shifts_wait_until_everyone_on_them_has_a_password(engine: Engine) -> None:
    # The API never gives a shift to someone who has not set up their account (an invited
    # person, without a password), so the seed does not either.
    seed_demo.seed(engine)
    for company_id in company_ids(engine).values():
        assert count(engine, company_id, Shift) == 0

    # Once DEMO_PASSWORD is set, the next run adds them.
    lines = seed_demo.seed(engine, DEMO_PASSWORD)
    assert all(line.endswith(ADDED) for line in lines)


def test_a_deactivated_worker_holds_back_the_shifts(engine: Engine) -> None:
    plan = seed_demo.DEMO_COMPANIES[0]
    seed_demo.seed_company(engine, plan)
    seed_demo.set_demo_passwords(engine, plan, DEMO_PASSWORD)
    with Session(engine) as session:
        set_company(session, company_ids(engine)[plan.name])
        worker = plan.people[seed_demo.KITCHEN_A].name
        user = session.scalars(select(User).where(User.display_name == worker)).one()
        user.deactivated_at = datetime(2026, 1, 1)
        session.commit()

    assert seed_demo.seed_shifts(engine, plan) is None
