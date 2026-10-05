"""The demo seed script (scripts/seed_demo.py): two alike companies, same result every run.

Runs on SQLite in memory with the org tables, the way the script runs on MySQL.
"""

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.orm import Session

from app.auth import passwords
from app.auth.passwords import PasswordRejected, verify_password
from app.core.config import get_settings
from app.db.base import Base
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.tenancy.context import set_company
from scripts import seed_demo

ORG_TABLES = [model.__table__ for model in (Company, Department, Team, User, TeamMember)]

DEMO_PASSWORD = "a calm river bends at dusk"


@pytest.fixture(autouse=True)
def quick_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cheap Argon2 settings for these tests, so hashing 16 accounts takes no time. The
    real settings are tested in tests/unit/test_passwords.py."""
    monkeypatch.setattr(
        passwords, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )


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
        "Northwind Cafe: created; no DEMO_PASSWORD, so no one can sign in",
        "Summit Outfitters: created; no DEMO_PASSWORD, so no one can sign in",
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
    seed_demo.seed(engine)
    lines = seed_demo.seed(engine)

    assert lines == [
        "Northwind Cafe: already there; no DEMO_PASSWORD, so no one can sign in",
        "Summit Outfitters: already there; no DEMO_PASSWORD, so no one can sign in",
    ]
    assert len(company_ids(engine)) == 2
    for company_id in company_ids(engine).values():
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
        "Northwind Cafe: created; demo password set for 8 accounts",
        "Summit Outfitters: created; demo password set for 8 accounts",
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

    assert lines[0] == "Northwind Cafe: already there; demo password set for 8 accounts"
    # A third run changes nothing: everyone already has a password.
    assert seed_demo.seed(engine, DEMO_PASSWORD)[0].endswith("demo password set for 0 accounts")
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
