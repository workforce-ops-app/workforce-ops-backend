"""The demo seed script (scripts/seed_demo.py): two alike companies, same result every run.

Runs on SQLite in memory with the org tables, the way the script runs on MySQL.
"""

import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import Base
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.tenancy.context import set_company
from scripts import seed_demo

ORG_TABLES = [model.__table__ for model in (Company, Department, Team, User, TeamMember)]


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

    assert lines == ["Northwind Cafe: created", "Summit Outfitters: created"]
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
        "Northwind Cafe: already there, left unchanged",
        "Summit Outfitters: already there, left unchanged",
    ]
    assert len(company_ids(engine)) == 2
    for company_id in company_ids(engine).values():
        assert count(engine, company_id, User) == 8


def test_emails_use_the_reserved_domains_and_have_no_password_yet(engine: Engine) -> None:
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
    # Passwords arrive with S1; until then nobody can sign in.
    assert all(u.password_hash is None for u in [*northwind, *summit])


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
