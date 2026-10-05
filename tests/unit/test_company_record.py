"""How the companies table behaves for the application's own code (CompanyRecord).

The attacks (another company reading or changing a company) are in
tests/security/test_org_company_links.py.
"""

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from app.db.base import Base
from app.modules.org.models import Company, Department, User
from app.tenancy.context import set_company
from app.tenancy.filter import UnsafeQueryError, WrongCompanyError


@pytest.fixture
def engine() -> Iterator[Engine]:
    """An in-memory database with two companies; returns the engine."""
    engine = create_engine("sqlite://")
    tables = [Company.__table__, Department.__table__, User.__table__]
    Base.metadata.create_all(engine, tables=tables)
    with Session(engine) as session:
        session.add_all([Company(name="A", timezone="UTC"), Company(name="B", timezone="UTC")])
        session.commit()
    yield engine
    engine.dispose()


def company_id(engine: Engine, name: str) -> uuid.UUID:
    """A company's ID, looked up by platform code (no company on the session)."""
    with Session(engine) as session:
        return session.scalars(select(Company.id).where(Company.name == name)).one()


def test_platform_code_sees_every_company(engine: Engine) -> None:
    # A session with no company is platform code (the seed script): no filter applies.
    with Session(engine) as session:
        assert sorted(session.scalars(select(Company.name)).all()) == ["A", "B"]


def test_a_company_session_sees_only_its_own_company(engine: Engine) -> None:
    with Session(engine) as session:
        set_company(session, company_id(engine, "A"))
        assert session.scalars(select(Company.name)).all() == ["A"]


def test_a_company_session_cannot_create_a_company(engine: Engine) -> None:
    with Session(engine) as session:
        set_company(session, company_id(engine, "A"))
        session.add(Company(name="C", timezone="UTC"))
        with pytest.raises(UnsafeQueryError, match="platform"):
            session.commit()


def test_emails_are_lowercased_when_set() -> None:
    # The model stores every address in lowercase, whatever case it was typed in.
    assert User(email="Ana@Example.COM").email == "ana@example.com"


def test_a_company_session_can_rename_its_own_company(engine: Engine) -> None:
    with Session(engine) as session:
        set_company(session, company_id(engine, "A"))
        own = session.scalars(select(Company)).one()
        own.name = "A renamed"
        session.commit()
    assert company_id(engine, "A renamed")


def test_a_company_session_cannot_change_another_company(engine: Engine) -> None:
    # Company B, loaded by platform code and handed to company A's session by mistake.
    with Session(engine) as platform:
        other = platform.scalars(select(Company).where(Company.name == "B")).one()
        platform.expunge(other)
    with Session(engine) as session:
        set_company(session, company_id(engine, "A"))
        session.add(other)
        other.name = "B renamed by A"
        with pytest.raises(WrongCompanyError):
            session.commit()
