"""The database itself refuses links between companies (tenancy layer 2, threats I1 and T3).

The company filter (layer 1) fills in the session's company on every new row, but it does
not look at what a row links to. Here company B tries to attach its rows to company A's
department, team, or people. The company-aware keys, (company_id, <x>_id) pointing at
(company_id, id), make the database refuse every such link, so even a bug that got past
layer 1 could not connect two companies' data.

SQLite in memory, with foreign keys switched on (SQLite leaves them off by default); the
same keys exist in MySQL through migration 0002, which the migration check compares with
these models.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.tenancy.context import set_company

ORG_TABLES = [model.__table__ for model in (Company, Department, Team, User, TeamMember)]


@dataclass
class Org:
    """Two companies, each with one department, team, and person."""

    engine: Engine
    company_a: uuid.UUID
    company_b: uuid.UUID
    department_a: uuid.UUID
    team_a: uuid.UUID
    user_a: uuid.UUID
    user_b: uuid.UUID

    def session_for(self, company_id: uuid.UUID) -> Session:
        session = Session(self.engine)
        set_company(session, company_id)
        return session


def _enforce_foreign_keys(dbapi_connection: Any, connection_record: Any) -> None:
    """Switch SQLite's foreign key checks on for every new connection."""
    dbapi_connection.execute("PRAGMA foreign_keys = ON")


@pytest.fixture
def org() -> Iterator[Org]:
    # An empty database with the org tables, foreign keys enforced.
    engine = create_engine("sqlite://")
    event.listen(engine, "connect", _enforce_foreign_keys)
    Base.metadata.create_all(engine, tables=ORG_TABLES)

    # The two companies. companies is not company-owned, so no company is needed here.
    with Session(engine) as session:
        company_a = Company(name="Northwind Cafe", timezone="America/Chicago")
        company_b = Company(name="Summit Outfitters", timezone="America/Denver")
        session.add_all([company_a, company_b])
        session.commit()
        ids_a, ids_b = company_a.id, company_b.id

    # Company A: a department, a team in it, and a person whose home it is.
    with Session(engine) as session:
        set_company(session, ids_a)
        department_a = Department(name="Kitchen")
        session.add(department_a)
        session.flush()
        team_a = Team(name="Weekend Crew", department_id=department_a.id)
        user_a = User(email="ana@example.com", display_name="Ana", department_id=department_a.id)
        session.add_all([team_a, user_a])
        session.commit()
        org_ids_a = (department_a.id, team_a.id, user_a.id)

    # Company B: its own department and person (same department name on purpose: names
    # only need to be unique within a company).
    with Session(engine) as session:
        set_company(session, ids_b)
        department_b = Department(name="Kitchen")
        session.add(department_b)
        session.flush()
        user_b = User(email="ben@example.org", display_name="Ben", department_id=department_b.id)
        session.add(user_b)
        session.commit()
        user_b_id = user_b.id

    yield Org(engine, ids_a, ids_b, *org_ids_a, user_b_id)
    engine.dispose()


def test_a_team_cannot_sit_in_another_companys_department(org: Org) -> None:
    # As company B, create a team inside company A's department.
    with org.session_for(org.company_b) as session:
        session.add(Team(name="Planted", department_id=org.department_a))
        with pytest.raises(IntegrityError):
            session.commit()


def test_a_person_cannot_get_another_companys_home_department(org: Org) -> None:
    # As company B, create a person whose home department is company A's.
    with org.session_for(org.company_b) as session:
        session.add(
            User(email="eve@example.org", display_name="Eve", department_id=org.department_a)
        )
        with pytest.raises(IntegrityError):
            session.commit()


@pytest.mark.parametrize("acting_as", ["a", "b"])
def test_team_membership_cannot_cross_companies(org: Org, acting_as: str) -> None:
    # Put company B's person on company A's team, acting as either company: whichever
    # company_id the row gets, one of the two links points into the other company.
    company = org.company_a if acting_as == "a" else org.company_b
    with org.session_for(company) as session:
        session.add(TeamMember(team_id=org.team_a, user_id=org.user_b))
        with pytest.raises(IntegrityError):
            session.commit()


def test_an_email_belongs_to_one_account_on_the_whole_platform(org: Org) -> None:
    # Company B cannot create an account with an address company A already uses (and the
    # error does not say where it is used; that is the endpoint's job, Z3).
    with org.session_for(org.company_b) as session:
        session.add(User(email="ana@example.com", display_name="Copy", department_id=uuid.uuid4()))
        with pytest.raises(IntegrityError):
            session.commit()


def test_emails_are_stored_in_lowercase(org: Org) -> None:
    # "Ana@Example.com" and "ana@example.com" must not become two accounts.
    with org.session_for(org.company_a) as session:
        session.add(
            User(email="Ana@Example.com", display_name="Ana", department_id=org.department_a)
        )
        with pytest.raises(IntegrityError):
            session.commit()


def test_links_within_one_company_work(org: Org) -> None:
    # The same links inside company A go through: the keys only stop crossing over.
    with org.session_for(org.company_a) as session:
        session.add(TeamMember(team_id=org.team_a, user_id=org.user_a))
        session.commit()
        assert session.get(TeamMember, (org.team_a, org.user_a)) is not None
