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
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine, delete, event, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.tenancy.context import set_company
from app.tenancy.filter import UnsafeQueryError, WrongCompanyError

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
    # The model lowercases every email before saving.
    with org.session_for(org.company_a) as session:
        user = User(email="Cara@Example.COM", display_name="Cara", department_id=org.department_a)
        session.add(user)
        session.commit()
        assert user.email == "cara@example.com"


def test_the_same_address_in_another_case_is_still_one_account(org: Org) -> None:
    # "ANA@example.com" becomes "ana@example.com", which company A already uses.
    with org.session_for(org.company_b) as session:
        session.add(User(email="ANA@example.com", display_name="Copy", department_id=uuid.uuid4()))
        with pytest.raises(IntegrityError):
            session.commit()


def test_the_database_refuses_a_mixed_case_email_written_around_the_model(org: Org) -> None:
    # The backstop: a write that skips the model (only migrations may, so the connection is
    # trusted here) still cannot store a mixed-case address. The migration check repeats
    # this on MySQL, whose default comparison would otherwise let it through.
    from sqlalchemy import insert

    from app.tenancy.filter import trust_connection

    with org.engine.connect() as connection, pytest.raises(IntegrityError):
        trust_connection(connection)
        connection.execute(
            insert(User.__table__).values(
                id=uuid.uuid4(),
                company_id=org.company_a,
                department_id=org.department_a,
                email="Mixed@Example.com",
                display_name="Mixed",
                failed_sign_ins=0,
                created_at=datetime.now(UTC).replace(tzinfo=None),
                updated_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )


def test_links_within_one_company_work(org: Org) -> None:
    # The same links inside company A go through: the keys only stop crossing over.
    with org.session_for(org.company_a) as session:
        session.add(TeamMember(team_id=org.team_a, user_id=org.user_a))
        session.commit()
        assert session.get(TeamMember, (org.team_a, org.user_a)) is not None


# --- The companies table itself ---------------------------------------------------------
# companies is not company-owned (each row is a company), so the plain company filter
# would not cover it. These tests make sure a company still cannot read or change another
# company through it.


def test_a_company_sees_only_itself_in_the_companies_table(org: Org) -> None:
    with org.session_for(org.company_a) as session:
        # Listing companies shows only company A's own row.
        assert session.scalars(select(Company.name)).all() == ["Northwind Cafe"]
        # Company B by its exact ID looks like it does not exist.
        assert session.get(Company, org.company_b) is None


def test_a_company_cannot_rename_another_company(org: Org) -> None:
    # Company B, loaded by platform code and detached, then attached to company A's
    # session and renamed: refused.
    with Session(org.engine) as platform:
        other = platform.get(Company, org.company_b)
        assert other is not None
        platform.expunge(other)
    with org.session_for(org.company_a) as session:
        session.add(other)
        other.name = "Renamed by A"
        with pytest.raises(WrongCompanyError):
            session.commit()
    with Session(org.engine) as platform:
        assert platform.get(Company, org.company_b).name == "Summit Outfitters"  # type: ignore[union-attr]


@pytest.mark.parametrize("action", ["create", "delete"])
def test_a_company_cannot_create_or_delete_companies(org: Org, action: str) -> None:
    # Creating and deleting companies is platform work, even for a company's own row.
    with org.session_for(org.company_a) as session:
        if action == "create":
            session.add(Company(name="Shell company", timezone="UTC"))
        else:
            own = session.get(Company, org.company_a)
            assert own is not None
            session.delete(own)
        with pytest.raises(UnsafeQueryError):
            session.commit()


def test_a_company_cannot_bulk_delete_companies(org: Org) -> None:
    # A bulk delete skips the save check above, so the query hook refuses it itself. Without
    # that, delete(Company) would remove company A's own row (the filter limits it to that
    # row, but deleting companies is platform work).
    with org.session_for(org.company_a) as session, pytest.raises(UnsafeQueryError):
        session.execute(delete(Company))
    with Session(org.engine) as platform:
        assert len(platform.scalars(select(Company)).all()) == 2


@pytest.mark.parametrize("form", ["values", "parameters"])
def test_a_company_cannot_change_its_company_id_in_bulk(org: Org, form: str) -> None:
    # A company's id is the value the filter uses to tell companies apart. Changing it with
    # a bulk update would re-key the company (and could take over an ID chosen by the
    # attacker), so it is refused, whether the new value is in .values() or passed separately.
    new_id = uuid.uuid4()
    with org.session_for(org.company_a) as session, pytest.raises(WrongCompanyError):
        if form == "values":
            session.execute(update(Company).values(id=new_id))
        else:
            session.execute(update(Company), {"id": new_id})
    with Session(org.engine) as platform:
        assert platform.get(Company, org.company_a) is not None
        assert platform.get(Company, new_id) is None


def test_a_company_can_still_rename_itself_in_bulk(org: Org) -> None:
    # The refusals above are narrow: a bulk update of other columns of its own row works,
    # and the filter still keeps it to that one row.
    with org.session_for(org.company_a) as session:
        session.execute(update(Company).values(name="Northwind Cafe and Bakery"))
        session.commit()
    with Session(org.engine) as platform:
        assert platform.get(Company, org.company_a).name == "Northwind Cafe and Bakery"  # type: ignore[union-attr]
        assert platform.get(Company, org.company_b).name == "Summit Outfitters"  # type: ignore[union-attr]


def test_the_raw_companies_table_is_refused(org: Org) -> None:
    # Reading Company.__table__ directly would skip the "own company only" condition.
    with org.session_for(org.company_a) as session, pytest.raises(UnsafeQueryError):
        session.execute(select(Company.__table__.c.name))


def test_a_company_can_change_its_own_row(org: Org) -> None:
    with org.session_for(org.company_a) as session:
        own = session.get(Company, org.company_a)
        assert own is not None
        own.name = "Northwind Cafe and Bakery"
        session.commit()
    with org.session_for(org.company_a) as session:
        assert session.scalars(select(Company.name)).all() == ["Northwind Cafe and Bakery"]


def test_platform_code_without_a_company_manages_companies(org: Org) -> None:
    # The seed script works in a session with no company: it sees and creates companies.
    with Session(org.engine) as platform:
        platform.add(Company(name="Third Company", timezone="UTC"))
        platform.commit()
        assert len(platform.scalars(select(Company)).all()) == 3
