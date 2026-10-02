"""Cross-company access: a user of company A can neither see nor change company B's data.

Threats I1 and T3 (threat model), tenancy layer 1 (tenancy.md). Each test works the way
an attacker would: as company A, it asks for company B's data in every way the ORM
allows, and checks that B's data stays invisible and unchanged.

When endpoints exist, each one also gets a test here that calls it as a user of the
other demo company and expects 404.
"""

from collections.abc import Iterator

import pytest
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session, aliased

from app.db.base import Base
from app.tenancy.context import set_company
from app.tenancy.filter import CompanyOwned, TenancyError, UnsafeQueryError, WrongCompanyError
from tests.tenant_data import TenantNote, TwoCompanies, make_two_companies


@pytest.fixture
def data() -> Iterator[TwoCompanies]:
    """Two companies with one note each, in a fresh database for every test."""
    two = make_two_companies()
    yield two
    two.engine.dispose()


def b_note_title(data: TwoCompanies) -> str:
    """Company B's note title, read through a session working for company B."""
    with data.session_for(data.company_b) as session:
        note = session.get(TenantNote, data.note_b)
        assert note is not None
        return note.title


def test_listing_shows_only_own_company(data: TwoCompanies) -> None:
    # As company A, list every note: only A's note comes back.
    with data.session_for(data.company_a) as session:
        titles = session.scalars(select(TenantNote.title)).all()
    assert titles == ["A's note"]


def test_other_companys_record_by_id_looks_like_it_does_not_exist(data: TwoCompanies) -> None:
    # As company A, ask for B's note by its exact ID, the way /api/notes/{id} would.
    # It comes back as None, exactly like an ID that does not exist (the API answers 404).
    with data.session_for(data.company_a) as session:
        assert session.get(TenantNote, data.note_b) is None
        found = session.scalars(select(TenantNote).where(TenantNote.id == data.note_b)).all()
    assert found == []


def test_counting_does_not_reveal_other_companys_rows(data: TwoCompanies) -> None:
    # Even a count must not leak how many rows other companies have.
    with data.session_for(data.company_a) as session:
        count = session.scalar(select(func.count(TenantNote.id)))
    assert count == 1


def test_aliases_and_joins_are_filtered_too(data: TwoCompanies) -> None:
    # A query that uses the table twice (an alias, as joins do) is filtered on both sides.
    other = aliased(TenantNote)
    with data.session_for(data.company_a) as session:
        rows = session.execute(
            select(TenantNote.title, other.title).join(other, other.id != TenantNote.id)
        ).all()
    # A has only one note, so there is no second row to pair it with, from any company.
    assert rows == []


def test_bulk_update_cannot_change_other_companys_rows(data: TwoCompanies) -> None:
    # As company A, try to rename every note, then specifically B's note.
    with data.session_for(data.company_a) as session:
        session.execute(update(TenantNote).values(title="changed"))
        session.execute(update(TenantNote).where(TenantNote.id == data.note_b).values(title="x"))
        session.commit()
    # B's note is untouched.
    assert b_note_title(data) == "B's note"


def test_bulk_delete_cannot_remove_other_companys_rows(data: TwoCompanies) -> None:
    # As company A, try to delete every note.
    with data.session_for(data.company_a) as session:
        session.execute(delete(TenantNote))
        session.commit()
    # B's note still exists.
    assert b_note_title(data) == "B's note"


def test_cannot_create_a_row_for_another_company(data: TwoCompanies) -> None:
    # As company A, try to create a note that claims to belong to company B, as a request
    # body with a forged company_id would. Nothing is saved.
    with data.session_for(data.company_a) as session:
        session.add(TenantNote(title="planted", company_id=data.company_b))
        with pytest.raises(WrongCompanyError):
            session.commit()
    with data.session_for(data.company_b) as session:
        assert session.scalars(select(TenantNote.title)).all() == ["B's note"]


def test_cannot_move_own_row_into_another_company(data: TwoCompanies) -> None:
    # As company A, load A's own note and try to hand it to company B.
    with data.session_for(data.company_a) as session:
        note = session.get(TenantNote, data.note_a)
        assert note is not None
        note.company_id = data.company_b
        with pytest.raises(WrongCompanyError):
            session.commit()


def test_bulk_update_cannot_move_rows_into_another_company(data: TwoCompanies) -> None:
    # As company A, set company_id on A's own rows to B: that would hand A's data to B.
    with data.session_for(data.company_a) as session, pytest.raises(WrongCompanyError):
        session.execute(update(TenantNote).values(company_id=data.company_b))
    # The same with the value passed separately to session.execute.
    with data.session_for(data.company_a) as session, pytest.raises(WrongCompanyError):
        session.execute(update(TenantNote), {"company_id": data.company_b})
    # B still has only its own note.
    with data.session_for(data.company_b) as session:
        assert session.scalars(select(TenantNote.title)).all() == ["B's note"]


def test_bulk_update_by_primary_key_cannot_reach_other_companys_rows(data: TwoCompanies) -> None:
    # A list of rows keyed by ID is sent without the company condition, so it is refused.
    with data.session_for(data.company_a) as session, pytest.raises(UnsafeQueryError):
        session.execute(update(TenantNote), [{"id": data.note_b, "title": "hijacked"}])
    assert b_note_title(data) == "B's note"


@pytest.mark.parametrize("company", ["b", "none"])
def test_bulk_insert_cannot_plant_rows(data: TwoCompanies, company: str) -> None:
    # A bulk insert skips the save check, so company data must be added with session.add().
    # Tried as company A claiming company B, and with no company set at all.
    session = data.session_for(data.company_a) if company == "b" else Session(data.engine)
    with session, pytest.raises(TenancyError):
        session.execute(insert(TenantNote).values(title="planted", company_id=data.company_b))
    with data.session_for(data.company_b) as session:
        assert session.scalars(select(TenantNote.title)).all() == ["B's note"]


@pytest.mark.parametrize("kind", ["select", "update", "delete", "insert"])
def test_raw_table_statements_on_company_data_are_refused(data: TwoCompanies, kind: str) -> None:
    # The table itself (TenantNote.__table__) instead of the model is not filtered, so any
    # such statement on company data is refused, with a company set or without one.
    table = TenantNote.__table__
    statement = {
        "select": select(table.c.title),
        "update": update(table).values(title="raw"),
        "delete": delete(table),
        "insert": insert(table).values(id=data.note_a.bytes, title="raw"),
    }[kind]
    for session in (data.session_for(data.company_a), Session(data.engine)):
        with session, pytest.raises(UnsafeQueryError):
            session.execute(statement)
    assert b_note_title(data) == "B's note"


def test_every_model_with_company_id_is_covered_by_the_filter() -> None:
    # Layer 3 of tenancy.md: a new table that has a company_id column but forgets
    # CompanyOwned would not be filtered. This test finds any such model.
    unprotected = [
        mapper.class_.__name__
        for mapper in Base.registry.mappers
        if "company_id" in mapper.columns and not issubclass(mapper.class_, CompanyOwned)
    ]
    assert unprotected == [], f"add CompanyOwned to: {', '.join(unprotected)}"


def test_a_session_cannot_switch_companies(data: TwoCompanies) -> None:
    # A session that works for A cannot be turned into a session for B halfway, which
    # would mix A's already loaded rows with B's.
    with data.session_for(data.company_a) as session, pytest.raises(RuntimeError):
        set_company(session, data.company_b)


def test_session_is_not_shared_between_companies(data: TwoCompanies) -> None:
    # Two sessions for two companies, side by side, each see only their own row.
    with data.session_for(data.company_a) as a, data.session_for(data.company_b) as b:
        assert a.scalars(select(TenantNote.title)).all() == ["A's note"]
        assert b.scalars(select(TenantNote.title)).all() == ["B's note"]
