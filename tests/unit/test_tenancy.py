"""How the company filter behaves for the application's own code (app/tenancy/).

The attacker's view (reaching another company's data) is in tests/security/.
"""

from collections.abc import Iterator

import pytest
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.tenancy.context import get_company, set_company
from app.tenancy.filter import (
    MissingCompanyError,
    UnsafeQueryError,
    WrongCompanyError,
    trust_connection,
)
from tests.tenant_data import TenantNote, TwoCompanies, make_two_companies


@pytest.fixture
def data() -> Iterator[TwoCompanies]:
    """Two companies with one note each, in a fresh database for every test."""
    two = make_two_companies()
    yield two
    two.engine.dispose()


def test_a_new_session_has_no_company(data: TwoCompanies) -> None:
    with Session(data.engine) as session:
        assert get_company(session) is None


def test_setting_the_same_company_twice_is_allowed(data: TwoCompanies) -> None:
    # Setting it again to the same value is harmless (no switch happens).
    with data.session_for(data.company_a) as session:
        set_company(session, data.company_a)
        assert get_company(session) == data.company_a


def test_switching_a_session_to_another_company_is_refused(data: TwoCompanies) -> None:
    # A programming mistake that reuses one session for two companies fails at once.
    with data.session_for(data.company_a) as session, pytest.raises(RuntimeError):
        set_company(session, data.company_b)


def test_saving_a_row_with_another_companys_id_is_refused(data: TwoCompanies) -> None:
    # Code that copies a company_id from somewhere else (for example a request body)
    # cannot save it: only the session's own company is accepted.
    with data.session_for(data.company_a) as session:
        session.add(TenantNote(title="wrong", company_id=data.company_b))
        with pytest.raises(WrongCompanyError):
            session.commit()


def test_query_without_a_company_is_refused(data: TwoCompanies) -> None:
    # Forgetting to set the company must fail loudly, not return every company's rows.
    with Session(data.engine) as session, pytest.raises(MissingCompanyError):
        session.scalars(select(TenantNote)).all()


def test_save_without_a_company_is_refused(data: TwoCompanies) -> None:
    with Session(data.engine) as session:
        session.add(TenantNote(title="no company"))
        with pytest.raises(MissingCompanyError):
            session.commit()


def test_new_row_gets_the_sessions_company(data: TwoCompanies) -> None:
    # Feature code never sets company_id itself; the filter fills it in.
    with data.session_for(data.company_a) as session:
        note = TenantNote(title="second")
        session.add(note)
        session.commit()
        assert note.company_id == data.company_a


def test_changing_own_row_works(data: TwoCompanies) -> None:
    # Ordinary edits within the company go through untouched.
    with data.session_for(data.company_a) as session:
        note = session.get(TenantNote, data.note_a)
        assert note is not None
        note.title = "renamed"
        session.commit()
    with data.session_for(data.company_a) as session:
        assert session.scalars(select(TenantNote.title)).all() == ["renamed"]


def test_models_without_company_are_not_filtered(data: TwoCompanies) -> None:
    # A query that touches no company-owned model (here: a plain SQL expression with no
    # table) runs normally even without a company: global tables stay readable.
    with Session(data.engine) as session:
        assert session.scalar(select(1)) == 1


def test_saving_rows_that_are_not_company_owned_needs_no_company() -> None:
    # Flushing a session with no company-owned changes is not affected by the check.
    from sqlalchemy import String, create_engine
    from sqlalchemy.orm import Mapped, mapped_column

    from app.db.base import IdAndTimestamps

    class GlobalThing(IdAndTimestamps, Base):
        __tablename__ = "global_things_test_only"
        name: Mapped[str] = mapped_column(String(50))

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[GlobalThing.__table__])
    with Session(engine) as session:
        session.add(GlobalThing(name="shared"))
        session.commit()
        assert session.scalars(select(GlobalThing.name)).all() == ["shared"]
    engine.dispose()


def test_add_all_is_the_way_to_add_many_rows(data: TwoCompanies) -> None:
    # Bulk inserts are refused for company data; session.add_all() goes through the save
    # check and works.
    with data.session_for(data.company_a) as session:
        session.add_all([TenantNote(title="one"), TenantNote(title="two")])
        session.commit()
        assert session.scalar(select(func.count(TenantNote.id))) == 3


def test_bulk_insert_on_company_data_is_refused_with_a_hint(data: TwoCompanies) -> None:
    with (
        data.session_for(data.company_a) as session,
        pytest.raises(UnsafeQueryError, match="session.add"),
    ):
        session.execute(insert(TenantNote).values(title="bulk"))


@pytest.mark.parametrize("form", ["values", "ordered_values", "parameters"])
def test_every_way_of_setting_company_id_in_a_bulk_update_is_refused(
    data: TwoCompanies, form: str
) -> None:
    # .values(company_id=...), .ordered_values((company_id, ...)), or the value passed
    # separately to session.execute: all three would move rows to another company.
    with data.session_for(data.company_a) as session, pytest.raises(WrongCompanyError):
        if form == "values":
            session.execute(update(TenantNote).values(company_id=data.company_b))
        elif form == "ordered_values":
            session.execute(update(TenantNote).ordered_values(("company_id", data.company_b)))
        else:
            session.execute(update(TenantNote), {"company_id": data.company_b})


def test_bulk_update_or_delete_by_primary_key_is_refused(data: TwoCompanies) -> None:
    # A list of rows keyed by ID runs without the company condition.
    with data.session_for(data.company_a) as session:
        with pytest.raises(UnsafeQueryError):
            session.execute(update(TenantNote), [{"id": data.note_a, "title": "x"}])
        with pytest.raises(UnsafeQueryError):
            session.execute(delete(TenantNote), [{"id": data.note_a}])


def test_the_table_instead_of_the_model_is_refused(data: TwoCompanies) -> None:
    with (
        data.session_for(data.company_a) as session,
        pytest.raises(UnsafeQueryError, match="model"),
    ):
        session.execute(select(TenantNote.__table__.c.title))


def test_bulk_statements_without_a_company_are_refused(data: TwoCompanies) -> None:
    # A filtered update with no company set fails like a query does.
    with Session(data.engine) as session, pytest.raises(MissingCompanyError):
        session.execute(update(TenantNote).values(title="x"))


def test_deleting_own_row_works(data: TwoCompanies) -> None:
    # Ordinary deletes within the company go through.
    with data.session_for(data.company_a) as session:
        note = session.get(TenantNote, data.note_a)
        assert note is not None
        session.delete(note)
        session.commit()
        assert session.scalars(select(TenantNote)).all() == []


def test_a_failed_save_leaves_no_way_around_the_guard(data: TwoCompanies) -> None:
    # A save that fails in the database (here: a duplicate ID) is rolled back. Afterwards
    # the connection must not still count as "saving", or raw statements would slip past.
    with data.session_for(data.company_a) as session:
        session.add(TenantNote(id=data.note_a, title="duplicate"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        with pytest.raises(UnsafeQueryError):
            session.connection().execute(update(TenantNote.__table__).values(title="raw"))


def test_trusted_connections_may_reach_company_data(data: TwoCompanies) -> None:
    # Migrations are operator-run code that no request can reach; data fixes there may
    # span companies, so migrations/env.py marks its connection as trusted.
    with data.engine.connect() as connection:
        trust_connection(connection)
        titles = connection.execute(select(TenantNote.__table__.c.title)).scalars().all()
    assert sorted(titles) == ["A's note", "B's note"]


def test_statements_without_company_tables_pass_the_guard(data: TwoCompanies) -> None:
    # The guard only looks at company tables; anything else runs normally.
    with data.engine.connect() as connection:
        assert connection.execute(select(1)).scalar() == 1
