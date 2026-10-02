"""How the company filter behaves for the application's own code (app/tenancy/).

The attacker's view (reaching another company's data) is in tests/security/.
"""

from collections.abc import Iterator

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import Base
from app.tenancy.context import get_company, set_company
from app.tenancy.filter import MissingCompanyError, WrongCompanyError
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
