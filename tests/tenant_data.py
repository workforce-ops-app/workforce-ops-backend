"""Test-only company data: a small company-owned model and two companies' worth of rows.

Used by tests/unit/test_tenancy.py (how the filter works) and tests/security/ (what a
user of one company can reach of another). Real company-owned tables arrive with later
slices; until then this model stands in for them.

The database is SQLite in memory: the company filter works inside SQLAlchemy, before
any SQL reaches the database, so SQLite tests it exactly as MySQL would run it.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import Engine, String, create_engine
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.db.base import Base, IdAndTimestamps
from app.tenancy.context import set_company
from app.tenancy.filter import CompanyOwned


class TenantNote(IdAndTimestamps, CompanyOwned, Base):
    """A company-owned row for tests only (never part of a migration)."""

    __tablename__ = "tenant_notes_test_only"

    title: Mapped[str] = mapped_column(String(100))


@dataclass
class TwoCompanies:
    """Two companies with one note each, and a database holding them."""

    engine: Engine
    company_a: uuid.UUID
    company_b: uuid.UUID
    note_a: uuid.UUID  # the ID of company A's note
    note_b: uuid.UUID  # the ID of company B's note

    def session_for(self, company_id: uuid.UUID) -> Session:
        """A new session working for one company, the way a request's session will."""
        session = Session(self.engine)
        set_company(session, company_id)
        return session


def make_two_companies() -> TwoCompanies:
    """Create an in-memory database with two companies, each owning one note."""
    # An empty SQLite database in memory, with just the test table.
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[TenantNote.__table__])

    # Two company IDs. No companies table exists yet; the IDs alone are enough here.
    company_a, company_b = uuid.uuid4(), uuid.uuid4()

    # Save one note per company, each through a session working for that company,
    # exactly as the application will (the filter fills in company_id).
    note_ids = []
    for company_id, title in ((company_a, "A's note"), (company_b, "B's note")):
        with Session(engine) as session:
            set_company(session, company_id)
            note = TenantNote(title=title)
            session.add(note)
            session.commit()
            note_ids.append(note.id)

    return TwoCompanies(engine, company_a, company_b, note_ids[0], note_ids[1])
