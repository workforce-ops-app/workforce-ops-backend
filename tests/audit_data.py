"""Shared setup for the audit log tests: two companies, the audit tables, and a test key.

SQLite in memory. The key and its ID are set through the environment, the way the app
reads them (app/core/config.py), from an empty folder so a developer's own .env cannot
change them.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from app.audit.models import AuditChainHead, AuditEvent
from app.core.config import get_settings
from app.db.base import Base
from app.modules.org.models import Company
from app.tenancy.context import set_company

# A test key: long enough for the settings (32 characters or more), and obviously fake.
TEST_KEY = "test-audit-key-not-for-real-use-0123456789"
TEST_KEY_ID = "test-1"

TABLES = [Company.__table__, AuditChainHead.__table__, AuditEvent.__table__]


@dataclass
class AuditSetup:
    """The database and the two companies' IDs."""

    engine: Engine
    company_a: uuid.UUID
    company_b: uuid.UUID

    def session_for(self, company_id: uuid.UUID | None) -> Session:
        """A session working for a company, or for the platform (None)."""
        session = Session(self.engine)
        if company_id is not None:
            set_company(session, company_id)
        return session

    def events(self, chain_id: uuid.UUID) -> list[AuditEvent]:
        """One chain's entries in order, read by platform code."""
        with Session(self.engine) as session:
            return list(
                session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.chain_id == chain_id)
                    .order_by(AuditEvent.seq)
                )
            )


def use_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, key: str | None) -> None:
    """Set (or remove) the signing key in the environment and reload the settings."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    monkeypatch.setenv("AUDIT_KEY_ID", TEST_KEY_ID)
    if key is None:
        monkeypatch.delenv("AUDIT_SIGNING_KEY", raising=False)
    else:
        monkeypatch.setenv("AUDIT_SIGNING_KEY", key)
    get_settings.cache_clear()


@pytest.fixture
def audit(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[AuditSetup]:
    """Two companies and empty audit tables, with the test key set."""
    use_key(monkeypatch, tmp_path, TEST_KEY)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=TABLES)
    with Session(engine) as platform:
        a = Company(name="Northwind Cafe", timezone="America/Chicago")
        b = Company(name="Summit Outfitters", timezone="America/Denver")
        platform.add_all([a, b])
        platform.commit()
        ids = a.id, b.id
    yield AuditSetup(engine, *ids)
    engine.dispose()
    # Settings read again by the next test, without this test's environment.
    get_settings.cache_clear()
