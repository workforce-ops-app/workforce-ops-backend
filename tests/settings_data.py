"""Shared setup for the company settings tests: two companies, the audit tables (every
change is audited), and company_settings, on SQLite in memory with the test signing key.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import Base
from app.modules.org.models import Company
from app.settings.models import CompanySetting
from tests.audit_data import TABLES, TEST_KEY, AuditSetup, use_key


@pytest.fixture
def companies(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[AuditSetup]:
    """Northwind Cafe (company_a) and Summit Outfitters (company_b), with no settings."""
    use_key(monkeypatch, tmp_path, TEST_KEY)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[*TABLES, CompanySetting.__table__])
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
