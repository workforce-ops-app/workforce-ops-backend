"""Sessions: one engine for the app, a fresh session per request, closed afterwards."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import get_engine, get_session


@pytest.fixture(autouse=True)
def sqlite_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DATABASE_URL", "sqlite://")
    get_settings.cache_clear()
    get_engine.cache_clear()
    yield
    get_engine().dispose()  # close its connections before forgetting it
    get_settings.cache_clear()
    get_engine.cache_clear()


def test_engine_is_created_once_from_settings() -> None:
    engine = get_engine()

    assert str(engine.url) == "sqlite://"
    assert get_engine() is engine


def test_session_works_and_is_closed_after_the_request() -> None:
    sessions = get_session()
    session = next(sessions)

    assert session.execute(text("SELECT 1")).scalar_one() == 1

    with pytest.raises(StopIteration):
        next(sessions)  # the request ends: the dependency finishes
    assert not session.in_transaction()
