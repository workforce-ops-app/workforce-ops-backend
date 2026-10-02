"""Settings come from environment variables, and secrets have no defaults."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import get_settings


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Run in an empty folder so a developer's own .env cannot affect the result.
    monkeypatch.chdir(tmp_path)
    for name in ("APP_ENV", "LOG_LEVEL", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    get_settings.cache_clear()


def test_settings_are_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://app:secret@db:3306/workforce_ops")

    settings = get_settings()

    assert settings.is_production
    assert settings.database_url.endswith("@db:3306/workforce_ops")
    assert settings.log_level == "INFO"  # the default


def test_missing_database_url_stops_startup() -> None:
    # The database URL holds a password, so it has no default: missing means fail loudly.
    with pytest.raises(ValidationError):
        get_settings()
