"""Settings come from environment variables, and secrets have no defaults."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import get_settings


@pytest.fixture(autouse=True)
def isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Run in an empty folder so a developer's own .env cannot affect the result.
    monkeypatch.chdir(tmp_path)
    for name in ("APP_ENV", "LOG_LEVEL", "DATABASE_URL", "DATABASE_PASSWORD"):
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


# Characters that mean something in a URL: @ ends the user part, : separates the
# password, / starts the path, % starts an escape, # a fragment, and ? a query.
RESERVED_PASSWORD = "p@ss:w/rd%41#x?y"


def test_password_with_url_characters_is_kept_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://workforce_app@db:3306/workforce_ops")
    monkeypatch.setenv("DATABASE_PASSWORD", RESERVED_PASSWORD)

    url = get_settings().sqlalchemy_url

    # Every part arrives intact: the password is not cut at @ or :, and the host, port,
    # and database are not taken from pieces of the password.
    assert url.password == RESERVED_PASSWORD
    assert url.username == "workforce_app"
    assert url.host == "db"
    assert url.port == 3306
    assert url.database == "workforce_ops"


def test_pasting_the_password_into_the_url_would_break() -> None:
    # The bug this design avoids, shown with SQLAlchemy's own URL parser.
    from sqlalchemy.engine import make_url

    def pasted(password: str) -> object:
        return make_url(f"mysql+pymysql://workforce_app:{password}@db:3306/workforce_ops")

    # "p@ss:word": the URL cannot even be read (the text after ":" is taken as a port), so
    # the API could not connect at all.
    with pytest.raises(ValueError):
        pasted("p@ss:word")

    # "pa%41ss": worse, it is read without error but silently changed, since %41 is taken
    # as an escape code for "A". The app would send the wrong password.
    assert pasted("pa%41ss").password == "paAss"  # type: ignore[attr-defined]


def test_a_password_inside_database_url_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    # Older .env files with the password in the URL keep working (URL-safe passwords only).
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://app:secret@db:3306/workforce_ops")

    assert get_settings().sqlalchemy_url.password == "secret"


def test_the_password_never_shows_when_printed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Settings and URLs end up in log lines and error messages; the password must not.
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://workforce_app@db:3306/workforce_ops")
    monkeypatch.setenv("DATABASE_PASSWORD", RESERVED_PASSWORD)

    settings = get_settings()

    assert RESERVED_PASSWORD not in repr(settings)
    assert RESERVED_PASSWORD not in str(settings.sqlalchemy_url)
