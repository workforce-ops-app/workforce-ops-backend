"""Settings, read only from environment variables (and a local .env file).

Every setting is listed in .env.example. Settings that hold secrets have no default here,
so a missing secret stops the app at startup instead of silently using a weak value.
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL, make_url

AppEnvironment = Literal["development", "test", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: AppEnvironment = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # Where the database is, e.g. mysql+pymysql://workforce_app@localhost:3307/workforce_ops
    # (decision 0034: PyMySQL). Required: there is no safe default database.
    database_url: str
    # The database password, kept apart from the URL (see sqlalchemy_url below). SecretStr
    # hides it when the settings are printed or logged. Optional, so a password already
    # written inside DATABASE_URL keeps working.
    database_password: SecretStr | None = None
    # The password the demo seed script (scripts/seed_demo.py) gives every demo account,
    # so the demo can sign in. Local and demo use only; never in production.
    demo_password: SecretStr | None = None
    # The secret key that signs every audit log entry (decision 0018, audit-log.md), and
    # its ID, which is stored with each entry so the key can be rotated later. Kept out of
    # the database and the repository: whoever has the key can forge a valid-looking log.
    # Optional here, so migrations and scripts run without it; writing an audit entry
    # without a key is refused (app/audit/record.py), and the action fails with it.
    audit_signing_key: SecretStr | None = Field(default=None, min_length=32)
    audit_key_id: str = Field(default="local-1", min_length=1, max_length=40)
    # The secret key that turns a session into its CSRF token (app/auth/csrf.py). Separate
    # from the audit key, so leaking one does not weaken the other. The API refuses to
    # start without it (app/main.py): every change to data depends on it.
    csrf_key: SecretStr | None = Field(default=None, min_length=32)
    # The application's own address as browsers see it, e.g. https://workforce.example or
    # http://localhost:8080 (decision 0003: pages and API at one address). Requests that
    # change something must come from it (the Origin check). Unset: the address the
    # request itself was sent to, which is right when nothing in front rewrites it.
    app_origin: str | None = None

    @property
    def sqlalchemy_url(self) -> URL:
        """The database address as SQLAlchemy's URL object, with the password filled in.

        A password pasted into URL text breaks when it contains characters that mean
        something in a URL: "p@ss:word" would be read as user "p", host "ss", and so on.
        Setting it as a separate part of the URL object needs no escaping at all.
        """
        # Read the address (driver, user, host, port, database) from the text.
        url = make_url(self.database_url)

        # Put the password in as its own part, if one was given separately. It wins over
        # a password inside DATABASE_URL.
        if self.database_password is not None:
            url = url.set(password=self.database_password.get_secret_value())

        return url

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache
def get_settings() -> Settings:
    """The settings, read once and then reused."""
    return Settings()  # values come from the environment and .env
