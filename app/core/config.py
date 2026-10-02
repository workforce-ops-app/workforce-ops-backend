"""Settings, read only from environment variables (and a local .env file).

Every setting is listed in .env.example. Settings that hold secrets have no default here,
so a missing secret stops the app at startup instead of silently using a weak value.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: Literal["development", "test", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # Contains the database password, so it has no default (decision 0034: PyMySQL).
    database_url: str

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
