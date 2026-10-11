"""Shared test setup: an app built with test settings, and a client to call it."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

# A test CSRF key: long enough for the settings, and obviously fake. The API refuses to
# start without one (app/main.py).
TEST_CSRF_KEY = "test-csrf-key-not-for-real-use-0123456789"

# The address test clients use; requests that change something must come from it, so the
# clients send it as their Origin, as a browser on our own pages would.
TEST_ORIGIN = "http://testserver"


@pytest.fixture
def settings() -> Settings:
    # A placeholder URL: unit tests never open a database connection.
    return Settings(
        app_env="test",
        database_url="mysql+pymysql://test:test@localhost:3307/test",
        csrf_key=TEST_CSRF_KEY,  # type: ignore[arg-type]
    )


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    # raise_server_exceptions=False: see the 500 response the browser would get,
    # instead of the test crashing with the original exception.
    return TestClient(app, raise_server_exceptions=False, headers={"Origin": TEST_ORIGIN})
