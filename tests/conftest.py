"""Shared test setup: an app built with test settings, and a client to call it."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def settings() -> Settings:
    # A placeholder URL: unit tests never open a database connection.
    return Settings(app_env="test", database_url="mysql+pymysql://test:test@localhost:3307/test")


@pytest.fixture
def app(settings: Settings) -> FastAPI:
    return create_app(settings)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    # raise_server_exceptions=False: see the 500 response the browser would get,
    # instead of the test crashing with the original exception.
    return TestClient(app, raise_server_exceptions=False)
