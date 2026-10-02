"""The app factory: API docs only outside production, and module discovery."""

import importlib
import pkgutil
from types import SimpleNamespace

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app import main
from app.core.config import Settings
from app.main import create_app


def test_app_loads_settings_when_none_are_supplied(monkeypatch: pytest.MonkeyPatch) -> None:
    environment_settings = Settings(
        app_env="development",
        database_url="mysql+pymysql://test:test@localhost:3307/test",
    )
    monkeypatch.setattr(main, "get_settings", lambda: environment_settings)

    app = create_app()

    assert app.docs_url == "/api/docs"


def test_api_docs_are_available_in_development(client: TestClient) -> None:
    assert client.get("/api/docs").status_code == 200
    assert client.get("/api/openapi.json").status_code == 200


def test_api_docs_are_hidden_in_production() -> None:
    # A production server must not advertise every endpoint (threat model I4).
    settings = Settings(
        app_env="production", database_url="mysql+pymysql://test:test@localhost:3307/test"
    )
    client = TestClient(create_app(settings))

    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_discovery_includes_only_real_routers(monkeypatch: pytest.MonkeyPatch) -> None:
    real_router = APIRouter()
    found = [
        SimpleNamespace(name="loose_file", ispkg=False),  # a plain .py file: skipped
        SimpleNamespace(name="no_endpoints", ispkg=True),  # no router.py: skipped
        SimpleNamespace(name="wrong_type", ispkg=True),  # `router` is not an APIRouter: skipped
        SimpleNamespace(name="good", ispkg=True),  # included
    ]
    modules_by_name = {
        "app.modules.wrong_type.router": SimpleNamespace(router="not a router"),
        "app.modules.good.router": SimpleNamespace(router=real_router),
    }

    def fake_import(name: str) -> object:
        if name not in modules_by_name:
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return modules_by_name[name]

    monkeypatch.setattr(pkgutil, "iter_modules", lambda path: found)
    monkeypatch.setattr(importlib, "import_module", fake_import)

    assert main.discover_routers() == [real_router]


def test_discovery_fails_when_a_router_has_a_missing_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # router.py exists, but it imports something that does not: the app must not start
    # quietly without that feature's endpoints.
    found = [SimpleNamespace(name="broken", ispkg=True)]

    def fake_import(name: str) -> object:
        raise ModuleNotFoundError("No module named 'missing_dependency'", name="missing_dependency")

    monkeypatch.setattr(pkgutil, "iter_modules", lambda path: found)
    monkeypatch.setattr(importlib, "import_module", fake_import)

    with pytest.raises(ModuleNotFoundError, match="missing_dependency"):
        main.discover_routers()
