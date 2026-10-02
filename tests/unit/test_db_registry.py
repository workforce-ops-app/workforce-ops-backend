"""Loading the features' models for Alembic (app/db/registry.py).

A feature without models.py is skipped; a models.py whose own imports fail stops
Alembic, so migrations are never generated from an incomplete list of tables.
"""

import importlib
import pkgutil
from types import SimpleNamespace

import pytest

from app.db import registry


def fake_features(monkeypatch: pytest.MonkeyPatch, imports: dict[str, Exception | None]) -> None:
    """Pretend app/modules holds the given features, and fake what importing each does.

    imports maps a feature name to the error its models import raises (None: imports fine).
    """
    # The folder listing: one package per feature, plus a loose file that is not a feature.
    found = [SimpleNamespace(name=name, ispkg=True) for name in imports]
    found.append(SimpleNamespace(name="loose_file", ispkg=False))
    monkeypatch.setattr(pkgutil, "iter_modules", lambda path: found)

    # The import: raise the given error for that feature's models module, or succeed.
    def fake_import(name: str) -> object:
        feature = name.split(".")[2]
        error = imports[feature]
        if error is not None:
            raise error
        return SimpleNamespace()

    monkeypatch.setattr(importlib, "import_module", fake_import)


def test_features_with_models_are_imported_and_others_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_features(
        monkeypatch,
        {
            "shifts": None,  # has a models.py
            # No models.py: Python reports the models module itself as not found.
            "health": ModuleNotFoundError(
                "No module named 'app.modules.health.models'", name="app.modules.health.models"
            ),
        },
    )

    # Only the feature with a models.py is imported; the loose file is ignored.
    assert registry.import_all_models() == ["app.modules.shifts.models"]


def test_a_models_file_with_a_missing_import_stops_alembic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # models.py exists, but it imports something that does not: the error must come
    # through, so Alembic stops instead of generating migrations without its tables.
    fake_features(
        monkeypatch,
        {
            "broken": ModuleNotFoundError(
                "No module named 'missing_dependency'", name="missing_dependency"
            ),
        },
    )

    with pytest.raises(ModuleNotFoundError, match="missing_dependency"):
        registry.import_all_models()
