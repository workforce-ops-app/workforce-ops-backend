"""Every password a request can carry has a size limit (#85).

The request's own rules refuse a longer one (422) before any code runs, so an oversized
password never reaches Argon2id (the slow check) or the password rules. This walks every
request model in the app, so a new endpoint that forgets the limit fails here.
"""

import importlib
import pkgutil

from pydantic import BaseModel, SecretStr

import app.modules
from app.auth.passwords import MAX_LENGTH

LIMIT = 1024  # far above MAX_LENGTH (128), so no real password is turned away


def password_fields() -> list[tuple[str, int | None]]:
    """(model.field, its max_length) for every SecretStr field named like a password."""
    found = []
    for module in pkgutil.walk_packages(app.modules.__path__, "app.modules."):
        if not module.name.endswith(".schemas"):
            continue
        for value in vars(importlib.import_module(module.name)).values():
            if not (isinstance(value, type) and issubclass(value, BaseModel)):
                continue
            for name, field in value.model_fields.items():
                if field.annotation is SecretStr and "password" in name:
                    limits = [m.max_length for m in field.metadata if hasattr(m, "max_length")]
                    found.append((f"{value.__name__}.{name}", limits[0] if limits else None))
    return found


def test_every_password_field_has_a_size_limit() -> None:
    fields = password_fields()
    # Sign-in, re-authentication, changing a password (both), the reset link, and sign-up.
    assert len(fields) >= 6, fields
    assert [name for name, limit in fields if limit is None or limit > LIMIT] == []


def test_the_limit_never_refuses_a_password_the_rules_allow() -> None:
    assert LIMIT > MAX_LENGTH
