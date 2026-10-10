"""The permission registry: every permission the application can check (authorization.md).

Each feature module declares its permissions in app/modules/<feature>/permissions.py, as
a list named PERMISSIONS; the shared layers (authz, audit) declare theirs here. The
registry collects them all once, checks they follow the naming rules, and knows each
permission's KIND, which decides how authorize() checks it:

- self:    the user's own records only ("see your own shifts")
- record:  records in the assignment's scope ("edit Kitchen's shifts")
- person:  another person in scope, and only someone you are above ("review Sam's time off")
- company: company-wide settings and structure; needs a company-wide assignment

The permissions table is filled from here by sync_permissions(): the code is the source of
truth, and companies only choose which permissions each role grants.
"""

import importlib
import pkgutil
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app import modules
from app.authz.models import Permission


class Kind(StrEnum):
    """How a permission is checked (authorization.md, kinds of permission)."""

    SELF = "self"
    RECORD = "record"
    PERSON = "person"
    COMPANY = "company"


@dataclass(frozen=True)
class PermissionDef:
    """One permission as a module declares it. `module` is filled in by the registry."""

    code: str
    kind: Kind
    description: str
    module: str = ""


# "resource.action", lowercase letters and underscores.
_CODE = re.compile(r"^[a-z_]+\.[a-z_]+$")

# The shared layers' own permissions (feature modules declare theirs in permissions.py).
_SHARED = {
    "authz": [
        PermissionDef("role.view", Kind.COMPANY, "See roles and what they grant"),
        PermissionDef("role.manage", Kind.COMPANY, "Create, change, and archive roles"),
        PermissionDef("role.assign", Kind.PERSON, "Give or remove roles for people you are above"),
        PermissionDef(
            "reporting_line.manage", Kind.PERSON, "Add or end reporting lines between people"
        ),
    ],
    "audit": [
        PermissionDef("audit.view", Kind.COMPANY, "Read the company's audit log"),
        PermissionDef("audit.verify", Kind.COMPANY, "Verify the company's audit log"),
    ],
}


def _declared() -> list[PermissionDef]:
    """Every declaration: the shared layers', then each module's permissions.py."""
    found = [replace(p, module=module) for module, perms in _SHARED.items() for p in perms]
    for info in pkgutil.iter_modules(modules.__path__):
        if not info.ispkg:
            continue
        name = f"app.modules.{info.name}.permissions"
        try:
            declared = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            # No permissions.py: this module declares none. Any other missing import is a
            # real error and stops here (as router and model discovery do).
            if exc.name == name:
                continue
            raise
        found += [replace(p, module=info.name) for p in getattr(declared, "PERMISSIONS", [])]
    return found


@lru_cache
def all_permissions() -> dict[str, PermissionDef]:
    """Every permission by code, checked against the naming rules (read once)."""
    registry: dict[str, PermissionDef] = {}
    for permission in _declared():
        code = permission.code
        if not _CODE.match(code) or len(code) > 100:
            raise ValueError(f"permission {code!r} must be resource.action in lowercase")
        # A name ending in "_self" promises "only your own records", so it must be a self
        # permission: a name may never hide wider access than it suggests. (Some self
        # permissions, such as time_off.request, have no suffix; that only makes their name
        # less specific, never misleading.)
        if code.endswith("_self") and permission.kind is not Kind.SELF:
            raise ValueError(f"permission {code!r} ends in _self, so it must be a self permission")
        if code in registry:
            raise ValueError(f"permission {code!r} is declared twice")
        registry[code] = permission
    return registry


def get_permission(code: str) -> PermissionDef:
    """One permission by code. An unknown code is a bug in the caller, so it raises."""
    try:
        return all_permissions()[code]
    except KeyError:
        raise LookupError(f"unknown permission {code!r}") from None


def sync_permissions(db: Session) -> None:
    """Make the permissions table match the registry (adds new ones, updates descriptions).

    Called before roles are created (app/authz/roles.py), so every permission a role grants
    exists. The caller commits. Permissions are never removed here: a role may still
    reference one, and removing it is a deliberate migration.
    """
    stored = {p.code: p for p in db.scalars(select(Permission))}
    for code, permission in all_permissions().items():
        row = stored.get(code)
        if row is None:
            db.add(
                Permission(code=code, module=permission.module, description=permission.description)
            )
        else:
            row.module, row.description = permission.module, permission.description
    db.flush()
