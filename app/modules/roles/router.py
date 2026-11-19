"""Roles over HTTP (authorization.md). HTTP only: the rules and the permission checks are
in service.py.

    GET  /api/permissions                              200  what a role can grant
    GET  /api/roles                                    200  every role, archived included
    GET  /api/roles/{id}                               200  one role
    POST /api/roles  {name, permissions}               201  create
    PATCH /api/roles/{id}  {name?, permissions?}       200  rename, change what it grants
    POST /api/roles/{id}/archive                       200  archive

Errors: 401 not signed in, 403 not allowed (or "reauth-required": enter the password
again, then repeat the request), 404 not found (or another company's), 409 not allowed
in the current state, 422 invalid input. Every change also needs the CSRF token.
"""

import uuid

from fastapi import APIRouter

from app.auth.dependencies import Database, SignedInPerson
from app.authz.models import Role
from app.modules.roles import service
from app.modules.roles.schemas import (
    PermissionList,
    PermissionOut,
    RoleCreate,
    RoleList,
    RoleOut,
    RoleUpdate,
)

permissions = APIRouter(prefix="/api/permissions", tags=["roles"])
roles = APIRouter(prefix="/api/roles", tags=["roles"])


def _role(role: Role, codes: list[str]) -> RoleOut:
    """A role in the answer shape."""
    return RoleOut(
        id=role.id,
        name=role.name,
        built_in=role.built_in,
        archived=role.archived_at is not None,
        permissions=codes,
    )


@permissions.get("")
def list_permissions(current: SignedInPerson, db: Database) -> PermissionList:
    found = service.list_permissions(db, current.user)
    return PermissionList(
        items=[
            PermissionOut(code=p.code, kind=p.kind.value, description=p.description) for p in found
        ]
    )


@roles.get("")
def list_roles(current: SignedInPerson, db: Database) -> RoleList:
    return RoleList(
        items=[_role(role, codes) for role, codes in service.list_roles(db, current.user)]
    )


@roles.get("/{role_id}")
def view_role(role_id: uuid.UUID, current: SignedInPerson, db: Database) -> RoleOut:
    return _role(*service.view_role(db, current.user, role_id))


@roles.post("", status_code=201)
def create_role(body: RoleCreate, current: SignedInPerson, db: Database) -> RoleOut:
    role = service.create_role(db, current.user, body)
    return _role(role, service.granted(db, role))


@roles.patch("/{role_id}")
def update_role(
    role_id: uuid.UUID, body: RoleUpdate, current: SignedInPerson, db: Database
) -> RoleOut:
    role = service.update_role(db, current.user, role_id, body, session=current.session)
    return _role(role, service.granted(db, role))


@roles.post("/{role_id}/archive")
def archive_role(role_id: uuid.UUID, current: SignedInPerson, db: Database) -> RoleOut:
    role = service.archive_role(db, current.user, role_id, session=current.session)
    return _role(role, service.granted(db, role))


# The app includes the one `router` of each module (app/main.py). This comes last:
# include_router copies the routes defined above at this moment.
router = APIRouter()
router.include_router(permissions)
router.include_router(roles)
