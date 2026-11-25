"""Roles over HTTP (authorization.md). HTTP only: the rules and the permission checks are
in service.py.

    GET  /api/permissions                              200  what a role can grant
    GET  /api/roles                                    200  every role, archived included
    GET  /api/roles/{id}                               200  one role
    POST /api/roles  {name, permissions}               201  create
    PATCH /api/roles/{id}  {name?, permissions?}       200  rename, change what it grants
    POST /api/roles/{id}/archive                       200  archive
    GET  /api/role-assignments?user_id=                200  the roles one person holds
    POST /api/role-assignments  {user_id, role_id,     201  give a role, or
                                 scope_type, scope_id?} 202  ask for approval (own level)
    DELETE /api/role-assignments/{id}                  204  take a role away

Errors: 401 not signed in, 403 not allowed (or "reauth-required": enter the password
again, then repeat the request), 404 not found (or another company's), 409 not allowed
in the current state, 422 invalid input. Every change also needs the CSRF token.
"""

import uuid

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

import app.modules.roles.approval  # noqa: F401  (registers what role requests do on approval)
from app.auth.dependencies import Database, SignedInPerson
from app.authz.check import Forbidden, authorize
from app.authz.delegation import above_every_holder
from app.authz.models import Role, RoleAssignment
from app.modules.approval_requests.schemas import ApprovalRequestOut, shown
from app.modules.org.models import User
from app.modules.roles import assignments, service
from app.modules.roles.schemas import (
    AssignmentCreate,
    AssignmentList,
    AssignmentOut,
    PermissionList,
    PermissionOut,
    RoleCreate,
    RoleList,
    RoleOut,
    RoleUpdate,
)

permissions = APIRouter(prefix="/api/permissions", tags=["roles"])
roles = APIRouter(prefix="/api/roles", tags=["roles"])
role_assignments = APIRouter(prefix="/api/role-assignments", tags=["roles"])


def _may_manage(db: Database, viewer: User) -> bool:
    """Whether the viewer holds role.manage (ordinary reads; worked out once per answer)."""
    try:
        authorize(db, viewer, "role.manage")
    except Forbidden:
        return False
    return True


def _role(
    db: Database, viewer: User, role: Role, codes: list[str], *, may_manage: bool | None = None
) -> RoleOut:
    """A role in the answer shape, with whether the viewer may change it: the same rule as
    service._changeable_role (role.manage, not Owner, not archived, above every holder;
    review of #171), on ordinary reads, since an answer takes no row locks."""
    archived = role.archived_at is not None
    if may_manage is None:
        may_manage = _may_manage(db, viewer)
    changeable = (
        may_manage
        and role.built_in != "owner"
        and not archived
        and above_every_holder(db, viewer, role, fresh=False)
    )
    return RoleOut(
        id=role.id,
        name=role.name,
        built_in=role.built_in,
        archived=archived,
        permissions=codes,
        you_may_change=changeable,
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
    found = service.list_roles(db, current.user)
    may_manage = _may_manage(db, current.user)
    return RoleList(
        items=[_role(db, current.user, role, codes, may_manage=may_manage) for role, codes in found]
    )


@roles.get("/{role_id}")
def view_role(role_id: uuid.UUID, current: SignedInPerson, db: Database) -> RoleOut:
    return _role(db, current.user, *service.view_role(db, current.user, role_id))


@roles.post("", status_code=201)
def create_role(body: RoleCreate, current: SignedInPerson, db: Database) -> RoleOut:
    role = service.create_role(db, current.user, body)
    return _role(db, current.user, role, service.granted(db, role))


@roles.patch("/{role_id}")
def update_role(
    role_id: uuid.UUID, body: RoleUpdate, current: SignedInPerson, db: Database
) -> RoleOut:
    role = service.update_role(db, current.user, role_id, body, session=current.session)
    return _role(db, current.user, role, service.granted(db, role))


@roles.post("/{role_id}/archive")
def archive_role(role_id: uuid.UUID, current: SignedInPerson, db: Database) -> RoleOut:
    role = service.archive_role(db, current.user, role_id, session=current.session)
    return _role(db, current.user, role, service.granted(db, role))


def _assignment(item: RoleAssignment, role: Role) -> AssignmentOut:
    """A role someone holds, in the answer shape."""
    return AssignmentOut(
        id=item.id,
        user_id=item.user_id,
        role_id=role.id,
        role_name=role.name,
        built_in=role.built_in,
        role_archived=role.archived_at is not None,
        scope_type=item.scope_type,
        scope_id=assignments.scope_id_of(item),
    )


@role_assignments.get("")
def list_assignments(user_id: uuid.UUID, current: SignedInPerson, db: Database) -> AssignmentList:
    rows = assignments.list_for(db, current.user, user_id)
    return AssignmentList(items=[_assignment(item, role) for item, role in rows])


@role_assignments.post(
    "",
    status_code=201,
    # Two possible answers: 201 with the assignment, or 202 with the request. The 202 is
    # returned as a ready-made JSONResponse, which FastAPI passes through as it is.
    response_model=AssignmentOut,
    responses={202: {"model": ApprovalRequestOut, "description": "Waiting for approval"}},
)
def give_role(
    body: AssignmentCreate, current: SignedInPerson, db: Database
) -> AssignmentOut | JSONResponse:
    given = assignments.give(db, current.user, body, session=current.session)
    if given.assignment is None:
        # Accepted, not done: the role is given only once someone above approves it.
        content = shown(db, given.request).model_dump(mode="json")  # type: ignore[arg-type]
        return JSONResponse(status_code=202, content=content)
    return _assignment(given.assignment, given.role)


@role_assignments.delete("/{assignment_id}", status_code=204)
def remove_role(assignment_id: uuid.UUID, current: SignedInPerson, db: Database) -> Response:
    assignments.remove(db, current.user, assignment_id, session=current.session)
    return Response(status_code=204)


# The app includes the one `router` of each module (app/main.py). This comes last:
# include_router copies the routes defined above at this moment.
router = APIRouter()
router.include_router(permissions)
router.include_router(roles)
router.include_router(role_assignments)
