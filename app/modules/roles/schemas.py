"""Request and response shapes for the role endpoints (authorization.md).

Requests forbid unknown fields, so a body cannot set built_in, archived_at, or a company
(threat T2): those only change through the rules in service.py.
"""

import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints

from app.modules.org.schemas import Strict

# A role's name: surrounding spaces removed, 1 to 80 characters (the column).
RoleName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]

# A permission code as written in a request: at most 100 characters (the column). Whether
# it is a real permission is checked against the registry in the service (422 if not).
Code = Annotated[str, StringConstraints(min_length=1, max_length=100)]

# A list of codes: at most 200, more than there are permissions, so a huge body is refused
# before any work is done (every input is bounded, #105).
Codes = Annotated[list[Code], Field(max_length=200)]


class PermissionOut(BaseModel):
    """One permission a role can grant, for the screen that edits roles."""

    code: str
    kind: str  # self, record, person, or company (authorization.md)
    description: str


class PermissionList(BaseModel):
    items: list[PermissionOut]


class RoleOut(BaseModel):
    """A role and what it grants."""

    id: uuid.UUID
    name: str
    built_in: str | None  # owner, administrator, manager, employee; null for the company's own
    archived: bool
    permissions: list[str]  # sorted codes
    # Whether the signed-in person may rename, change, or archive it now: only with
    # role.manage, never the Owner role or an archived one, and only when they are above
    # every holder (AZ13; an owner may change any other role). Worked out by the API, so the
    # interface offers changes only where they can work; every change is still checked.
    you_may_change: bool


class RoleList(BaseModel):
    items: list[RoleOut]


class RoleCreate(Strict):
    """A new role and what it grants (repeated codes count once)."""

    name: RoleName
    permissions: Codes = []


class RoleUpdate(Strict):
    """Rename a role, or replace what it grants (the full list). Only the fields sent
    change."""

    name: RoleName | None = None
    permissions: Codes | None = None


# --- Role assignments ------------------------------------------------------------------


class AssignmentCreate(Strict):
    """Give a person a role for one place: the whole company (no scope_id), a department,
    a team, or one employee (scope_id names it)."""

    user_id: uuid.UUID
    role_id: uuid.UUID
    scope_type: Literal["company", "department", "team", "employee"]
    scope_id: uuid.UUID | None = None


class AssignmentOut(BaseModel):
    """A role one person holds, and where it applies."""

    id: uuid.UUID
    user_id: uuid.UUID
    role_id: uuid.UUID
    role_name: str
    built_in: str | None
    role_archived: bool  # an archived role is still listed, but grants nothing
    scope_type: str
    scope_id: uuid.UUID | None


class AssignmentList(BaseModel):
    items: list[AssignmentOut]
