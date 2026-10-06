"""The starting roles every company gets, and giving a person a role (authorization.md).

Every new company starts with Owner, Administrator, Manager, and Employee, granting what the
"starting roles" table on the authorization page says. Creating roles and assignments writes
audit entries (rule AZ12).

These are building blocks for platform code (the seed script) and later services. They do
not check who is asking: the delegation rules (who may give which role to whom, AZ1 to AZ4,
AZ14) belong to the role endpoints (Z4), which call authorize() first.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.authz.models import SCOPE_TYPES, Role, RoleAssignment, RolePermission
from app.authz.registry import all_permissions, sync_permissions

# What each starting role grants. Owner holds every permission (and is locked); the others
# follow the starting-roles table on the authorization page.
_MANAGER = [
    "schedule.view_self",
    "schedule.view",
    "schedule.edit",
    "time_off.request",
    "time_off.cancel_self",
    "time_off.view",
    "time_off.review",
    "user.view",
    "account.change_self",
    "role.view",
]
_EMPLOYEE = [
    "schedule.view_self",
    "schedule.view",  # their department's schedule; an administrator may remove it
    "time_off.request",
    "time_off.cancel_self",
    "account.change_self",
]
_OWNER_ONLY = ["company.transfer_ownership"]

# The starting roles' names, by built_in (what each grants: _grants_for below).
STARTING_ROLES = {
    "owner": "Owner",
    "administrator": "Administrator",
    "manager": "Manager",
    "employee": "Employee",
}


def _grants_for(built_in: str) -> list[str]:
    """The permission codes a starting role grants: Owner every permission, Administrator
    all but the owner-only ones, Manager and Employee their lists above."""
    everything = sorted(all_permissions())
    if built_in == "owner":
        return everything
    if built_in == "administrator":
        return [code for code in everything if code not in _OWNER_ONLY]
    return sorted(_MANAGER if built_in == "manager" else _EMPLOYEE)


class RoleError(ValueError):
    """A role or assignment that is not allowed by the data rules."""


def create_starting_roles(db: Session, actor: Actor) -> dict[str, Role]:
    """Create the four starting roles in the session's company; returns them by built_in.

    The caller commits. Each role's creation is audited, with what it grants.
    """
    sync_permissions(db)  # every permission a role grants must exist first
    roles: dict[str, Role] = {}
    for built_in, name in STARTING_ROLES.items():
        role = Role(name=name, built_in=built_in)
        db.add(role)
        db.flush()  # gives the role its ID
        codes = _grants_for(built_in)
        db.add_all(RolePermission(role_id=role.id, permission_code=code) for code in codes)
        record(
            db,
            actor=actor,
            action="role.created",
            target_type="role",
            target_id=role.id,
            details={"name": name, "built_in": built_in, "permissions": codes},
        )
        roles[built_in] = role
    db.flush()
    return roles


def assign_role(
    db: Session,
    actor: Actor,
    *,
    user_id: uuid.UUID,
    role: Role,
    scope_type: str,
    scope_id: uuid.UUID | None = None,
) -> RoleAssignment:
    """Give a person a role for one scope; audited. The caller commits.

    scope_id is the department, team, or employee for those scopes, and None for company.
    A duplicate (same person, role, and scope) is refused.
    """
    if scope_type not in SCOPE_TYPES:
        raise RoleError(f"unknown scope type {scope_type!r}")
    if (scope_type == "company") != (scope_id is None):
        raise RoleError("a company-wide assignment has no scope ID; every other one has one")
    # Owner is always assigned for the whole company (authorization.md).
    if role.built_in == "owner" and scope_type != "company":
        raise RoleError("the Owner role is always assigned for the whole company")

    columns = {
        "department_id": scope_id if scope_type == "department" else None,
        "team_id": scope_id if scope_type == "team" else None,
        "employee_id": scope_id if scope_type == "employee" else None,
    }
    duplicate = db.scalar(
        select(RoleAssignment.id).where(
            RoleAssignment.user_id == user_id,
            RoleAssignment.role_id == role.id,
            RoleAssignment.scope_type == scope_type,
            *(getattr(RoleAssignment, name) == value for name, value in columns.items() if value),
        )
    )
    if duplicate is not None:
        raise RoleError("this person already holds this role for this scope")

    assignment = RoleAssignment(user_id=user_id, role_id=role.id, scope_type=scope_type, **columns)
    db.add(assignment)
    db.flush()
    record(
        db,
        actor=actor,
        action="role_assignment.added",
        target_type="user",
        target_id=user_id,
        details={
            "role": role.built_in or role.name,
            "scope_type": scope_type,
            "scope_id": str(scope_id) if scope_id else None,
        },
    )
    return assignment
