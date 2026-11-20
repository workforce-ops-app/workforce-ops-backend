"""The rules for giving and removing roles (authorization.md, delegation limits; 0032).

Seeing someone's roles needs user.view covering them (managers see the roles of their
people; agreed in #81); everyone may see their own. Giving or removing a role needs
role.assign over the person, and then:

- AZ1: nobody changes their own role assignments (authorize() refuses a person
  permission aimed at yourself).
- AZ5: only for people you are above in the reporting chain (authorize() checks it).
- AZ3 and AZ4: you hold every permission of the role for the whole place it applies to.
  A department manager cannot give a company-wide role, nor a role with a permission
  they lack. Removing a role follows the same rule: you can only take away what you
  could have given.
- AZ14: a role that includes ALL of your own permissions for that place would make the
  person your equal there. It is not given: an approval request is opened instead (202),
  and the role is created only when someone above you approves it.
- The Owner role is never given or removed here: owners change through the owner change
  flow, with the other owners' approval (AZ8, AZ15; slice Z5).
- Giving or removing a role that includes an admin-level permission (user.manage,
  role.manage, role.assign, reporting_line.manage, settings.manage) needs the password
  entered again (decision 0025).
- Deactivated people are not given roles (409); archived roles, departments, and teams
  are not given either (409), since they grant nothing.

Every change writes its audit entry (AZ12) and commits once. Changes take turns through
the company's lock (chain.lock_reporting_lines), shared with role and reporting-line
changes; after it, the chain, the duplicates, and the pending requests are read fresh.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import open_request, pending_like
from app.audit import Actor, record
from app.auth.models import UserSession
from app.auth.reauth import require_reauth
from app.authz.chain import lock_reporting_lines
from app.authz.check import ADMIN_LEVEL, Forbidden, authorize
from app.authz.delegation import (
    held_for,
    is_above_fresh,
    is_same_level,
    place_problem,
    scope_of,
    what_role_grants,
)
from app.authz.models import Role, RoleAssignment
from app.authz.roles import assign_role
from app.authz.scope import Scope
from app.modules.org import repository
from app.modules.org.models import User
from app.modules.org.service import Conflict, Invalid, NotFound
from app.modules.roles.schemas import AssignmentCreate

OWNER_FLOW = "Owners are added and removed through the owner change flow."


def scope_id_of(assignment: RoleAssignment) -> uuid.UUID | None:
    """The department, team, or employee an assignment applies to (None: the company)."""
    return assignment.department_id or assignment.team_id or assignment.employee_id


# --- Seeing roles held -----------------------------------------------------------------


def list_for(db: Session, user: User, person_id: uuid.UUID) -> list[tuple[RoleAssignment, Role]]:
    """The roles one person holds, with their scopes: your own, or someone in your
    user.view scope (403 otherwise; 404 for an unknown person or another company's)."""
    person = repository.person(db, person_id)
    if person is None:
        raise NotFound()
    if person.id != user.id:
        authorize(db, user, "user.view", person)
    rows = db.execute(
        select(RoleAssignment, Role)
        .join(Role, Role.id == RoleAssignment.role_id)
        .where(RoleAssignment.user_id == person.id)
        .order_by(Role.name, RoleAssignment.id)
    )
    return [(row[0], row[1]) for row in rows]


# --- Shared checks ---------------------------------------------------------------------


def _person_to_act_on(db: Session, user: User, person_id: uuid.UUID) -> User:
    """The person, if the user holds role.assign over them (AZ1, AZ5): 404 or 403 otherwise.
    Unknown people in a body are 422, like any unknown reference."""
    person = repository.person(db, person_id)
    if person is None:
        raise Invalid("Unknown person.")
    authorize(db, user, "role.assign", person)
    return person


def _may_give_all_of(db: Session, user: User, codes: set[str], scope: Scope | None) -> None:
    """AZ3 and AZ4: the user holds every code for the whole place (403 otherwise, with the
    same message as every refusal, so it does not list what they lack)."""
    if held_for(db, user, codes, scope) != codes:
        raise Forbidden()


def _still_above(db: Session, user: User, person: User) -> None:
    """After the company's lock: the user is still above the person, on fresh reads (a
    line ended while this request waited counts). 403 otherwise."""
    if not is_above_fresh(db, user, person):
        raise Forbidden()


def _sensitive(codes: set[str]) -> bool:
    """Whether giving or removing a role with these codes is an admin-level change."""
    return not ADMIN_LEVEL.isdisjoint(codes)


# --- Giving a role ---------------------------------------------------------------------


@dataclass
class Given:
    """The result of giving a role: the assignment, or (assignment None) the request
    waiting for approval."""

    role: Role
    assignment: RoleAssignment | None = None
    request: ApprovalRequest | None = None


def give(db: Session, user: User, body: AssignmentCreate, *, session: UserSession) -> Given:
    """Give a person a role for one place, or ask for approval when it is at the giver's
    own level (the rules at the top of this file)."""
    # 1. Over whom: role.assign, someone else, and someone the user is above.
    person = _person_to_act_on(db, user, body.user_id)
    if person.deactivated_at is not None:
        raise Conflict("This person is deactivated.")
    # 2. Which role, and where.
    role = db.get(Role, body.role_id)
    if role is None:
        raise Invalid("Unknown role.")
    if role.built_in == "owner":
        raise Conflict(OWNER_FLOW)
    if role.archived_at is not None:
        raise Conflict("This role is archived.")
    problem = place_problem(db, body.scope_type, body.scope_id)
    if problem is not None:
        status, message = problem
        raise Conflict(message) if status == 409 else Invalid(message)
    scope = scope_of(db, body.scope_type, body.scope_id)
    # 3. Only what the user holds there (AZ3, AZ4).
    codes = what_role_grants(db, role)
    _may_give_all_of(db, user, codes, scope)
    # 4. Admin-level roles need the password entered again.
    if _sensitive(codes):
        require_reauth(session)

    # 5. Take turns, then check again on fresh reads.
    lock_reporting_lines(db)
    _still_above(db, user, person)
    if _holds_already(db, person.id, role.id, body.scope_type, body.scope_id):
        raise Conflict("This person already holds this role there.")
    payload = {
        "role_id": str(role.id),
        "scope_type": body.scope_type,
        "scope_id": str(body.scope_id) if body.scope_id else None,
    }
    if pending_like(db, "role_assignment", person.id, payload) is not None:
        raise Conflict("This role is already waiting for approval for this person.")

    # 6. At the giver's own level: ask for approval instead (AZ14).
    if is_same_level(db, user, codes, scope):
        request = open_request(
            db,
            kind="role_assignment",
            requested_by=user.id,
            subject_user_id=person.id,
            payload=payload,
            details={
                "role": role.built_in or role.name,
                "scope_type": body.scope_type,
                "scope_id": payload["scope_id"],
            },
        )
        db.commit()
        return Given(role, request=request)

    assignment = assign_role(
        db,
        Actor.user(user.id),
        user_id=person.id,
        role=role,
        scope_type=body.scope_type,
        scope_id=body.scope_id,
    )
    db.commit()
    return Given(role, assignment=assignment)


def _holds_already(
    db: Session,
    person_id: uuid.UUID,
    role_id: uuid.UUID,
    scope_type: str,
    scope_id: uuid.UUID | None,
) -> bool:
    """Whether the person already holds the role for this place, read fresh (FOR SHARE)."""
    rows = db.scalars(
        select(RoleAssignment)
        .where(
            RoleAssignment.user_id == person_id,
            RoleAssignment.role_id == role_id,
            RoleAssignment.scope_type == scope_type,
        )
        .with_for_update(read=True)
    )
    return any(scope_id_of(row) == scope_id for row in rows)


# --- Removing a role -------------------------------------------------------------------


def remove(db: Session, user: User, assignment_id: uuid.UUID, *, session: UserSession) -> None:
    """Take a role away from a person. The assignment is deleted; the audit entry keeps
    its history."""
    # 1. Which assignment (404), and over whom (role.assign over the holder: AZ1, AZ5).
    assignment = db.get(RoleAssignment, assignment_id)
    if assignment is None:
        raise NotFound()
    holder = repository.person(db, assignment.user_id)
    if holder is None:  # people are never deleted
        raise NotFound()
    authorize(db, user, "role.assign", holder)
    role = db.get(Role, assignment.role_id)
    if role is None:
        raise NotFound()
    if role.built_in == "owner":
        raise Conflict(OWNER_FLOW)
    # 2. Only what the user could have given (AZ3, AZ4), with re-entry for admin level.
    codes = what_role_grants(db, role)
    _may_give_all_of(db, user, codes, scope_of(db, assignment.scope_type, scope_id_of(assignment)))
    if _sensitive(codes):
        require_reauth(session)

    # 3. Take turns, then check again on fresh reads: still there, still above.
    lock_reporting_lines(db)
    assignment = db.get(RoleAssignment, assignment_id, populate_existing=True, with_for_update=True)
    if assignment is None:
        raise NotFound()  # removed by someone else meanwhile
    _still_above(db, user, holder)
    scope_id = scope_id_of(assignment)
    db.delete(assignment)
    record(
        db,
        actor=Actor.user(user.id),
        action="role_assignment.removed",
        target_type="user",
        target_id=holder.id,
        details={
            "role": role.built_in or role.name,
            "scope_type": assignment.scope_type,
            "scope_id": str(scope_id) if scope_id else None,
        },
    )
    db.commit()
