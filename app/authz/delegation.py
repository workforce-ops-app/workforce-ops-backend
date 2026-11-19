"""The delegation limits: who may change a role, and who may give one to whom
(authorization.md, delegation limits; decision 0032).

Access is handed down from the owner one layer at a time. These functions answer the
questions the role and role-assignment services ask before they change anything:

- what_role_grants():   the permission codes a role grants (the Owner: every one);
- holders():            who holds a role right now, read fresh;
- above_every_holder(): may this user change the role? Only if every holder is below them
                        (rule AZ13), or they are an owner (any role but Owner);
- scope_of():           the place an assignment applies to, as a Scope that authorize()'s
                        covers() understands;
- held_for():           the permissions the user holds for that place (rules AZ3, AZ4: a
                        role can only be given where the giver holds all of it);
- is_same_level():      would giving this role make someone the giver's equal there? Then
                        it needs approval from above (AZ14).

Reads made after the company's lock (chain.lock_reporting_lines) use locking reads (FOR
SHARE), so they see what other requests committed while this one waited (the reason is on
chain.is_above_in_chain_fresh).
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authz.chain import is_above_in_chain_fresh
from app.authz.check import effective_permissions, grants, is_owner
from app.authz.models import Role, RoleAssignment, RolePermission
from app.authz.registry import all_permissions
from app.authz.scope import Scope, covers, person_scope
from app.modules.org.models import Department, Team, User


def what_role_grants(db: Session, role: Role) -> set[str]:
    """The permission codes the role grants. The Owner role grants every registered
    permission, whatever its rows say (authorization.md, starting roles)."""
    if role.built_in == "owner":
        return set(all_permissions())
    return set(
        db.scalars(select(RolePermission.permission_code).where(RolePermission.role_id == role.id))
    )


def holders(db: Session, role_id: uuid.UUID) -> set[uuid.UUID]:
    """Everyone with an assignment of the role, deactivated people included (they would get
    it back if reactivated), read fresh (FOR SHARE)."""
    return set(
        db.scalars(
            select(RoleAssignment.user_id)
            .where(RoleAssignment.role_id == role_id)
            .with_for_update(read=True)
        )
    )


def above_every_holder(db: Session, user: User, role: Role) -> bool:
    """Whether the user may change, rename, or archive the role (AZ13).

    An owner may change any role except Owner (the caller refuses Owner first). Anyone
    else must be above every current holder in the reporting chain, so nobody reshapes a
    role held by a peer, a superior, or themselves. A role nobody holds can be changed by
    anyone with role.manage: it reaches nobody yet.
    """
    if is_owner(db, user):
        return True
    return all(
        holder != user.id and is_above_in_chain_fresh(db, user.id, holder)
        for holder in holders(db, role.id)
    )


def scope_of(db: Session, scope_type: str, scope_id: uuid.UUID | None) -> Scope | None:
    """Where an assignment applies, as a Scope; None for the whole company.

    - a department:  the department itself;
    - a team:        the team, and the department it belongs to (a department grant
                     covers its teams);
    - one employee:  that person as authorize() sees them: their home department, their
                     teams, and themselves.
    The caller has already checked that the department, team, or person exists.
    """
    if scope_type == "company" or scope_id is None:
        return None
    if scope_type == "department":
        return Scope(frozenset({scope_id}), frozenset(), None)
    if scope_type == "team":
        team = db.get(Team, scope_id)
        departments = frozenset({team.department_id}) if team is not None else frozenset()
        return Scope(departments, frozenset({scope_id}), None)
    person = db.get(User, scope_id)
    return person_scope(db, person) if person is not None else Scope(frozenset(), frozenset(), None)


def held_for(db: Session, user: User, codes: set[str], scope: Scope | None) -> set[str]:
    """Which of these permission codes the user holds for the whole of `scope`.

    The whole company (scope None) needs a company-wide grant; anywhere else, a grant whose
    scope covers it (the same covers() authorize() uses). A department grant therefore
    holds for its teams and its people, but never for the whole company (AZ4).
    """
    held = set()
    for code in codes:
        found = grants(db, user, code)
        if scope is None:
            if any(grant.scope_type == "company" for grant in found):
                held.add(code)
        elif any(covers(grant, scope) for grant in found):
            held.add(code)
    return held


def place_problem(
    db: Session, scope_type: str, scope_id: uuid.UUID | None
) -> tuple[int, str] | None:
    """Why an assignment's place is not acceptable, as (status, message), or None.

    422 for a place that does not exist: the company filter hides other companies' rows,
    so another company's department looks the same as a missing one. 409 for an archived
    department or team, which covers nothing (authorization.md), or a deactivated person.
    """
    if scope_type == "company":
        return None if scope_id is None else (422, "A company-wide role has no scope_id.")
    if scope_id is None:
        return 422, "Say where the role applies (scope_id)."
    model = {"department": Department, "team": Team, "employee": User}[scope_type]
    found = db.get(model, scope_id)
    if found is None:
        return 422, f"Unknown {scope_type}."
    if getattr(found, "archived_at", None) is not None:
        return 409, f"This {scope_type} is archived."
    if getattr(found, "deactivated_at", None) is not None:
        return 409, "This person is deactivated."
    return None


def is_same_level(db: Session, user: User, codes: set[str], scope: Scope | None) -> bool:
    """Whether a role granting `codes` at this place would put its receiver at the giver's
    own level there: it includes ALL of the permissions the giver holds for that place
    (decision 0032). Such a grant waits for approval from above the giver (AZ14).

    An owner is never "at their own level" with anyone: nobody is above an owner to
    approve, and an owner may give any role but Owner (which goes through the owner
    change flow instead).
    """
    if is_owner(db, user):
        return False
    mine_here = held_for(db, user, set(effective_permissions(db, user)), scope)
    return mine_here <= codes


def is_above_fresh(db: Session, user: User, person: User) -> bool:
    """Whether the user is above the person, on fresh reads, for checks made after the
    company's lock: an owner always; anyone else through current lines (a line ended while
    the request waited counts). Nobody is above themselves."""
    if user.id == person.id or user.deactivated_at is not None:
        return False
    return is_owner(db, user) or is_above_in_chain_fresh(db, user.id, person.id)
