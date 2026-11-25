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
from app.authz.check import effective_permissions, grants, is_above, is_owner
from app.authz.models import Role, RoleAssignment, RolePermission
from app.authz.registry import all_permissions
from app.authz.scope import Scope, covers, person_scope
from app.modules.org.models import Department, Team, User


def what_role_grants(db: Session, role: Role, *, fresh: bool = False) -> set[str]:
    """The permission codes the role grants. The Owner role grants every registered
    permission, whatever its rows say (authorization.md, starting roles).

    fresh=True reads the rows with a locking read (FOR SHARE), for a change made after the
    company's lock: an ordinary read could still show the grants from before another
    change committed while this one waited, and the change would then add or remove the
    wrong codes (the top of this file).
    """
    if role.built_in == "owner":
        return set(all_permissions())
    query = select(RolePermission.permission_code).where(RolePermission.role_id == role.id)
    if fresh:
        query = query.with_for_update(read=True)  # FOR SHARE: the newest committed rows
    return set(db.scalars(query))


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
    # Fresh, like the holders below: an owner removed while this request waited is no
    # longer an owner.
    if is_owner(db, user, fresh=True):
        return True
    return all(
        holder != user.id and is_above_in_chain_fresh(db, user.id, holder)
        for holder in holders(db, role.id)
    )


def _get[M](db: Session, model: type[M], row_id: uuid.UUID, fresh: bool) -> M | None:
    """One row by ID. fresh=True makes it a locking read (FOR SHARE) that replaces the copy
    this session holds, so it shows the newest committed version (the top of this file)."""
    if fresh:
        return db.get(model, row_id, with_for_update={"read": True}, populate_existing=True)
    return db.get(model, row_id)


def scope_of(
    db: Session, scope_type: str, scope_id: uuid.UUID | None, *, fresh: bool = False
) -> Scope | None:
    """Where an assignment applies, as a Scope; None for the whole company.

    - a department:  the department itself;
    - a team:        the team, and the department it belongs to (a department grant
                     covers its teams);
    - one employee:  that person as authorize() sees them: their home department, their
                     teams, and themselves.
    The caller has already checked that the department, team, or person exists. fresh=True
    reads the team or the person with locking reads, for a check after the company's lock.
    """
    if scope_type == "company" or scope_id is None:
        return None
    if scope_type == "department":
        return Scope(frozenset({scope_id}), frozenset(), None)
    if scope_type == "team":
        team = _get(db, Team, scope_id, fresh)
        departments = frozenset({team.department_id}) if team is not None else frozenset()
        return Scope(departments, frozenset({scope_id}), None)
    person = _get(db, User, scope_id, fresh)
    if person is None:
        return Scope(frozenset(), frozenset(), None)
    return person_scope(db, person, fresh=fresh)


def held_for(
    db: Session, user: User, codes: set[str], scope: Scope | None, *, fresh: bool = False
) -> set[str]:
    """Which of these permission codes the user holds for the whole of `scope`.

    The whole company (scope None) needs a company-wide grant; anywhere else, a grant whose
    scope covers it (the same covers() authorize() uses). A department grant therefore
    holds for its teams and its people, but never for the whole company (AZ4). fresh=True
    reads the user's grants with locking reads, for a check after the company's lock.
    """
    held = set()
    for code in codes:
        found = grants(db, user, code, fresh=fresh)
        if scope is None:
            if any(grant.scope_type == "company" for grant in found):
                held.add(code)
        elif any(covers(grant, scope) for grant in found):
            held.add(code)
    return held


def place_problem(
    db: Session, scope_type: str, scope_id: uuid.UUID | None, *, fresh: bool = False
) -> tuple[int, str] | None:
    """Why an assignment's place is not acceptable, as (status, message), or None.

    422 for a place that does not exist: the company filter hides other companies' rows,
    so another company's department looks the same as a missing one. 409 for an archived
    department or team, which covers nothing (authorization.md), or a deactivated person.
    fresh=True reads the place with a locking read, so a place archived (or a person
    deactivated) while the request waited for the company's lock is seen.
    """
    if scope_type == "company":
        return None if scope_id is None else (422, "A company-wide role has no scope_id.")
    if scope_id is None:
        return 422, "Say where the role applies (scope_id)."
    found: Department | Team | User | None
    if scope_type == "department":
        found = _get(db, Department, scope_id, fresh)
    elif scope_type == "team":
        found = _get(db, Team, scope_id, fresh)
    else:
        found = _get(db, User, scope_id, fresh)
    if found is None:
        return 422, f"Unknown {scope_type}."
    if getattr(found, "archived_at", None) is not None:
        return 409, f"This {scope_type} is archived."
    if getattr(found, "deactivated_at", None) is not None:
        return 409, "This person is deactivated."
    return None


def is_same_level(
    db: Session, user: User, codes: set[str], scope: Scope | None, *, fresh: bool = False
) -> bool:
    """Whether a role granting `codes` at this place would put its receiver at the giver's
    own level there: it includes ALL of the permissions the giver holds for that place
    (decision 0032). Such a grant waits for approval from above the giver (AZ14).

    An owner is never "at their own level" with anyone: nobody is above an owner to
    approve, and an owner may give any role but Owner (which goes through the owner
    change flow instead).

    fresh=True reads the giver's owner role and permissions with locking reads: a giver
    who lost permissions while the request waited may now be at the receiver's level, and
    the grant must then wait for approval instead of going straight through.
    """
    if is_owner(db, user, fresh=fresh):
        return False
    mine = set(effective_permissions(db, user, fresh=fresh))
    mine_here = held_for(db, user, mine, scope, fresh=fresh)
    return mine_here <= codes


def is_above_fresh(db: Session, user: User, person: User) -> bool:
    """Whether the user is above the person, on fresh reads, for checks made after the
    company's lock: an owner always; anyone else through current lines (a line ended while
    the request waited counts). Nobody is above themselves.

    The user's own row and owner role are read fresh too (check.is_above with fresh=True):
    an owner removed, or a user deactivated, while the request waited is above nobody."""
    return is_above(db, user, person, fresh=True)


def active_owners(db: Session, *, fresh: bool) -> set[uuid.UUID]:
    """The company's owners: people with the Owner role for the whole company who are not
    deactivated. fresh=True reads them with locking reads (FOR SHARE), for checks after
    the company's lock (the last owner, who must agree to an owner change); fresh=False
    is an ordinary read, for listing and for checks before the lock, which must not hold
    or wait for row locks (the top of this file; review of #163)."""
    query = (
        select(RoleAssignment.user_id, Role.id)
        .join(Role, Role.id == RoleAssignment.role_id)
        .where(Role.built_in == "owner", RoleAssignment.scope_type == "company")
    )
    holders = db.scalars(query.with_for_update(read=True) if fresh else query)
    owners = set()
    for person_id in set(holders):
        person = _get(db, User, person_id, fresh)  # deactivated meanwhile counts
        if person is not None and person.deactivated_at is None:
            owners.add(person_id)
    return owners
