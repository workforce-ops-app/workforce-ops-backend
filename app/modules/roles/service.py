"""The rules for a company's roles (authorization.md, delegation limits; decision 0032).

Seeing roles needs role.view (company-wide: Owner and Administrator). Creating, changing,
and archiving them needs role.manage (company-wide), and then the delegation limits:

- AZ3: nobody makes a role grant a permission they do not hold themselves. Creating a
  role, or adding a permission to one, only allows codes the user holds somewhere.
- AZ13: a role can be changed, renamed, or archived only by someone above EVERY current
  holder in the reporting chain, or by an owner. So nobody reshapes a role held by a
  peer, a superior, or themselves. A new role has no holders, so creating one needs only
  role.manage.
- AZ9: the Owner role is locked: its permissions, its name, and its state never change.
- Changing what a role grants (adding or removing a permission, or archiving it, which
  takes everything away from its holders) is a sensitive action: the password must have
  been entered again in this session within the last 5 minutes (decision 0025).
- Names are unique within the company, ignoring case, archived roles included (409).
  A company has at most 200 roles, so the list stays one page.

Every change writes its audit entry in the same transaction (AZ12) and commits once.

Before checking or adding a role's grants, the service fills the permissions table from
the registry (sync_permissions, agreed in #81): a module added after the company was
created brings new permissions, and a role edit must be able to grant them without
anyone reseeding the database.

Role changes take turns with each other, with role assignments, and with reporting-line
changes, through the company's lock (chain.lock_reporting_lines). After taking it,
everything the change depends on is read fresh (locking reads, FOR SHARE), because under
MySQL's REPEATABLE READ an ordinary read would still show the database from before the
wait:
- the user's own permissions and owner role (authorize and AZ3 again, fresh=True), so
  access taken away while they waited stops the change;
- the holders and the chain (app/authz/delegation.py), so a role given to a peer, or a
  line ended, meanwhile is seen;
- what the role grants now, so two edits in a row each start from the other's result;
- the number of roles, so two creations cannot both pass the limit.
The checks before the lock stay: they answer quickly without waiting for the lock.
"""

import uuid

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.auth.models import UserSession
from app.auth.reauth import require_reauth
from app.authz.chain import lock_reporting_lines
from app.authz.check import Forbidden, authorize, effective_permissions
from app.authz.delegation import above_every_holder, what_role_grants
from app.authz.models import Role, RolePermission
from app.authz.registry import PermissionDef, all_permissions, sync_permissions
from app.db.base import utcnow
from app.modules.org.models import User
from app.modules.org.service import Conflict, Invalid, NotFound, saved_or_conflict
from app.modules.roles.schemas import RoleCreate, RoleUpdate

# At most this many roles per company, archived ones included.
MAX_ROLES = 200

ROLE_NAME_TAKEN = "A role with this name already exists."
OWNER_LOCKED = "The Owner role cannot be changed."


# --- Seeing roles ----------------------------------------------------------------------


def granted(db: Session, role: Role) -> list[str]:
    """What the role grants, sorted, for the answer to a change (the change itself was
    allowed, so no second permission check)."""
    return sorted(what_role_grants(db, role))


def list_permissions(db: Session, user: User) -> list[PermissionDef]:
    """Every permission a role can grant, by code (for the screen that edits roles)."""
    authorize(db, user, "role.view")
    return sorted(all_permissions().values(), key=lambda p: p.code)


def list_roles(db: Session, user: User) -> list[tuple[Role, list[str]]]:
    """Every role of the company, archived ones included, by name, with what each grants."""
    authorize(db, user, "role.view")
    roles = list(db.scalars(select(Role).order_by(func.lower(Role.name), Role.id)))
    return [(role, sorted(what_role_grants(db, role))) for role in roles]


def view_role(db: Session, user: User, role_id: uuid.UUID) -> tuple[Role, list[str]]:
    """One role and what it grants."""
    authorize(db, user, "role.view")
    role = db.get(Role, role_id)
    if role is None:
        raise NotFound()  # unknown, or another company's
    return role, sorted(what_role_grants(db, role))


# --- Shared checks ---------------------------------------------------------------------


def _known_codes(db: Session, codes: list[str]) -> set[str]:
    """The codes as a set, after filling the permissions table from the registry; an
    unknown code is refused (422) rather than silently dropped."""
    sync_permissions(db)  # a permission added by a newer module exists before it is granted
    wanted = set(codes)
    unknown = sorted(wanted - set(all_permissions()))
    if unknown:
        raise Invalid(f"Unknown permission: {unknown[0]}.")
    return wanted


def _only_what_they_hold(db: Session, user: User, codes: set[str], *, fresh: bool = False) -> None:
    """AZ3: every code must be one the user holds themselves (somewhere). 403 otherwise,
    with the same message as every other refusal, so it does not list what they lack.
    fresh=True for the check after the company's lock (the top of this file)."""
    if not codes <= set(effective_permissions(db, user, fresh=fresh)):
        raise Forbidden()


def _changeable_role(db: Session, user: User, role_id: uuid.UUID) -> Role:
    """The role, locked for this change, if the user may change it at all.

    1. Allowed to manage roles at all (403), and the role exists in the company (404).
    2. Not the Owner role (409, AZ9), and not archived (409).
    3. The company's lock, so role changes take turns (the top of this file), then
       role.manage checked again on fresh reads (403), the role read fresh, and the holder
       check on fresh reads (AZ13, 403).
    """
    authorize(db, user, "role.manage")
    role = db.get(Role, role_id)
    if role is None:
        raise NotFound()
    if role.built_in == "owner":
        raise Conflict(OWNER_LOCKED)
    lock_reporting_lines(db)
    # Still allowed? Permissions taken away while this request waited count.
    authorize(db, user, "role.manage", fresh=True)
    role = db.get(Role, role_id, populate_existing=True, with_for_update=True)
    if role is None:  # roles are never deleted
        raise NotFound()
    if role.archived_at is not None:
        raise Conflict("This role is archived. It cannot be changed.")
    if not above_every_holder(db, user, role):
        raise Forbidden()
    return role


def _name_taken(db: Session, name: str, except_id: uuid.UUID | None = None) -> bool:
    """Whether another role of the company has this name, ignoring case (as MySQL does)."""
    found = db.scalar(select(Role.id).where(func.lower(Role.name) == name.lower()).limit(1))
    return found is not None and found != except_id


# --- Changing roles --------------------------------------------------------------------


def create_role(db: Session, user: User, body: RoleCreate) -> Role:
    """Create a role granting body.permissions. Nobody holds it yet."""
    # 1. Permission first, then what the role would grant (AZ3).
    authorize(db, user, "role.manage")
    codes = _known_codes(db, body.permissions)
    _only_what_they_hold(db, user, codes)
    # 2. Take turns with other role changes before the count and name checks.
    lock_reporting_lines(db)
    # 3. Checked again on fresh reads (the top of this file): still allowed, still holds
    #    every code, and the count includes roles created while this request waited.
    authorize(db, user, "role.manage", fresh=True)
    _only_what_they_hold(db, user, codes, fresh=True)
    count = select(func.count(Role.id)).with_for_update(read=True)  # FOR SHARE: newest rows
    if (db.scalar(count) or 0) >= MAX_ROLES:
        raise Conflict(f"A company can have at most {MAX_ROLES} roles.")
    if _name_taken(db, body.name):
        raise Conflict(ROLE_NAME_TAKEN)

    role = Role(name=body.name)
    with saved_or_conflict(db, ROLE_NAME_TAKEN):
        db.add(role)
        db.flush()  # gives the role its ID (a name taken meanwhile is refused here)
        db.add_all(RolePermission(role_id=role.id, permission_code=code) for code in codes)
        record(
            db,
            actor=Actor.user(user.id),
            action="role.created",
            target_type="role",
            target_id=role.id,
            details={"name": role.name, "built_in": None, "permissions": sorted(codes)},
        )
    return role


def update_role(
    db: Session, user: User, role_id: uuid.UUID, body: RoleUpdate, *, session: UserSession
) -> Role:
    """Rename a role, or replace what it grants. Only the fields sent change."""
    fields = body.model_fields_set
    if "name" in fields and body.name is None:
        raise Invalid("A role must have a name.")
    if "permissions" in fields and body.permissions is None:
        raise Invalid("Send the full list of permissions, or leave it out.")

    # 1. The new list is checked before anything is locked: unknown codes (422), and codes
    #    the user does not hold (403, AZ3). Codes being removed need no check: the user is
    #    above everyone who holds the role, or they could not change it.
    wanted = _known_codes(db, body.permissions) if body.permissions is not None else None
    role = _changeable_role(db, user, role_id)
    # What the role grants now, read fresh: another edit may have committed while this one
    # waited for the lock, and added/removed must be worked out from its result.
    current = what_role_grants(db, role, fresh=True)
    added = sorted(wanted - current) if wanted is not None else []
    removed = sorted(current - wanted) if wanted is not None else []
    # AZ3 on fresh reads too: a code the user lost while waiting cannot be added.
    _only_what_they_hold(db, user, set(added), fresh=True)
    # 2. Changing what a role grants needs the password re-entered (decision 0025).
    if added or removed:
        require_reauth(session)

    renamed = body.name is not None and body.name != role.name
    if renamed and body.name is not None and _name_taken(db, body.name, except_id=role.id):
        raise Conflict(ROLE_NAME_TAKEN)

    actor = Actor.user(user.id)
    with saved_or_conflict(db, ROLE_NAME_TAKEN):
        if renamed and body.name is not None:
            old_name, role.name = role.name, body.name
            record(
                db,
                actor=actor,
                action="role.renamed",
                target_type="role",
                target_id=role.id,
                details={"from": old_name, "to": role.name},
            )
        if added:
            db.add_all(RolePermission(role_id=role.id, permission_code=code) for code in added)
            record(
                db,
                actor=actor,
                action="role.permission_added",
                target_type="role",
                target_id=role.id,
                details={"permissions": added},
            )
        if removed:
            db.execute(
                delete(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_code.in_(removed),
                )
            )
            record(
                db,
                actor=actor,
                action="role.permission_removed",
                target_type="role",
                target_id=role.id,
                details={"permissions": removed},
            )
    return role


def archive_role(db: Session, user: User, role_id: uuid.UUID, *, session: UserSession) -> Role:
    """Archive a role: it stays for history, but grants nothing to anyone from now on."""
    role = _changeable_role(db, user, role_id)
    # Archiving takes everything the role grants away from its holders: sensitive.
    require_reauth(session)
    role.archived_at = utcnow()
    record(
        db,
        actor=Actor.user(user.id),
        action="role.archived",
        target_type="role",
        target_id=role.id,
        details={"name": role.name},
    )
    db.commit()
    return role
