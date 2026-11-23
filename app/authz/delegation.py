"""The delegation limits: who may change a role, and who may give one to whom
(authorization.md, delegation limits; decision 0032).

Access is handed down from the owner one layer at a time. These functions answer the
questions the role and role-assignment services ask before they change anything:

- what_role_grants():   the permission codes a role grants (the Owner: every one);
- holders():            who holds a role right now, read fresh;
- above_every_holder(): may this user change the role? Only if every holder is below them
                        (rule AZ13), or they are an owner (any role but Owner).

Giving roles to people (AZ1, AZ3, AZ4, AZ14) adds its checks here with the role
assignment endpoints (the rest of slice Z4).

Reads made after the company's lock (chain.lock_reporting_lines) use locking reads (FOR
SHARE), so they see what other requests committed while this one waited (the reason is on
chain.is_above_in_chain_fresh).
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authz.chain import is_above_in_chain_fresh
from app.authz.check import is_owner
from app.authz.models import Role, RoleAssignment, RolePermission
from app.authz.registry import all_permissions
from app.modules.org.models import User


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
