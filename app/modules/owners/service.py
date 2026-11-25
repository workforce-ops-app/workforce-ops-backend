"""The rules for adding and removing a company's owners (authorization.md, delegation
limits; decision 0032; rules AZ8, AZ9, AZ15).

Owners hold everything, so owner changes are the strictest:

- Only an owner proposes one (company.transfer_ownership, which only the Owner role
  grants), always with the password entered again.
- Adding an owner needs every current owner. The owner who proposes it counts as
  agreeing, so with one owner it happens at once; with several, a request (202) waits
  until every other owner approves.
- Removing an owner needs every owner except the one being removed, so nobody can block
  their own removal. The proposer counts as agreeing here too: with two owners, either
  may remove the other at once, and with three or more, the others must approve.
- Never the last owner (AZ8): removing the only owner is refused (409), on fresh reads,
  both when asked and again when the last approval arrives.
- After the company's lock everything is read again with locking reads: the proposer's
  permission, the owners, and the person (locked, so a deactivation cannot race with
  making them an owner).
- The Owner role itself never changes (AZ9, app/modules/roles/service.py); it is given
  and taken only here.

Everything is audited: ownership.owner_added and ownership.owner_removed when a change
takes effect, and the approval entries for requests. Changes take turns through the
company's lock (chain.lock_reporting_lines), and the owners are then read fresh.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import DecisionError, open_request, pending_like
from app.audit import Actor, record
from app.auth.models import UserSession
from app.auth.reauth import require_reauth
from app.authz.chain import lock_reporting_lines
from app.authz.check import authorize
from app.authz.delegation import active_owners
from app.authz.models import Role, RoleAssignment
from app.authz.roles import assign_role
from app.modules.org import repository
from app.modules.org.models import User
from app.modules.org.service import Conflict, Invalid, NotFound

PERMISSION = "company.transfer_ownership"
LAST_OWNER = "A company always has at least one owner."


def _owner_role(db: Session) -> Role:
    role = db.scalars(select(Role).where(Role.built_in == "owner")).one_or_none()
    if role is None:  # every company is created with one
        raise RuntimeError("the company has no Owner role")
    return role


def list_owners(db: Session, user: User) -> list[User]:
    """The company's owners, by name (role.view: the people who manage roles)."""
    authorize(db, user, "role.view")
    people = [db.get(User, person_id) for person_id in active_owners(db, fresh=False)]
    return sorted((p for p in people if p is not None), key=lambda p: (p.display_name, p.id))


# --- Making the change (also used when a request is approved) --------------------------


def make_owner(db: Session, actor: Actor, person: User) -> None:
    """Give the person the Owner role for the whole company; audited. Caller commits."""
    if person.deactivated_at is not None:
        raise DecisionError("This person is deactivated.")
    if person.id in active_owners(db, fresh=True):
        raise DecisionError("This person is already an owner.")
    assign_role(db, actor, user_id=person.id, role=_owner_role(db), scope_type="company")
    record(db, actor=actor, action="ownership.owner_added", target_type="user", target_id=person.id)


def unmake_owner(db: Session, actor: Actor, person: User) -> None:
    """Take the Owner role away from the person; audited. Never the last owner. Their
    other roles stay. Caller commits."""
    owners = active_owners(db, fresh=True)
    if person.id not in owners:
        raise DecisionError("This person is not an owner.")
    if len(owners) <= 1:
        raise DecisionError(LAST_OWNER)
    db.execute(
        delete(RoleAssignment).where(
            RoleAssignment.user_id == person.id, RoleAssignment.role_id == _owner_role(db).id
        )
    )
    record(
        db, actor=actor, action="ownership.owner_removed", target_type="user", target_id=person.id
    )


# --- Proposing a change ----------------------------------------------------------------


@dataclass
class Proposed:
    """Done at once (request None), or waiting for the other owners (request set)."""

    request: ApprovalRequest | None = None


def locked_person(db: Session, person_id: uuid.UUID) -> User | None:
    """The person's row, locked (SELECT ... FOR UPDATE) and read fresh. Deactivation locks
    the same row (app/modules/org/people.py), so the two take turns: a deactivation
    committed first is seen here, and one that comes later waits, then sees an owner and
    is refused. Taken after the company's lock and before any audit entry (the lock order
    in chain.lock_reporting_lines)."""
    return db.get(User, person_id, with_for_update=True, populate_existing=True)


def _proposer_and_person(
    db: Session, user: User, person_id: uuid.UUID, session: UserSession
) -> User:
    """Checks before the company's lock (ordinary reads), the lock, then the same checks
    again on fresh reads: an owner removed while this request waited proposes nothing,
    and the person is the newest committed row, locked (review of #165)."""
    authorize(db, user, PERMISSION)  # owners only; no row lock held or waited for yet
    if repository.person(db, person_id) is None:
        raise Invalid("Unknown person.")
    require_reauth(session)
    lock_reporting_lines(db)
    authorize(db, user, PERMISSION, fresh=True)
    person = locked_person(db, person_id)
    if person is None:  # people are never deleted
        raise Invalid("Unknown person.")
    return person


def add_owner(db: Session, user: User, person_id: uuid.UUID, *, session: UserSession) -> Proposed:
    """Propose a new owner: at once with one owner, else every other owner must approve."""
    person = _proposer_and_person(db, user, person_id, session)
    owners = active_owners(db, fresh=True)
    if person.deactivated_at is not None:
        raise Conflict("This person is deactivated.")
    if person.id in owners:
        raise Conflict("This person is already an owner.")
    others = owners - {user.id}
    if not others:
        make_owner(db, Actor.user(user.id), person)
        db.commit()
        return Proposed()
    if pending_like(db, "owner_add", person.id, {}) is not None:
        raise Conflict("Making this person an owner is already waiting for approval.")
    request = open_request(
        db,
        kind="owner_add",
        requested_by=user.id,
        subject_user_id=person.id,
        payload={},
        details={},
        required_approvals=len(others),
    )
    db.commit()
    return Proposed(request)


def remove_owner(
    db: Session, user: User, person_id: uuid.UUID, *, session: UserSession
) -> Proposed:
    """Propose removing an owner: needs every owner except the one being removed."""
    person = _proposer_and_person(db, user, person_id, session)
    owners = active_owners(db, fresh=True)
    if person.id not in owners:
        raise NotFound()  # not an owner: nothing to remove
    if len(owners) <= 1:
        raise Conflict(LAST_OWNER)
    needed = owners - {person.id, user.id}
    if not needed:
        unmake_owner(db, Actor.user(user.id), person)
        db.commit()
        return Proposed()
    if pending_like(db, "owner_remove", person.id, {}) is not None:
        raise Conflict("Removing this owner is already waiting for approval.")
    request = open_request(
        db,
        kind="owner_remove",
        requested_by=user.id,
        subject_user_id=person.id,
        payload={},
        details={},
        required_approvals=len(needed),
    )
    db.commit()
    return Proposed(request)
