"""The rules for people's accounts (docs/features/organization.md, "People").

Seeing people needs user.view, and the scope filter limits a list to the people the user's
assignments cover. Changing an account needs user.manage AND a place above the person in
the reporting chain (AZ5): the Owner is above everyone, anyone else only above the people
who report to them, directly or not (app/authz/chain.py). authorize() checks both, and
refuses anyone acting on their own account (nobody deactivates, unlocks, or signs out
themselves through these actions).

Rules:
- A new account has no password ("invited") until its setup link is used (#57). It names
  who the person reports to (manager_id): the creator, or someone the creator is above.
  The reporting line is added in the same transaction, so the creator is above the new
  person from the start and can go on to set up their account. Only an Owner may leave it
  out, being above everyone anyway. This is the one line a person may add while being
  part of it (AZ2): a brand-new account holds nothing, so it cannot be an escalation.
- Emails are unique across the platform. A taken email gets one answer, "This email can't
  be used.", whether the address is in this company or another, so the answer never says
  where an account exists (decision 0016, threat I3). The database's unique key is what
  finds it, for both cases alike: there is no cross-company lookup.
- A person is created in, or moved to, an active department that the user's own
  user.manage covers (check.covers_department), so nobody puts a person where they could
  not act on them afterwards.
- Deactivating ends every session of the person at once and keeps everything else for
  history: records, roles, reporting lines, and upcoming shifts, which the answer lists
  for reassigning. An owner cannot be deactivated (AZ8, AZ15): owners leave through the
  owner change flow (#56), which needs the other owners' approval.
- Reactivating puts the person back to "invited": their password is cleared, and they
  choose a new one with a fresh setup link. Their home department must be active.
- Unlocking clears a lockout and the count of wrong passwords.

Changes take turns with each other, and with team and shift changes, through row locks,
always taken in one order so two requests never wait for each other forever:
the department (when one is involved), then the person, then the reporting lines (the
company row), then the audit log. Archiving a department locks it and then reads its
people the same way, so a person cannot be created in, moved to, or reactivated into a
department that is being archived at that moment.

Each request first checks permission with ordinary reads, so a request that may not act
on the person never waits for, or holds, their lock. After taking the lock it checks
again, on the person as they are now (the same pattern as shifts, review on #127): if
someone moved them to a department outside the user's scope while this request waited,
it is refused. Roles and reporting lines are read as of the request's start, as for
every other permission check.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.authz.chain import add_reporting_line, lock_reporting_lines
from app.authz.check import (
    Forbidden,
    authorize,
    covers_department,
    is_above,
    is_owner,
    scope_filter,
)
from app.authz.scope import ScopeColumns
from app.db.base import utcnow
from app.modules.org import repository
from app.modules.org.models import Department, User
from app.modules.org.schemas import UserCreate, UserUpdate
from app.modules.org.service import Conflict, Invalid, NotFound, saved_or_conflict

EMAIL_TAKEN = "This email can't be used."


def status(person: User) -> str:
    """Where the account is in its life (the state diagram on the organization page)."""
    if person.deactivated_at is not None:
        return "deactivated"
    if person.password_hash is None:
        return "invited"
    return "active"


def is_locked(person: User) -> bool:
    """Whether wrong passwords have locked the account for now."""
    return person.locked_until is not None and person.locked_until > utcnow()


# --- Seeing people ---------------------------------------------------------------------


def list_people(
    db: Session, user: User, *, cursor: str | None, limit: int
) -> tuple[list[User], str | None]:
    """One page of the people the user may see, by name, and the next page's bookmark."""
    # 1. Permission somewhere at all: an employee without user.view gets 403, not an
    #    empty list that looks like a company without people.
    authorize(db, user, "user.view")
    # 2. Where: the scope filter, the same rules as authorize() on one person.
    visible = scope_filter(db, user, "user.view", ScopeColumns(User.department_id, User.id))

    # 3. The bookmark is the last person's ID; they must still be someone the user sees,
    #    so a bookmark cannot be used to learn where anyone else sorts.
    after = None
    if cursor is not None:
        person_id = repository.decode_cursor(cursor)
        found = repository.person(db, person_id) if person_id is not None else None
        if found is None or not _may_see(db, user, found):
            raise Invalid("This cursor is not valid.")
        after = found.display_name, found.id

    rows = repository.list_people(db, visible=visible, after=after, limit=limit)
    page, more = rows[:limit], len(rows) > limit
    return page, (repository.encode_cursor(page[-1].id) if more else None)


def _may_see(db: Session, user: User, person: User) -> bool:
    """Whether the user may see this person: always themselves, others with user.view."""
    if person.id == user.id:
        return True
    try:
        authorize(db, user, "user.view", person)
    except Forbidden:
        return False
    return True


def view_person(db: Session, user: User, person_id: uuid.UUID) -> User:
    """One person: themselves, or someone in the user's user.view scope."""
    person = repository.person(db, person_id)
    if person is None:
        raise NotFound()  # unknown, or another company's
    # Everyone may see their own account; anyone else needs user.view covering them (403).
    if person.id != user.id:
        authorize(db, user, "user.view", person)
    return person


def teams_of(db: Session, people: list[User]) -> dict[uuid.UUID, list[uuid.UUID]]:
    """The teams of each person, for the answer (one query for a whole page)."""
    return repository.team_ids_by_person(db, [person.id for person in people])


# --- Creating and changing accounts ----------------------------------------------------


def _department_to_place_in(db: Session, user: User, department_id: uuid.UUID) -> Department:
    """The department a person is created in or moved to, locked: it must be the
    company's own (otherwise 422, like any unknown reference in a body), active (409), and
    covered by the user's own user.manage (403). Locked first of everything (the order at
    the top), so it cannot be archived until this request ends."""
    department = repository.department(db, department_id, lock=True)
    if department is None:
        raise Invalid("Unknown department.")
    if department.archived_at is not None:
        raise Conflict("This department is archived. Nobody can be placed in it.")
    if not covers_department(db, user, "user.manage", department.id):
        raise Forbidden()
    return department


def create_person(db: Session, user: User, body: UserCreate) -> User:
    """Create an account with no password yet; it reports to body.manager_id."""
    # 1. Permission first: someone who may not manage accounts learns nothing more.
    authorize(db, user, "user.manage")
    # 2. Where the person goes (locked first, as the order at the top says).
    department = _department_to_place_in(db, user, body.department_id)

    # 3. Who they report to: the creator, or someone the creator is above. An Owner, who
    #    is above everyone, may leave it out.
    manager = None
    if body.manager_id is None:
        if not is_owner(db, user):
            raise Invalid("Say who this person reports to (manager_id).")
    else:
        manager = repository.person(db, body.manager_id)
        if manager is None:
            raise Invalid("Unknown manager.")
        if manager.deactivated_at is not None:
            raise Conflict("This manager is deactivated.")
        if manager.id != user.id and not is_above(db, user, manager):
            raise Forbidden()
        # The reporting lines' lock comes before any audit entry (chain.py says why).
        lock_reporting_lines(db)

    person = User(display_name=body.display_name, email=body.email, department_id=department.id)
    # 4. Save the account, its audit entry, and its reporting line together. A taken email
    #    is refused by the database's unique key, here or in another company alike: 409.
    with saved_or_conflict(db, EMAIL_TAKEN):
        db.add(person)
        db.flush()  # sends the row (a taken email is refused here) and gives it an ID
        record(
            db,
            actor=Actor.user(user.id),
            action="user.created",
            target_type="user",
            target_id=person.id,
            # No email: the audit log is kept for good, and the person's address is
            # theirs to change; the account's ID is enough to find them.
            details={
                "department_id": str(department.id),
                "manager_id": str(manager.id) if manager is not None else None,
            },
        )
        if manager is not None:
            add_reporting_line(
                db, Actor.user(user.id), manager_id=manager.id, employee_id=person.id
            )
    return person


def _person_to_change(db: Session, user: User, person_id: uuid.UUID) -> User:
    """The person, locked and read fresh, if the user may act on their account.

    1. An ordinary read and the permission check: someone who may not act on the person
       gets 404 or 403 without ever waiting for, or holding, the person's lock.
    2. The lock (SELECT ... FOR UPDATE), which also reads the newest committed row.
    3. The check again, on the person as they are now: if someone moved them out of the
       user's scope (another home department) while this request waited, it is refused
       (403) instead of acting on someone the user no longer covers.
    """
    person = repository.person(db, person_id)
    if person is None:
        raise NotFound()
    authorize(db, user, "user.manage", person)
    person = repository.person(db, person_id, lock=True)
    if person is None:  # existed a moment ago; people are never deleted
        raise NotFound()
    authorize(db, user, "user.manage", person)
    return person


def change_person(db: Session, user: User, person_id: uuid.UUID, body: UserUpdate) -> User:
    """Change a person's name, email, or home department. Only the fields sent change."""
    changed = sorted(body.model_fields_set)
    # 1. Allowed at all, before anything is locked (see _person_to_change).
    found = repository.person(db, person_id)
    if found is None:
        raise NotFound()
    authorize(db, user, "user.manage", found)
    # 2. A new home department is locked before the person (the order at the top).
    department = None
    if "department_id" in changed:
        if body.department_id is None:
            raise Invalid("Everyone has a home department.")
        department = _department_to_place_in(db, user, body.department_id)
    # 3. The person, locked and checked again.
    person = _person_to_change(db, user, person_id)

    if "display_name" in changed:
        if body.display_name is None:
            raise Invalid("A person must have a name.")
        person.display_name = body.display_name
    if "email" in changed:
        if body.email is None:
            raise Invalid("A person must have an email.")
        person.email = body.email
    if department is not None:
        # Department-scoped roles now cover them through the new department instead.
        person.department_id = department.id

    # record() sends the change to the database, so a taken email is refused there:
    # inside the block, that is the same 409 as at creation.
    with saved_or_conflict(db, EMAIL_TAKEN):
        if changed:
            record(
                db,
                actor=Actor.user(user.id),
                action="user.updated",
                target_type="user",
                target_id=person.id,
                details={"fields": changed},  # which fields, never their values
            )
    return person


# --- Account state ---------------------------------------------------------------------


@dataclass
class Deactivated:
    """A deactivated person, and their upcoming shifts that still need someone."""

    person: User
    upcoming_shift_ids: list[uuid.UUID]


def deactivate(db: Session, user: User, person_id: uuid.UUID) -> Deactivated:
    """Deactivate a person: they cannot sign in, and every session of theirs ends now.

    Their unused setup and reset links are cancelled too once links exist (#57).
    Deactivating someone who holds an admin-level role will need the password re-entered
    once re-entry exists (#51; authorization.md, sensitive actions).
    """
    person = _person_to_change(db, user, person_id)
    if person.deactivated_at is not None:
        raise Conflict("This person is already deactivated.")
    # AZ8 and AZ15: owners are removed only through the owner change flow, with the other
    # owners' approval, and the last owner never.
    if is_owner(db, person):
        raise Conflict("An owner cannot be deactivated. Remove them as an owner first.")

    person.deactivated_at = utcnow()
    # Every browser of theirs is signed out at once (load_session would also refuse a
    # deactivated person's session; deleting the rows makes the tokens useless for good).
    ended = repository.end_sessions(db, person.id)
    record(
        db,
        actor=Actor.user(user.id),
        action="user.deactivated",
        target_type="user",
        target_id=person.id,
    )
    if ended:
        record(
            db,
            actor=Actor.user(user.id),
            action="auth.sessions_ended",
            target_type="user",
            target_id=person.id,
            details={"count": ended, "reason": "deactivated"},
        )
    upcoming = repository.upcoming_shift_ids(db, person.id, utcnow())
    db.commit()
    return Deactivated(person, upcoming)


def reactivate(db: Session, user: User, person_id: uuid.UUID) -> User:
    """Put a deactivated person back to "invited": they set a new password with a fresh
    setup link (#57)."""
    # 1. Allowed at all, before anything is locked.
    found = repository.person(db, person_id)
    if found is None:
        raise NotFound()
    authorize(db, user, "user.manage", found)
    # 2. Their home department, locked before the person (the order at the top), so it
    #    cannot be archived while they come back.
    home = repository.department(db, found.department_id, lock=True)
    # 3. The person, locked and checked again. If someone moved them to another department
    #    meanwhile, the department locked above is the wrong one: refused, try again.
    person = _person_to_change(db, user, person_id)
    if home is None or person.department_id != home.id:
        raise Conflict("This person was changed meanwhile. Try again.")
    if person.deactivated_at is None:
        raise Conflict("This person is not deactivated.")
    if home.archived_at is not None:
        raise Conflict("Their home department is archived. Move them to another one first.")

    person.deactivated_at = None
    # Back to "invited": the old password no longer works, and no old lockout carries over.
    person.password_hash = None
    person.failed_sign_ins = 0
    person.locked_until = None
    record(
        db,
        actor=Actor.user(user.id),
        action="user.reactivated",
        target_type="user",
        target_id=person.id,
    )
    db.commit()
    return person


def unlock(db: Session, user: User, person_id: uuid.UUID) -> User:
    """Clear a lockout and the count of wrong passwords. Audited when it changed anything."""
    person = _person_to_change(db, user, person_id)
    if person.failed_sign_ins or person.locked_until is not None:
        person.failed_sign_ins = 0
        person.locked_until = None
        record(
            db,
            actor=Actor.user(user.id),
            action="auth.unlocked",
            target_type="user",
            target_id=person.id,
        )
    db.commit()
    return person


def sign_out_everywhere(db: Session, user: User, person_id: uuid.UUID) -> None:
    """End every session of the person: each of their browsers is signed out at once."""
    person = _person_to_change(db, user, person_id)
    ended = repository.end_sessions(db, person.id)
    record(
        db,
        actor=Actor.user(user.id),
        action="auth.sessions_ended",
        target_type="user",
        target_id=person.id,
        details={"count": ended, "reason": "signed_out"},
    )
    db.commit()
