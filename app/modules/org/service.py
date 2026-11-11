"""The rules for a company's structure: departments, teams, and who is on which team
(docs/features/organization.md, "Departments and teams").

Every change checks org.manage (a company-wide permission: Owner and Administrator) with
authorize() before it reveals or changes anything, writes its audit entry in the same
transaction as the change, and commits once at the end.

Rules:
- Names are unique within the company (departments) or within the department (teams),
  ignoring case, archived ones included, so an old name cannot be confused with a new one
  in history (409).
- Archiving instead of deleting (decision 0020). An archived department or team cannot be
  changed (409), and nothing new goes into it (409).
- A department cannot be archived while it is the home department of anyone not
  deactivated, has upcoming shifts, or still has active teams (409): move the people and
  shifts, and archive the teams, first. Its row is locked while this is checked, so two
  changes to one department take turns.
- Archiving a team keeps its member list for history; role assignments for an archived
  department or team stop granting anything (app/authz/check.py).
- A deactivated person cannot be added to a team (409); nobody is on a team twice (409).

Listing departments and teams only needs a signed-in person: every screen that plans
shifts or shows people needs their names.
"""

import uuid

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.authz.check import authorize
from app.db.base import utcnow
from app.modules.org import repository
from app.modules.org.models import Department, Team, TeamMember, User
from app.modules.org.schemas import DepartmentCreate, DepartmentUpdate, TeamCreate


class Conflict(HTTPException):
    """409: not allowed in the current state."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=409, detail=detail)


class NotFound(HTTPException):
    """404: no such record in the user's company."""

    def __init__(self) -> None:
        super().__init__(status_code=404, detail="Not found.")


class Invalid(HTTPException):
    """422: the request itself is not acceptable."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=422, detail=detail)


DEPARTMENT_NAME_TAKEN = "A department with this name already exists."
TEAM_NAME_TAKEN = "This department already has a team with this name."


def _commit_or_conflict(db: Session, detail: str) -> None:
    """Commit; if the database refuses a duplicate name (two requests creating the same
    name at the same moment both passed the check above it), answer 409, not 500."""
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise Conflict(detail) from error


# --- Departments -----------------------------------------------------------------------


def list_departments(
    db: Session,
    *,
    cursor: str | None,
    limit: int,
) -> tuple[list[Department], str | None]:
    """Apply the cursor rules and return one page plus its next-page bookmark."""

    # Resolve the cursor inside the tenant before rebuilding the (name, ID) sort position.
    after = None
    if cursor is not None:
        department_id = repository.decode_cursor(cursor)
        department = (
            repository.active_department(db, department_id) if department_id is not None else None
        )
        if department is None:
            raise HTTPException(status_code=422, detail="This cursor is not valid.")
        after = department.name, department.id

    rows = repository.list_active_departments(db, after=after, limit=limit)
    page, more = rows[:limit], len(rows) > limit
    next_cursor = repository.encode_cursor(page[-1].id) if more else None
    return page, next_cursor


def create_department(db: Session, user: User, body: DepartmentCreate) -> Department:
    """Add a department to the user's company."""
    # 1. Permission first: someone who may not manage the structure learns nothing more.
    authorize(db, user, "org.manage")
    # 2. The name is free (ignoring case, archived ones too).
    if repository.department_named(db, body.name) is not None:
        raise Conflict(DEPARTMENT_NAME_TAKEN)
    # 3. Add it; the company filter fills in company_id from the session (tenancy layer 1).
    item = Department(name=body.name, timezone=body.timezone)
    db.add(item)
    db.flush()  # gives the new row its ID, for the audit entry
    record(
        db,
        actor=Actor.user(user.id),
        action="department.created",
        target_type="department",
        target_id=item.id,
        details={"name": item.name, "timezone": item.timezone},
    )
    _commit_or_conflict(db, DEPARTMENT_NAME_TAKEN)
    return item


def update_department(
    db: Session, user: User, department_id: uuid.UUID, body: DepartmentUpdate
) -> Department:
    """Rename a department or change its time zone. Only the fields sent change."""
    authorize(db, user, "org.manage")
    item = repository.department(db, department_id, lock=True)
    if item is None:
        raise NotFound()
    if item.archived_at is not None:
        raise Conflict("This department is archived and can no longer be changed.")

    changed = sorted(body.model_fields_set)
    if "name" in changed:
        if body.name is None:
            raise Invalid("A department must have a name.")
        # A new name must be free; keeping the same name (or changing only its case) is fine.
        taken = repository.department_named(db, body.name)
        if taken is not None and taken.id != item.id:
            raise Conflict(DEPARTMENT_NAME_TAKEN)
        item.name = body.name
    if "timezone" in changed:
        # Existing shifts keep the zone they were created with (schedules.md); only new
        # shifts use the new one.
        item.timezone = body.timezone

    if changed:
        record(
            db,
            actor=Actor.user(user.id),
            action="department.updated",
            target_type="department",
            target_id=item.id,
            details={"fields": changed},
        )
    _commit_or_conflict(db, DEPARTMENT_NAME_TAKEN)
    return item


def archive_department(db: Session, user: User, department_id: uuid.UUID) -> Department:
    """Archive a department nobody depends on any more (see the rules at the top)."""
    authorize(db, user, "org.manage")
    # Locked, so a second change to this department waits until this one is decided.
    item = repository.department(db, department_id, lock=True)
    if item is None:
        raise NotFound()
    if item.archived_at is not None:
        raise Conflict("This department is already archived.")
    if repository.is_anyones_home(db, item.id):
        raise Conflict("People still have this as their home department. Move them first.")
    if repository.has_upcoming_shifts(db, item.id, utcnow()):
        raise Conflict("This department has upcoming shifts. Move or cancel them first.")
    if repository.has_active_teams(db, item.id):
        raise Conflict("This department still has teams. Archive them first.")

    item.archived_at = utcnow()
    record(
        db,
        actor=Actor.user(user.id),
        action="department.archived",
        target_type="department",
        target_id=item.id,
    )
    db.commit()
    return item


# --- Teams -----------------------------------------------------------------------------


def list_teams(
    db: Session,
    *,
    department_id: uuid.UUID | None,
    cursor: str | None,
    limit: int,
) -> tuple[list[Team], str | None]:
    """One page of active teams (optionally of one department) and the next bookmark."""
    after = None
    if cursor is not None:
        team_id = repository.decode_cursor(cursor)
        found = repository.active_team(db, team_id) if team_id is not None else None
        if found is None:
            raise Invalid("This cursor is not valid.")
        after = found.name, found.id

    rows = repository.list_active_teams(db, department_id=department_id, after=after, limit=limit)
    page, more = rows[:limit], len(rows) > limit
    return page, (repository.encode_cursor(page[-1].id) if more else None)


def create_team(db: Session, user: User, body: TeamCreate) -> Team:
    """Add a team to an active department."""
    authorize(db, user, "org.manage")
    # The department must be the company's own (another company's: 422, like any unknown
    # reference in a body) and active. Locked, so it cannot be archived meanwhile.
    department = repository.department(db, body.department_id, lock=True)
    if department is None:
        raise Invalid("Unknown department.")
    if department.archived_at is not None:
        raise Conflict("This department is archived. Teams cannot be added to it.")
    if repository.team_named(db, department.id, body.name) is not None:
        raise Conflict(TEAM_NAME_TAKEN)

    item = Team(department_id=department.id, name=body.name)
    db.add(item)
    db.flush()
    record(
        db,
        actor=Actor.user(user.id),
        action="team.created",
        target_type="team",
        target_id=item.id,
        details={"department_id": str(department.id), "name": item.name},
    )
    _commit_or_conflict(db, TEAM_NAME_TAKEN)
    return item


def _changeable_team(db: Session, team_id: uuid.UUID) -> Team:
    """The team, if it exists in the company and is not archived."""
    item = repository.team(db, team_id)
    if item is None:
        raise NotFound()
    if item.archived_at is not None:
        raise Conflict("This team is archived and can no longer be changed.")
    return item


def rename_team(db: Session, user: User, team_id: uuid.UUID, name: str) -> Team:
    """Rename a team (its department never changes)."""
    authorize(db, user, "org.manage")
    item = _changeable_team(db, team_id)
    taken = repository.team_named(db, item.department_id, name)
    if taken is not None and taken.id != item.id:
        raise Conflict(TEAM_NAME_TAKEN)
    item.name = name
    record(
        db,
        actor=Actor.user(user.id),
        action="team.updated",
        target_type="team",
        target_id=item.id,
        details={"fields": ["name"]},
    )
    _commit_or_conflict(db, TEAM_NAME_TAKEN)
    return item


def archive_team(db: Session, user: User, team_id: uuid.UUID) -> Team:
    """Archive a team. Its members stay listed for history; roles for it stop granting."""
    authorize(db, user, "org.manage")
    item = _changeable_team(db, team_id)
    item.archived_at = utcnow()
    record(
        db, actor=Actor.user(user.id), action="team.archived", target_type="team", target_id=item.id
    )
    db.commit()
    return item


def add_member(db: Session, user: User, team_id: uuid.UUID, user_id: uuid.UUID) -> TeamMember:
    """Put a person on a team. Their home department does not change."""
    authorize(db, user, "org.manage")
    item = _changeable_team(db, team_id)
    # The person must be the company's own (another company's: 422, like any unknown
    # reference in a body), and not deactivated.
    member = repository.person(db, user_id)
    if member is None:
        raise Invalid("Unknown person.")
    if member.deactivated_at is not None:
        raise Conflict("This person is deactivated and cannot join a team.")
    if repository.membership(db, item.id, member.id) is not None:
        raise Conflict("This person is already on this team.")

    row = TeamMember(team_id=item.id, user_id=member.id)
    db.add(row)
    record(
        db,
        actor=Actor.user(user.id),
        action="team_member.added",
        target_type="team",
        target_id=item.id,
        details={"user_id": str(member.id)},
    )
    # Two requests adding the same person at the same moment: the key refuses the second.
    _commit_or_conflict(db, "This person is already on this team.")
    return row


def remove_member(db: Session, user: User, team_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Take a person off a team."""
    authorize(db, user, "org.manage")
    item = _changeable_team(db, team_id)
    row = repository.membership(db, item.id, user_id)
    if row is None:
        raise NotFound()
    db.delete(row)
    record(
        db,
        actor=Actor.user(user.id),
        action="team_member.removed",
        target_type="team",
        target_id=item.id,
        details={"user_id": str(user_id)},
    )
    db.commit()
