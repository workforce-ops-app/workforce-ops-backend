"""The rules for adding and ending reporting lines (authorization.md, the reporting chain;
decision 0024).

A line says one person reports to another; lines decide whom a person permission may act
on, so changing them is as strict as changing roles:

- Seeing a person's lines needs user.view covering them; everyone sees their own.
- Adding or ending a line needs reporting_line.manage and a place above BOTH people
  (AZ6). authorize() checks each person, and refuses a person permission aimed at
  yourself, so nobody adds or ends a line they are part of (AZ2). The Owner is above
  everyone, so the Owner can always do it.
- The data rules come from app/authz/chain.py: nobody reports to themselves, one current
  line per pair, and no loops (409).
- Deactivated people get no new lines (409); their existing lines stay, so the people
  above them stay above the people below them.
- Both need the password entered again (decision 0025), and both are audited (AZ12).

Changes take turns through the company's lock (chain.lock_reporting_lines), always taken
before any audit entry. After it, everything is checked again on fresh reads (locking reads;
under MySQL's REPEATABLE READ an ordinary read would answer from before the wait): the
actor still holds reporting_line.manage over both people, both are still in its scope, the
actor is still above both, and for a new line both people are still active. So a line
ended, a role taken away, a person moved, or a person deactivated while this request waited
all count (review of #164).
"""

import uuid

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.audit import Actor
from app.auth.models import UserSession
from app.auth.reauth import require_reauth
from app.authz.chain import (
    ReportingLineError,
    add_reporting_line,
    end_reporting_line,
    lock_reporting_lines,
)
from app.authz.check import authorize
from app.authz.models import ReportingLine
from app.modules.org import repository
from app.modules.org.models import User
from app.modules.org.service import Conflict, Invalid, NotFound
from app.modules.reporting_lines.schemas import LineCreate

PERMISSION = "reporting_line.manage"


def list_lines(
    db: Session, user: User, person_id: uuid.UUID, *, include_ended: bool
) -> list[ReportingLine]:
    """The lines a person is part of (as manager or as employee), newest first."""
    person = repository.person(db, person_id)
    if person is None:
        raise NotFound()
    if person.id != user.id:
        authorize(db, user, "user.view", person)
    query = select(ReportingLine).where(
        or_(ReportingLine.manager_id == person.id, ReportingLine.employee_id == person.id)
    )
    if not include_ended:
        query = query.where(ReportingLine.ended_at.is_(None))
    return list(db.scalars(query.order_by(ReportingLine.created_at.desc()).limit(500)))


def _both(
    db: Session, user: User, manager_id: uuid.UUID, employee_id: uuid.UUID
) -> tuple[User, User]:
    """The two people, if the user may change a line between them (AZ2, AZ6)."""
    manager, employee = repository.person(db, manager_id), repository.person(db, employee_id)
    if manager is None or employee is None:
        raise Invalid("Unknown person.")
    authorize(db, user, PERMISSION, manager)
    authorize(db, user, PERMISSION, employee)
    return manager, employee


def _still_allowed(db: Session, user: User, manager: User, employee: User) -> None:
    """After the company's lock, the whole check again on fresh reads (the top of this
    file): the permission, each person's scope, and the place above each. authorize()
    with fresh=True also refreshes the two User copies, so their status is current after
    this."""
    authorize(db, user, PERMISSION, manager, fresh=True)
    authorize(db, user, PERMISSION, employee, fresh=True)


def _check_active(manager: User, employee: User) -> None:
    """Deactivated people get no new lines (the top of this file)."""
    if manager.deactivated_at is not None or employee.deactivated_at is not None:
        raise Conflict("This person is deactivated.")


def add_line(db: Session, user: User, body: LineCreate, *, session: UserSession) -> ReportingLine:
    """The employee now reports to the manager."""
    authorize(db, user, PERMISSION)  # anywhere at all, before looking anyone up
    manager, employee = _both(db, user, body.manager_id, body.employee_id)
    _check_active(manager, employee)  # early, so the answer comes before the password
    require_reauth(session)
    lock_reporting_lines(db)
    _still_allowed(db, user, manager, employee)
    _check_active(manager, employee)  # again: either may have been deactivated meanwhile
    try:
        line = add_reporting_line(
            db, Actor.user(user.id), manager_id=manager.id, employee_id=employee.id
        )
    except ReportingLineError as error:
        db.rollback()
        raise Conflict(f"{str(error).capitalize()}.") from error
    db.commit()
    return line


def end_line(db: Session, user: User, line_id: uuid.UUID, *, session: UserSession) -> ReportingLine:
    """End a current line; it stays as history."""
    found = db.get(ReportingLine, line_id)
    if found is None:
        raise NotFound()
    manager, employee = _both(db, user, found.manager_id, found.employee_id)
    require_reauth(session)
    lock_reporting_lines(db)
    _still_allowed(db, user, manager, employee)
    try:
        line = end_reporting_line(db, Actor.user(user.id), line_id)
    except ReportingLineError as error:
        db.rollback()
        raise Conflict(f"{str(error).capitalize()}.") from error
    except LookupError as error:
        raise NotFound() from error
    db.commit()
    return line
