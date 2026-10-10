"""The rules for shifts (docs/features/schedules.md). Every function checks permission with
authorize() before it reveals or changes anything, writes its audit entry in the same
transaction as the change, and commits once at the end.

Rules:
- Times arrive as moments with an offset and are stored in UTC; the workplace zone (the
  department's, or the company's) is copied onto the shift and never recalculated.
- The end is after the start, and a shift is at most 12 hours long (422).
- Only an active person who has set up their account, whose home department is the
  shift's department or who is on a team in it, can be assigned (422).
- Nobody is booked on two overlapping shifts (409). The person's row is locked while this
  is checked, so two requests at the same moment cannot both pass.
- A shift that has ended, or was cancelled, can no longer be changed (409).
- Time off is checked here once time-off requests exist (time-off slices).
"""

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.authz.check import Forbidden, authorize, scope_filter
from app.authz.scope import ScopeColumns
from app.db.base import utcnow
from app.modules.org.models import Team, TeamMember, User
from app.modules.schedules import repository
from app.modules.schedules import scope as _scope  # noqa: F401  (registers the resolver)
from app.modules.schedules.models import Shift
from app.modules.schedules.schemas import ShiftCreate, ShiftUpdate

MAX_LENGTH = timedelta(hours=12)
MAX_DAYS = 31  # per list request (threat D2: no huge date ranges)


class Invalid(HTTPException):
    """422: the request itself is not acceptable."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=422, detail=detail)


class Conflict(HTTPException):
    """409: not allowed in the shift's (or the person's) current state."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=409, detail=detail)


class NotFound(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=404, detail="Not found.")


CANNOT_ASSIGN = "This person cannot be assigned to this shift."


def _utc(moment: datetime) -> datetime:
    """A moment with an offset as UTC without a zone, the way it is stored."""
    return moment.astimezone(UTC).replace(tzinfo=None)


def _check_times(starts_at: datetime, ends_at: datetime) -> None:
    if ends_at <= starts_at:
        raise Invalid("A shift must end after it starts.")
    if ends_at - starts_at > MAX_LENGTH:
        raise Invalid("A shift can be at most 12 hours long.")


def _check_changeable(shift: Shift) -> None:
    """Ended and cancelled shifts are history: they cannot be changed."""
    if shift.status == "cancelled":
        raise Conflict("This shift was cancelled and can no longer be changed.")
    if shift.ends_at <= utcnow():
        raise Conflict("This shift has ended and can no longer be changed.")


def _check_assignable(db: Session, shift: Shift, employee_id: uuid.UUID) -> None:
    """Refuse anyone who cannot work this shift (see the rules at the top)."""
    person = repository.person(db, employee_id, lock=True)
    # Unknown (or of another company), deactivated, or not set up yet ("invited").
    if person is None or person.deactivated_at is not None or person.password_hash is None:
        raise Invalid(CANNOT_ASSIGN)
    # Home department, or on a team in the shift's department.
    on_team = db.execute(
        select(TeamMember.user_id, Team.id)
        .join(Team, Team.id == TeamMember.team_id)
        .where(TeamMember.user_id == person.id, Team.department_id == shift.department_id)
        .limit(1)
    ).first()
    if person.department_id != shift.department_id and on_team is None:
        raise Invalid(CANNOT_ASSIGN)
    if repository.has_overlap(db, person.id, shift.starts_at, shift.ends_at, ignore=shift.id):
        raise Conflict("This person already has a shift at that time.")


def get_shift(db: Session, user: User, shift_id: uuid.UUID) -> Shift:
    """One shift, if the user may see it: in their scope, or their own."""
    item = repository.shift(db, shift_id)
    if item is None:
        raise NotFound()
    try:
        authorize(db, user, "schedule.view", item)
    except Forbidden:
        authorize(db, user, "schedule.view_self", item)
    return item


def create_shift(db: Session, user: User, body: ShiftCreate) -> Shift:
    dept = repository.department(db, body.department_id)
    if dept is None:
        raise Invalid("Unknown department.")
    item = Shift(
        company_id=user.company_id,
        department_id=dept.id,
        employee_id=body.employee_id,
        starts_at=_utc(body.starts_at),
        ends_at=_utc(body.ends_at),
        timezone=repository.workplace_zone(db, dept),
        status="scheduled" if body.employee_id else "open",
        details=body.details,
        notes=body.notes,
        event_name=body.event_name,
        event_description=body.event_description,
    )
    # May the user edit shifts here (this department, and this person if any)?
    authorize(db, user, "schedule.edit", item)
    _check_times(item.starts_at, item.ends_at)
    if item.ends_at <= utcnow():
        raise Invalid("A shift that has already ended cannot be created.")
    if body.employee_id is not None:
        _check_assignable(db, item, body.employee_id)

    db.add(item)
    db.flush()
    record(
        db,
        actor=Actor.user(user.id),
        action="shift.created",
        target_type="shift",
        target_id=item.id,
        details={
            "department_id": str(item.department_id),
            "employee_id": str(item.employee_id) if item.employee_id else None,
            "starts_at": item.starts_at.isoformat(),
            "ends_at": item.ends_at.isoformat(),
        },
    )
    db.commit()
    return item


def update_shift(db: Session, user: User, shift_id: uuid.UUID, body: ShiftUpdate) -> Shift:
    """Change times or text. Only the fields sent are changed (and are listed in the audit
    entry by name, never with their text)."""
    item = repository.shift(db, shift_id)
    if item is None:
        raise NotFound()
    authorize(db, user, "schedule.edit", item)
    _check_changeable(item)

    changed = sorted(body.model_fields_set)
    for field in changed:
        value = getattr(body, field)
        if field in ("starts_at", "ends_at"):
            if value is None:
                raise Invalid("A shift must have a start and an end.")
            value = _utc(value)
        setattr(item, field, value)
    _check_times(item.starts_at, item.ends_at)
    if {"starts_at", "ends_at"} & set(changed) and item.employee_id is not None:
        # New times: the person must still be free (and their row locked while checking).
        repository.person(db, item.employee_id, lock=True)
        if repository.has_overlap(db, item.employee_id, item.starts_at, item.ends_at, item.id):
            raise Conflict("This person already has a shift at that time.")

    if changed:
        record(
            db,
            actor=Actor.user(user.id),
            action="shift.updated",
            target_type="shift",
            target_id=item.id,
            details={"fields": changed},
        )
    db.commit()
    return item


def assign_shift(
    db: Session, user: User, shift_id: uuid.UUID, employee_id: uuid.UUID | None
) -> Shift:
    """Give the shift to a person, or make it open (employee_id None)."""
    item = repository.shift(db, shift_id)
    if item is None:
        raise NotFound()
    authorize(db, user, "schedule.edit", item)  # the shift as it is now...
    _check_changeable(item)
    previous = item.employee_id

    if employee_id is None:
        item.employee_id, item.status = None, "open"
    else:
        item.employee_id, item.status = employee_id, "scheduled"
        _check_assignable(db, item, employee_id)
    # ...and as it will be: a manager cannot move a shift out of their own scope either.
    authorize(db, user, "schedule.edit", item)

    record(
        db,
        actor=Actor.user(user.id),
        action="shift.opened" if employee_id is None else "shift.assigned",
        target_type="shift",
        target_id=item.id,
        details={
            "employee_id": str(employee_id) if employee_id else None,
            "previous_employee_id": str(previous) if previous else None,
        },
    )
    db.commit()
    return item


def cancel_shift(db: Session, user: User, shift_id: uuid.UUID) -> Shift:
    item = repository.shift(db, shift_id)
    if item is None:
        raise NotFound()
    authorize(db, user, "schedule.edit", item)
    _check_changeable(item)
    item.status = "cancelled"
    record(
        db,
        actor=Actor.user(user.id),
        action="shift.cancelled",
        target_type="shift",
        target_id=item.id,
    )
    db.commit()
    return item


def list_shifts(
    db: Session,
    user: User,
    *,
    first: date,
    last: date,
    department_id: uuid.UUID | None,
    mine: bool,
    cursor: str | None,
    limit: int,
) -> tuple[list[Any], str | None]:
    """A page of the shifts the user may see on these days, and the cursor for the next."""
    if last < first:
        raise Invalid("The last day must not be before the first.")
    if (last - first).days + 1 > MAX_DAYS:
        raise Invalid(f"Ask for at most {MAX_DAYS} days at a time.")
    after = None
    if cursor is not None:
        after = repository.decode_cursor(cursor)
        if after is None:
            raise Invalid("This cursor is not valid.")

    columns = ScopeColumns(department=Shift.department_id, employee=Shift.employee_id)
    if mine:
        # Your own shifts: schedule.view_self.
        authorize(db, user, "schedule.view_self")
        allowed = scope_filter(db, user, "schedule.view_self", columns)
    else:
        # Everything in your scopes: schedule.view, and only the rows it covers.
        authorize(db, user, "schedule.view")
        allowed = scope_filter(db, user, "schedule.view", columns)

    rows = repository.list_shifts(
        db,
        allowed=allowed,
        first=first,
        last=last,
        department_id=department_id,
        after=after,
        limit=limit,
    )
    page, more = rows[:limit], len(rows) > limit
    next_cursor = repository.encode_cursor(page[-1][0]) if more else None
    return page, next_cursor
