"""Every database query of the schedules module (the only file here that talks to the database).

All queries are built with SQLAlchemy, so every value is sent as a bound parameter, never
pasted into SQL text (SQL injection, threat T1), and the company filter adds "company_id =
<the session's company>" to each of them (tenancy.md).
"""

import base64
import binascii
import json
import uuid
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import ColumnElement, and_, or_, select
from sqlalchemy.orm import Session

from app.modules.org.models import Company, Department, User
from app.modules.schedules.models import Shift


def department(db: Session, department_id: uuid.UUID) -> Department | None:
    """A department of the session's company (another company's looks like none)."""
    return db.get(Department, department_id)


def workplace_zone(db: Session, dept: Department) -> str:
    """The workplace time zone: the department's own, or else the company's."""
    if dept.timezone:
        return dept.timezone
    company = db.get(Company, dept.company_id)
    if company is None:  # the session's own company is always visible to it
        raise RuntimeError("the department's company is missing")
    return company.timezone


def person(db: Session, user_id: uuid.UUID, *, lock: bool = False) -> User | None:
    """A person of the session's company. lock=True locks their row until the transaction
    ends (SELECT ... FOR UPDATE): two managers giving the same person overlapping shifts at
    the same moment then take turns, so the double-booking check cannot be raced."""
    return db.get(User, user_id, with_for_update=lock)


def has_overlap(
    db: Session,
    employee_id: uuid.UUID,
    starts_at: datetime,
    ends_at: datetime,
    ignore: uuid.UUID | None,
) -> bool:
    """Whether the person already has a (not cancelled) shift overlapping this time.

    Two time ranges overlap when each starts before the other ends.
    """
    conditions = [
        Shift.employee_id == employee_id,
        Shift.status != "cancelled",
        Shift.starts_at < ends_at,
        Shift.ends_at > starts_at,
    ]
    if ignore is not None:
        conditions.append(Shift.id != ignore)
    return db.scalar(select(Shift.id).where(*conditions).limit(1)) is not None


def shift(db: Session, shift_id: uuid.UUID) -> Shift | None:
    """One shift of the session's company (another company's looks like none: 404)."""
    return db.get(Shift, shift_id)


def names(db: Session, item: Shift) -> tuple[str, str | None]:
    """The department's name and the person's display name, for one shift's answer."""
    dept = db.get(Department, item.department_id)
    person_name = None
    if item.employee_id is not None:
        employee = db.get(User, item.employee_id)
        person_name = employee.display_name if employee is not None else None
    return (dept.name if dept is not None else ""), person_name


# --- The list ---------------------------------------------------------------------------


def encode_cursor(item: Shift) -> str:
    """A bookmark to the last shift of a page: its start and ID (the list's sort order)."""
    raw = json.dumps({"s": item.starts_at.isoformat(), "i": str(item.id)}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID] | None:
    """The bookmark inside a cursor, or None if it is not one of ours."""
    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        return datetime.fromisoformat(raw["s"]), uuid.UUID(raw["i"])
    except (binascii.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _day_range(zone: str, first: date, last: date) -> tuple[datetime, datetime]:
    """The UTC moments where the days first..last (both included) begin and end in a zone."""
    tz = ZoneInfo(zone)
    start = datetime.combine(first, time(0), tz).astimezone(UTC)
    end = datetime.combine(last + timedelta(days=1), time(0), tz).astimezone(UTC)
    return start.replace(tzinfo=None), end.replace(tzinfo=None)


def list_shifts(
    db: Session,
    *,
    allowed: ColumnElement[bool],
    first: date,
    last: date,
    department_id: uuid.UUID | None,
    after: tuple[datetime, uuid.UUID] | None,
    limit: int,
) -> list[Any]:
    """One page of shifts, with their department's and person's names.

    Course topic: SQL JOINs. One query joins each shift to its department (INNER JOIN:
    every shift has one) and to its person (LEFT OUTER JOIN: an open shift has none, and
    must still be listed). In SQL it is roughly:

        SELECT shifts.*, departments.name, users.display_name
          FROM shifts
          JOIN departments ON departments.id = shifts.department_id
          LEFT OUTER JOIN users ON users.id = shifts.employee_id
         WHERE <the user's scopes> AND <the days> AND shifts.status <> 'cancelled'
         ORDER BY shifts.starts_at, shifts.id
         LIMIT :limit

    The company filter adds "company_id = :company" for all three tables, and `allowed` is
    the scope condition from authz (only the shifts the user may see).
    """
    base = [allowed, Shift.status != "cancelled"]
    if department_id is not None:
        base.append(Shift.department_id == department_id)

    # "A shift belongs to the day it starts in its workplace zone." Each zone has its own
    # midnight, so the days are turned into UTC once per zone the shifts use, and each
    # shift is compared with its own zone's range. The zones come from shifts starting
    # around those days (a day either side covers every offset in the world).
    near_start, near_end = _day_range("UTC", first - timedelta(days=1), last + timedelta(days=1))
    zones = db.scalars(
        select(Shift.timezone)
        .distinct()
        .where(*base, Shift.starts_at >= near_start, Shift.starts_at < near_end)
    ).all()
    if not zones:
        return []
    in_days = or_(
        *(
            and_(Shift.timezone == zone, Shift.starts_at >= start, Shift.starts_at < end)
            for zone in zones
            for start, end in [_day_range(zone, first, last)]
        )
    )

    query = (
        select(Shift, Department.id, Department.name, User.id, User.display_name)
        .join(Department, Department.id == Shift.department_id)
        .outerjoin(User, User.id == Shift.employee_id)
        .where(*base, in_days)
        .order_by(Shift.starts_at, Shift.id)
        .limit(limit + 1)  # one more than asked: tells whether another page exists
    )
    if after is not None:
        # Everything after the bookmark in the sort order (start time, then ID).
        starts, last_id = after
        query = query.where(
            or_(Shift.starts_at > starts, and_(Shift.starts_at == starts, Shift.id > last_id))
        )
    return list(db.execute(query).all())
