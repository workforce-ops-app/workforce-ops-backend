"""Shifts over HTTP (docs/features/schedules.md, decision 0026). HTTP only: the rules and
the permission checks are in service.py.

Course topic: REST. Each URL names a thing (a collection of shifts, or one shift), the
HTTP method says what to do with it, and the status code says how it went:

    GET    /api/shifts?from=&to=[&department_id=][&mine=true][&cursor=]   200  list (paged)
    GET    /api/shifts/{id}                                                200  one shift
    POST   /api/shifts                                                     201  create
    PATCH  /api/shifts/{id}                                                200  change some fields
    POST   /api/shifts/{id}/assign  {employee_id | null}                   200  give or open
    POST   /api/shifts/{id}/cancel                                         200  cancel

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's), 409 not
allowed in the shift's current state, 422 invalid input.
"""

import uuid
from datetime import date
from typing import Annotated

from fastapi import APIRouter, Query

from app.auth.dependencies import Database, SignedInPerson
from app.modules.schedules import repository, service
from app.modules.schedules.models import Shift
from app.modules.schedules.schemas import (
    DepartmentRef,
    EmployeeRef,
    ShiftAssign,
    ShiftCreate,
    ShiftOut,
    ShiftPage,
    ShiftUpdate,
    utc,
)

router = APIRouter(prefix="/api/shifts", tags=["shifts"])


def _out(item: Shift, department_name: str, employee_name: str | None) -> ShiftOut:
    """A shift in the agreed answer shape."""
    return ShiftOut(
        id=item.id,
        department=DepartmentRef(id=item.department_id, name=department_name),
        employee=(
            EmployeeRef(id=item.employee_id, display_name=employee_name or "")
            if item.employee_id is not None
            else None
        ),
        starts_at=utc(item.starts_at),
        ends_at=utc(item.ends_at),
        timezone=item.timezone,
        status=item.status,
        details=item.details,
        notes=item.notes,
        event_name=item.event_name,
        event_description=item.event_description,
    )


def _one(db: Database, item: Shift) -> ShiftOut:
    return _out(item, *repository.names(db, item))


@router.get("")
def list_shifts(
    current: SignedInPerson,
    db: Database,
    first: Annotated[date, Query(alias="from")],
    last: Annotated[date, Query(alias="to")],
    department_id: uuid.UUID | None = None,
    mine: bool = False,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ShiftPage:
    """Shifts starting on the days from..to (both included, in each shift's workplace zone)."""
    rows, next_cursor = service.list_shifts(
        db,
        current.user,
        first=first,
        last=last,
        department_id=department_id,
        mine=mine,
        cursor=cursor,
        limit=limit,
    )
    items = [_out(row[0], row[2], row[4]) for row in rows]
    return ShiftPage(items=items, next_cursor=next_cursor)


@router.get("/{shift_id}")
def get_shift(shift_id: uuid.UUID, current: SignedInPerson, db: Database) -> ShiftOut:
    return _one(db, service.get_shift(db, current.user, shift_id))


@router.post("", status_code=201)
def create_shift(body: ShiftCreate, current: SignedInPerson, db: Database) -> ShiftOut:
    return _one(db, service.create_shift(db, current.user, body))


@router.patch("/{shift_id}")
def update_shift(
    shift_id: uuid.UUID, body: ShiftUpdate, current: SignedInPerson, db: Database
) -> ShiftOut:
    return _one(db, service.update_shift(db, current.user, shift_id, body))


@router.post("/{shift_id}/assign")
def assign_shift(
    shift_id: uuid.UUID, body: ShiftAssign, current: SignedInPerson, db: Database
) -> ShiftOut:
    return _one(db, service.assign_shift(db, current.user, shift_id, body.employee_id))


@router.post("/{shift_id}/cancel")
def cancel_shift(shift_id: uuid.UUID, current: SignedInPerson, db: Database) -> ShiftOut:
    return _one(db, service.cancel_shift(db, current.user, shift_id))
