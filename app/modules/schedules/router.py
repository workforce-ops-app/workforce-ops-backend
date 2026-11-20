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
    POST   /api/shifts/batch  {action: create | cancel | assign, ...}      200  several at once

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's), 409 not
allowed in the shift's current state (or a batch without the right confirm_count), 422
invalid input.
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
    RoleRef,
    ShiftAssign,
    ShiftBatch,
    ShiftBatchOut,
    ShiftCreate,
    ShiftOut,
    ShiftPage,
    ShiftUpdate,
    utc,
)

router = APIRouter(prefix="/api/shifts", tags=["shifts"])


def _out(
    item: Shift, department_name: str, employee_name: str | None, roles: repository.RolesByPerson
) -> ShiftOut:
    """A shift in the agreed answer shape. roles holds everyone's roles in the departments
    of the answer's shifts, looked up once for all of them (repository.roles_of)."""
    return ShiftOut(
        id=item.id,
        department=DepartmentRef(id=item.department_id, name=department_name),
        employee=(
            EmployeeRef(
                id=item.employee_id,
                display_name=employee_name or "",
                roles=[
                    RoleRef(name=name, built_in=built_in)
                    for name, built_in in roles.get((item.employee_id, item.department_id), [])
                ],
            )
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


def _people(items: list[Shift]) -> list[repository.PersonInDepartment]:
    """Who works these shifts and in which department, each pair once (open shifts have
    nobody). Roles are shown for the shift's department (repository.roles_of)."""
    return list(
        {(item.employee_id, item.department_id) for item in items if item.employee_id is not None}
    )


def _one(db: Database, item: Shift, roles: repository.RolesByPerson | None = None) -> ShiftOut:
    """One shift in the answer shape. A batch passes the roles it already looked up for all
    its shifts; a single shift looks up its own person's."""
    if roles is None:
        roles = repository.roles_of(db, _people([item]))
    return _out(item, *repository.names(db, item), roles)


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
    # The roles of everyone on this page, in one query.
    roles = repository.roles_of(db, _people([row[0] for row in rows]))
    items = [_out(row[0], row[2], row[4], roles) for row in rows]
    return ShiftPage(items=items, next_cursor=next_cursor)


@router.post("/batch")
def batch(body: ShiftBatch, current: SignedInPerson, db: Database) -> ShiftBatchOut:
    """Several shifts at once, all or nothing. 200 for every action (a create batch too),
    since the answer is the batch's result rather than one new resource."""
    items = service.batch(db, current.user, body)
    # The roles of everyone in the batch, in one query.
    roles = repository.roles_of(db, _people(items))
    return ShiftBatchOut(
        action=body.action, count=len(items), items=[_one(db, item, roles) for item in items]
    )


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
