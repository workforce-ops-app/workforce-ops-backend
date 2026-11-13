"""Organization data over HTTP (docs/features/organization.md). HTTP only: the rules and
the permission checks are in service.py.

Course topic: REST. Each URL names a thing (a collection, or one item in it), the HTTP
method says what to do with it, and the status code says how it went:

    GET    /api/departments[?cursor=]                         200  list (paged)
    POST   /api/departments  {name, timezone?}                201  create
    PATCH  /api/departments/{id}  {name?, timezone?}          200  rename, change zone
    POST   /api/departments/{id}/archive                      200  archive
    GET    /api/teams[?department_id=][&cursor=]             200  list (paged)
    POST   /api/teams  {department_id, name}                  201  create
    PATCH  /api/teams/{id}  {name}                            200  rename
    POST   /api/teams/{id}/archive                            200  archive
    POST   /api/teams/{id}/members  {user_id}                 201  add someone
    DELETE /api/teams/{id}/members/{user_id}                  204  take someone off

Archiving is a POST to an "archive" action rather than DELETE, because nothing is deleted:
the record stays for history (decision 0020).

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's), 409 not
allowed in the current state, 422 invalid input. Every change also needs the CSRF token.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Response

from app.auth.dependencies import Database, SignedInPerson
from app.modules.org import service
from app.modules.org.models import Department, Team
from app.modules.org.schemas import (
    DepartmentCreate,
    DepartmentDetail,
    DepartmentOut,
    DepartmentPage,
    DepartmentUpdate,
    MemberAdd,
    MemberOut,
    TeamCreate,
    TeamOut,
    TeamPage,
    TeamUpdate,
)

departments = APIRouter(prefix="/api/departments", tags=["departments"])
teams = APIRouter(prefix="/api/teams", tags=["teams"])


def _department(item: Department) -> DepartmentDetail:
    """A department in the answer shape for the people who manage it."""
    return DepartmentDetail(
        id=item.id, name=item.name, timezone=item.timezone, archived=item.archived_at is not None
    )


def _team(item: Team) -> TeamOut:
    """A team in the agreed answer shape."""
    return TeamOut(
        id=item.id,
        department_id=item.department_id,
        name=item.name,
        archived=item.archived_at is not None,
    )


# --- Departments -----------------------------------------------------------------------


@departments.get("")
def list_departments(
    _current_person: SignedInPerson,
    db: Database,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> DepartmentPage:
    """Return active departments for the signed-in person's company."""

    rows, next_cursor = service.list_departments(db, cursor=cursor, limit=limit)
    items = [DepartmentOut(id=department.id, name=department.name) for department in rows]
    return DepartmentPage(items=items, next_cursor=next_cursor)


@departments.post("", status_code=201)
def create_department(
    body: DepartmentCreate, current: SignedInPerson, db: Database
) -> DepartmentDetail:
    return _department(service.create_department(db, current.user, body))


@departments.patch("/{department_id}")
def update_department(
    department_id: uuid.UUID, body: DepartmentUpdate, current: SignedInPerson, db: Database
) -> DepartmentDetail:
    return _department(service.update_department(db, current.user, department_id, body))


@departments.post("/{department_id}/archive")
def archive_department(
    department_id: uuid.UUID, current: SignedInPerson, db: Database
) -> DepartmentDetail:
    return _department(service.archive_department(db, current.user, department_id))


# --- Teams -----------------------------------------------------------------------------


@teams.get("")
def list_teams(
    _current_person: SignedInPerson,
    db: Database,
    department_id: uuid.UUID | None = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> TeamPage:
    """Active teams of the signed-in person's company, optionally of one department."""
    rows, next_cursor = service.list_teams(
        db, department_id=department_id, cursor=cursor, limit=limit
    )
    return TeamPage(items=[_team(row) for row in rows], next_cursor=next_cursor)


@teams.post("", status_code=201)
def create_team(body: TeamCreate, current: SignedInPerson, db: Database) -> TeamOut:
    return _team(service.create_team(db, current.user, body))


@teams.patch("/{team_id}")
def rename_team(
    team_id: uuid.UUID, body: TeamUpdate, current: SignedInPerson, db: Database
) -> TeamOut:
    return _team(service.rename_team(db, current.user, team_id, body.name))


@teams.post("/{team_id}/archive")
def archive_team(team_id: uuid.UUID, current: SignedInPerson, db: Database) -> TeamOut:
    return _team(service.archive_team(db, current.user, team_id))


@teams.post("/{team_id}/members", status_code=201)
def add_member(
    team_id: uuid.UUID, body: MemberAdd, current: SignedInPerson, db: Database
) -> MemberOut:
    row = service.add_member(db, current.user, team_id, body.user_id)
    return MemberOut(team_id=row.team_id, user_id=row.user_id)


@teams.delete("/{team_id}/members/{user_id}", status_code=204)
def remove_member(
    team_id: uuid.UUID, user_id: uuid.UUID, current: SignedInPerson, db: Database
) -> Response:
    service.remove_member(db, current.user, team_id, user_id)
    return Response(status_code=204)


# The app includes the one `router` of each module (app/main.py), so both collections go
# into it. This comes last: include_router copies the routes defined above at this moment.
router = APIRouter()
router.include_router(departments)
router.include_router(teams)
