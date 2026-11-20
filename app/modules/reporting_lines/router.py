"""Reporting lines over HTTP (authorization.md, the reporting chain). HTTP only: the rules
are in service.py.

    GET  /api/reporting-lines?user_id=[&include_ended=]   200  the lines a person is part of
    POST /api/reporting-lines  {manager_id, employee_id}  201  add a line
    POST /api/reporting-lines/{id}/end                    200  end a line (kept as history)

Errors: 401 not signed in, 403 not allowed (or "reauth-required"), 404 not found, 409 a
loop, a duplicate, a deactivated person, or already ended, 422 invalid input. Every change
also needs the CSRF token.
"""

import uuid

from fastapi import APIRouter

from app.auth.dependencies import Database, SignedInPerson
from app.authz.models import ReportingLine
from app.modules.reporting_lines import service
from app.modules.reporting_lines.schemas import LineCreate, LineList, LineOut

router = APIRouter(prefix="/api/reporting-lines", tags=["reporting lines"])


def _line(line: ReportingLine) -> LineOut:
    return LineOut(
        id=line.id,
        manager_id=line.manager_id,
        employee_id=line.employee_id,
        created_at=line.created_at,
        ended_at=line.ended_at,
    )


@router.get("")
def list_lines(
    user_id: uuid.UUID, current: SignedInPerson, db: Database, include_ended: bool = False
) -> LineList:
    rows = service.list_lines(db, current.user, user_id, include_ended=include_ended)
    return LineList(items=[_line(row) for row in rows])


@router.post("", status_code=201)
def add_line(body: LineCreate, current: SignedInPerson, db: Database) -> LineOut:
    return _line(service.add_line(db, current.user, body, session=current.session))


@router.post("/{line_id}/end")
def end_line(line_id: uuid.UUID, current: SignedInPerson, db: Database) -> LineOut:
    return _line(service.end_line(db, current.user, line_id, session=current.session))
