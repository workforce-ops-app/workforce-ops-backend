"""Organization data over HTTP.

Course topic: REST. GET names the department collection and retrieves it without changing
it; 200 carries one page, while invalid input uses the shared 422 problem response.
"""

from typing import Annotated

from fastapi import APIRouter, Query

from app.auth.dependencies import Database, SignedInPerson
from app.modules.org import service
from app.modules.org.schemas import DepartmentOut, DepartmentPage

router = APIRouter(prefix="/api/departments", tags=["departments"])


@router.get("")
def list_departments(
    _current_person: SignedInPerson,
    db: Database,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> DepartmentPage:
    """Return active departments for the signed-in person's company."""

    departments, next_cursor = service.list_departments(db, cursor=cursor, limit=limit)
    items = [DepartmentOut(id=department.id, name=department.name) for department in departments]
    return DepartmentPage(items=items, next_cursor=next_cursor)
