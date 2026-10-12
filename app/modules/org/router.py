"""HTTP endpoints for organization data."""

from fastapi import APIRouter

from app.auth.dependencies import Database, SignedInPerson
from app.modules.org import service
from app.modules.org.schemas import DepartmentOut

router = APIRouter(prefix="/api/departments", tags=["departments"])


@router.get("")
def list_departments(
    _current_person: SignedInPerson,
    db: Database,
) -> list[DepartmentOut]:
    """Return active departments for the signed-in person's company."""

    return [
        DepartmentOut(id=department.id, name=department.name)
        for department in service.list_departments(db)
    ]
