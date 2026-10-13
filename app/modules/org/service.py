"""Business operations for organization data."""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.modules.org import repository
from app.modules.org.models import Department


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
