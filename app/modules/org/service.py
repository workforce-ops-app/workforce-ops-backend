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

    # Turn the public cursor back into the repository's (name, ID) sort position.
    after = None
    if cursor is not None:
        after = repository.decode_cursor(cursor)
        if after is None:
            raise HTTPException(status_code=422, detail="This cursor is not valid.")

    rows = repository.list_active_departments(db, after=after, limit=limit)
    page, more = rows[:limit], len(rows) > limit
    next_cursor = repository.encode_cursor(page[-1]) if more else None
    return page, next_cursor
