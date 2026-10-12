"""Database queries for organization data."""

import base64
import binascii
import json
import uuid

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.modules.org.models import Department


def encode_cursor(item: Department) -> str:
    """Encode the last department's name and ID as the next-page bookmark."""

    raw = json.dumps({"n": item.name, "i": str(item.id)}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[str, uuid.UUID] | None:
    """Decode one of this list's bookmarks, or return None when it is invalid."""

    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        name = raw["n"]
        if not isinstance(name, str):
            return None
        return name, uuid.UUID(raw["i"])
    except (
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ):
        return None


def list_active_departments(
    db: Session,
    *,
    after: tuple[str, uuid.UUID] | None,
    limit: int,
) -> list[Department]:
    """Return one page of the current tenant's active departments in name order."""

    # Course topic: SQL. The WHERE leaves out archived rows, ORDER BY makes paging
    # predictable, and LIMIT asks for one extra row so the service can detect another
    # page. The tenant-aware session automatically adds WHERE company_id = :company.
    statement = (
        select(Department)
        .where(Department.archived_at.is_(None))
        .order_by(Department.name, Department.id)
        .limit(limit + 1)
    )
    if after is not None:
        name, last_id = after
        statement = statement.where(
            or_(
                Department.name > name,
                and_(Department.name == name, Department.id > last_id),
            )
        )
    return list(db.scalars(statement))
