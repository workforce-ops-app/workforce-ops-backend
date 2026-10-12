"""Database queries for organization data."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.org.models import Department


def list_active_departments(db: Session) -> list[Department]:
    """Return the current tenant's active departments in name order."""

    statement = select(Department).where(Department.archived_at.is_(None)).order_by(Department.name)
    return list(db.scalars(statement))
