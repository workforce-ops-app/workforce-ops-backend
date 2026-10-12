"""Business operations for organization data."""

from sqlalchemy.orm import Session

from app.modules.org import repository
from app.modules.org.models import Department


def list_departments(db: Session) -> list[Department]:
    """List active departments visible within the signed-in company."""

    return repository.list_active_departments(db)
