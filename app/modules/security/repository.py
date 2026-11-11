"""Every database query of the security module (the only file here that talks to the
database, decision 0004).

The writer runs outside any request (in the detection worker thread, DT4), so these
functions open their own short sessions from the engine instead of using a request's.
Rows are only ever INSERTED here, or deleted once a year old: never updated (rule DE6).
"""

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import Engine, delete, select
from sqlalchemy.orm import Session

from app.modules.org.models import Company
from app.modules.security.models import PlatformSecurityEvent, SecurityEvent
from app.tenancy.context import set_company


def insert_company_events(engine: Engine, company_id: uuid.UUID, rows: Sequence[dict]) -> None:
    """Insert one company's events, in a session working for that company.

    company_id is not passed to the rows: the company filter fills it in from the session
    (tenancy layer 1), and the (company_id, user_id) key makes the database refuse a person
    of another company (layer 2).
    """
    with Session(engine) as db:
        set_company(db, company_id)
        db.add_all([SecurityEvent(**row) for row in rows])
        db.commit()


def insert_platform_events(engine: Engine, rows: Sequence[dict]) -> None:
    """Insert events that belong to no company, in a session with no company."""
    with Session(engine) as db:
        db.add_all([PlatformSecurityEvent(**row) for row in rows])
        db.commit()


def remove_events_before(engine: Engine, before: datetime) -> tuple[int, int]:
    """Delete rows that occurred before `before` from both tables.

    Returns (company rows removed, platform rows removed).

    The company filter refuses company tables in a session with no company, so each
    company's old rows are deleted in that company's own session: the filter adds
    "company_id = <that company>" to the delete, as for every other query.
    """
    # 1. Which companies exist (a session with no company may read the companies table).
    with Session(engine) as platform:
        company_ids = list(platform.scalars(select(Company.id)))

    # 2. Each company's old events, in its own session.
    company_rows = 0
    for company_id in company_ids:
        with Session(engine) as db:
            set_company(db, company_id)
            result = db.execute(delete(SecurityEvent).where(SecurityEvent.occurred_at < before))
            db.commit()
            company_rows += result.rowcount  # type: ignore[attr-defined]

    # 3. The platform's old events.
    with Session(engine) as platform:
        result = platform.execute(
            delete(PlatformSecurityEvent).where(PlatformSecurityEvent.occurred_at < before)
        )
        platform.commit()
        platform_rows: int = result.rowcount  # type: ignore[attr-defined]
    return company_rows, platform_rows
