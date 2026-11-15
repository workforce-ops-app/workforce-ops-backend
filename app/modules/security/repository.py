"""Every database query of the security module (the only file here that talks to the
database, decision 0004).

Two kinds of functions:
- For the writer, which runs outside any request (in the detection worker thread, DT4):
  these open their own short sessions from the engine instead of using a request's.
  Rows are only ever INSERTED here, or deleted once a year old: never updated (rule DE6).
- For the security page's endpoints (DT5): these only READ, in the request's own session,
  which works for the signed-in person's company, so the company filter adds
  "company_id = <that company>" to every query (tenancy.md). They read security_events
  only; nothing in a request ever reads platform_security_events.

Every value goes into the queries as a bound parameter, never into SQL text (threat T1):
the filters on this page are exactly the kind of text an attacker would type.
"""

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import Engine, and_, delete, func, or_, select
from sqlalchemy.orm import Session

from app.modules.org.models import Company, User
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


# --- Reading, for the security page (DT5) ----------------------------------------------


def event(db: Session, event_id: uuid.UUID) -> SecurityEvent | None:
    """One of the company's events (another company's looks like none), for the cursor."""
    return db.get(SecurityEvent, event_id)


def list_events(
    db: Session,
    *,
    kind: str | None,
    user_id: uuid.UUID | None,
    start: datetime | None,
    end: datetime | None,
    after: tuple[datetime, uuid.UUID] | None,
    limit: int,
) -> list[SecurityEvent]:
    """One page of the company's events, newest first, with the filters that were given.

    start and end are UTC moments: start included, end not. `after` is the last event of
    the previous page (its time and ID), so the next page starts just past it.
    """
    statement = (
        select(SecurityEvent)
        .order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id.desc())
        .limit(limit + 1)  # one more than asked: tells whether another page exists
    )
    if kind is not None:
        statement = statement.where(SecurityEvent.kind == kind)
    if user_id is not None:
        # Another company's person matches nothing: the company filter already limits
        # the rows to this company, so the answer is an empty page, never their events.
        statement = statement.where(SecurityEvent.user_id == user_id)
    if start is not None:
        statement = statement.where(SecurityEvent.occurred_at >= start)
    if end is not None:
        statement = statement.where(SecurityEvent.occurred_at < end)
    if after is not None:
        moment, last_id = after
        # Newest first, so the next page is everything OLDER than the bookmark (and, at
        # the same moment, with a smaller ID).
        statement = statement.where(
            or_(
                SecurityEvent.occurred_at < moment,
                and_(SecurityEvent.occurred_at == moment, SecurityEvent.id < last_id),
            )
        )
    return list(db.scalars(statement))


def names(db: Session, user_ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    """The display names of these people, in one query for a whole page of events."""
    if not user_ids:
        return {}
    rows = db.execute(select(User.id, User.display_name).where(User.id.in_(user_ids)))
    return {user_id: name for user_id, name in rows}


def counts_since(db: Session, since: datetime) -> dict[str, int]:
    """How many events of each kind happened since `since`, by kind.

    A summary row stands for `count` events the rate cap held back, so the counts add up
    the count column rather than counting rows.
    """
    rows = db.execute(
        select(SecurityEvent.kind, func.sum(SecurityEvent.count))
        .where(SecurityEvent.occurred_at >= since)
        .group_by(SecurityEvent.kind)
    )
    return {kind: int(total or 0) for kind, total in rows}
