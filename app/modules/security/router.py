"""Security events over HTTP (docs/features/detection.md, "Backend"). HTTP only: the
permission check and the rules are in service.py.

    GET /api/security-events[?kind=][&user_id=][&from=][&to=][&cursor=][&limit=]
                                       200  the company's events, newest first (paged)
    GET /api/security-events/summary   200  counts per kind, last 7 and 30 days

Both need security.view (Owner and Administrator by default). There is deliberately no
POST, PATCH, or DELETE: events are a record of what someone sent, and nobody changes or
removes them through the API (rows older than a year are removed by a nightly job).

Errors: 401 not signed in, 403 without security.view, 422 invalid filters.
"""

import uuid
from datetime import UTC, date
from typing import Annotated

from fastapi import APIRouter, Query

from app.auth.dependencies import Database, SignedInPerson
from app.modules.security import service
from app.modules.security.models import SecurityEvent
from app.modules.security.schemas import (
    KindCount,
    SecurityEventOut,
    SecurityEventPage,
    SecuritySummary,
)

router = APIRouter(prefix="/api/security-events", tags=["security"])


def _event(item: SecurityEvent, names: dict[uuid.UUID, str]) -> SecurityEventOut:
    """An event in the agreed answer shape; the excerpt is passed on unchanged."""
    return SecurityEventOut(
        id=item.id,
        kind=item.kind,
        pattern_id=item.pattern_id,
        field=item.field,
        method=item.method,
        route=item.route,
        user_id=item.user_id,
        user_name=names.get(item.user_id, ""),
        client_address=item.client_address,
        request_id=item.request_id,
        excerpt=item.excerpt,
        count=item.count,
        # Stored as UTC without a zone (MySQL DATETIME has none); sent with one.
        occurred_at=item.occurred_at.replace(tzinfo=UTC),
    )


@router.get("")
def list_events(
    current: SignedInPerson,
    db: Database,
    kind: Annotated[str | None, Query(max_length=50)] = None,
    user_id: uuid.UUID | None = None,
    first: Annotated[date | None, Query(alias="from")] = None,
    last: Annotated[date | None, Query(alias="to")] = None,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> SecurityEventPage:
    """The company's security events, newest first; from and to are days in the
    company's time zone, both included."""
    rows, next_cursor = service.list_events(
        db,
        current.user,
        kind=kind,
        user_id=user_id,
        first=first,
        last=last,
        cursor=cursor,
        limit=limit,
    )
    names = service.names_of(db, rows)
    return SecurityEventPage(items=[_event(row, names) for row in rows], next_cursor=next_cursor)


@router.get("/summary")
def summary(current: SignedInPerson, db: Database) -> SecuritySummary:
    """How many events of each kind happened in the last 7 and the last 30 days."""
    counts = service.summary(db, current.user)
    return SecuritySummary(
        kinds=[KindCount(kind=kind, **windows) for kind, windows in counts.items()]
    )
