"""Announcements over HTTP (docs/features/announcements.md, decision 0026). HTTP only: the
rules and the permission checks are in service.py.

Course topic: REST. Each URL names a thing (the announcements someone manages, or one
announcement), the HTTP method says what to do with it, and the status code says how it
went:

    GET   /api/announcements/managed?cursor=&limit=&include_archived=   200  list (paged)
    POST  /api/announcements                                            201  post
    PATCH /api/announcements/{id}  {title?, body?}                      200  correct the text
    POST  /api/announcements/{id}/archive                               200  archive

Reading (the reader's list, one announcement, read marks, and the read list) arrives with
AN2.

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's), 409 not
allowed in the current state (archived announcement, department, or team), 422 invalid
input.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query

from app.auth.dependencies import Database, SignedInPerson
from app.modules.announcements import repository, service
from app.modules.announcements.models import Announcement
from app.modules.announcements.schemas import (
    AnnouncementCreate,
    AnnouncementManagedOut,
    AnnouncementManagedPage,
    AnnouncementUpdate,
    AudienceOut,
    AuthorRef,
    utc,
)

router = APIRouter(prefix="/api/announcements", tags=["announcements"])


def _out(
    item: Announcement,
    author_name: str,
    department_name: str | None,
    team_name: str | None,
    counts: tuple[int, int],
) -> AnnouncementManagedOut:
    """An announcement in the agreed answer shape, for the people who manage it."""
    read_count, audience_count = counts
    return AnnouncementManagedOut(
        id=item.id,
        audience=AudienceOut(
            type=item.audience_type,
            department_id=item.department_id,
            department_name=department_name,
            team_id=item.team_id,
            team_name=team_name,
        ),
        title=item.title,
        body=item.body,
        author=AuthorRef(id=item.author_id, display_name=author_name),
        posted_at=utc(item.created_at),
        edited_at=utc(item.edited_at) if item.edited_at else None,
        archived=item.archived_at is not None,
        read_count=read_count,
        audience_count=audience_count,
    )


def _one(db: Database, item: Announcement) -> AnnouncementManagedOut:
    return _out(item, *repository.names(db, item), service.counts_for(db, item))


@router.get("/managed")
def list_managed(
    current: SignedInPerson,
    db: Database,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    include_archived: bool = False,
) -> AnnouncementManagedPage:
    """The announcements whose audience your assignments cover, newest first."""
    rows, counted, next_cursor = service.list_managed(
        db, current.user, cursor=cursor, limit=limit, include_archived=include_archived
    )
    # Each row: the announcement, the author's ID and name, the department's and team's
    # names (repository.list_managed).
    items = [_out(row[0], row[2], row[3], row[4], counted.get(row[0].id, (0, 0))) for row in rows]
    return AnnouncementManagedPage(items=items, next_cursor=next_cursor)


@router.post("", status_code=201)
def post_announcement(
    body: AnnouncementCreate, current: SignedInPerson, db: Database
) -> AnnouncementManagedOut:
    return _one(db, service.post_announcement(db, current.user, body))


@router.patch("/{announcement_id}")
def edit_announcement(
    announcement_id: uuid.UUID, body: AnnouncementUpdate, current: SignedInPerson, db: Database
) -> AnnouncementManagedOut:
    return _one(db, service.edit_announcement(db, current.user, announcement_id, body))


@router.post("/{announcement_id}/archive")
def archive_announcement(
    announcement_id: uuid.UUID, current: SignedInPerson, db: Database
) -> AnnouncementManagedOut:
    return _one(db, service.archive_announcement(db, current.user, announcement_id))
