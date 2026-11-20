"""Announcements over HTTP (docs/features/announcements.md, decision 0026). HTTP only: the
rules and the permission checks are in service.py.

Course topic: REST. Each URL names a thing (the announcements meant for you, the ones
someone manages, one announcement, or who has read it), the HTTP method says what to do
with it, and the status code says how it went:

    GET   /api/announcements?cursor=&limit=                             200  yours (paged)
    GET   /api/announcements/managed?cursor=&limit=&include_archived=   200  managed (paged)
    GET   /api/announcements/audiences                                  200  where you may post
    GET   /api/announcements/{id}                                       200  one
    POST  /api/announcements                                            201  post
    PATCH /api/announcements/{id}  {title?, body?}                      200  correct the text
    POST  /api/announcements/{id}/archive                               200  archive
    POST  /api/announcements/{id}/read                                  204  mark read
    GET   /api/announcements/{id}/reads?cursor=&limit=                  200  who read it (paged)

Errors: 401 not signed in, 403 not allowed, 404 not found (or another company's, or not
meant for you), 409 not allowed in the current state (archived announcement, department,
or team), 422 invalid input.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Query, Response

from app.auth.dependencies import Database, SignedInPerson
from app.modules.announcements import repository, service
from app.modules.announcements.models import Announcement
from app.modules.announcements.schemas import (
    AnnouncementCreate,
    AnnouncementDetailOut,
    AnnouncementManagedOut,
    AnnouncementManagedPage,
    AnnouncementOut,
    AnnouncementPage,
    AnnouncementUpdate,
    AudienceChoice,
    AudienceChoiceList,
    AudienceOut,
    AuthorRef,
    ReadOut,
    ReadPage,
    utc,
)

router = APIRouter(prefix="/api/announcements", tags=["announcements"])


def _fields(
    item: Announcement, author_name: str, department_name: str | None, team_name: str | None
) -> dict[str, Any]:
    """The fields every answer shape shares, in the agreed form."""
    return {
        "id": item.id,
        "audience": AudienceOut(
            type=item.audience_type,
            department_id=item.department_id,
            department_name=department_name,
            team_id=item.team_id,
            team_name=team_name,
        ),
        "title": item.title,
        "body": item.body,
        "author": AuthorRef(id=item.author_id, display_name=author_name),
        "posted_at": utc(item.created_at),
        "edited_at": utc(item.edited_at) if item.edited_at else None,
        "archived": item.archived_at is not None,
    }


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
        **_fields(item, author_name, department_name, team_name),
        read_count=read_count,
        audience_count=audience_count,
    )


def _one(db: Database, item: Announcement) -> AnnouncementManagedOut:
    return _out(item, *repository.names(db, item), service.counts_for(db, item))


@router.get("")
def list_announcements(
    current: SignedInPerson,
    db: Database,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AnnouncementPage:
    """The active announcements whose audience includes you, newest first."""
    rows, next_cursor = service.list_for_reader(db, current.user, cursor=cursor, limit=limit)
    # Each row: the announcement, the author's ID and name, the department's and team's
    # names, and when you read it (None: not yet) (repository.list_for_reader).
    items = [
        AnnouncementOut(**_fields(row[0], row[2], row[3], row[4]), read=row[5] is not None)
        for row in rows
    ]
    return AnnouncementPage(items=items, next_cursor=next_cursor)


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


@router.get("/audiences")
def list_audiences(current: SignedInPerson, db: Database) -> AudienceChoiceList:
    """The audiences you may post to, for the posting form (declared before /{id}, so
    "audiences" is never read as an announcement's ID)."""
    choices = []
    for item in service.postable_audiences(db, current.user):
        # The names the form shows: the department's or team's, and a team's department
        # (already loaded by the session, so these look-ups send no new queries).
        team = repository.team(db, item.team_id) if item.team_id else None
        department_id = team.department_id if team else item.department_id
        department = repository.department(db, department_id) if department_id else None
        choices.append(
            AudienceChoice(
                type=item.audience_type,
                department_id=item.department_id,
                team_id=item.team_id,
                name=team.name if team else (department.name if department else None),
                department_name=department.name if team and department else None,
            )
        )
    return AudienceChoiceList(items=choices)


@router.get("/{announcement_id}")
def view_announcement(
    announcement_id: uuid.UUID, current: SignedInPerson, db: Database
) -> AnnouncementDetailOut:
    """One announcement: yours to read, or one you manage (with its read counts)."""
    item, read, counts = service.view_announcement(db, current.user, announcement_id)
    read_count, audience_count = counts if counts is not None else (None, None)
    return AnnouncementDetailOut(
        **_fields(item, *repository.names(db, item)),
        read=read,
        read_count=read_count,
        audience_count=audience_count,
    )


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


@router.post("/{announcement_id}/read", status_code=204)
def mark_read(announcement_id: uuid.UUID, current: SignedInPerson, db: Database) -> Response:
    """Record that you have read it (the same again changes nothing)."""
    service.mark_read(db, current.user, announcement_id)
    return Response(status_code=204)


@router.get("/{announcement_id}/reads")
def list_reads(
    announcement_id: uuid.UUID,
    current: SignedInPerson,
    db: Database,
    cursor: Annotated[str | None, Query(max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ReadPage:
    """The people in the audience now, by name, each with when they read it."""
    rows, next_cursor = service.list_reads(
        db, current.user, announcement_id, cursor=cursor, limit=limit
    )
    # Each row: the person's ID and display name, and when they read it (None: not yet)
    # (repository.list_reads).
    items = [
        ReadOut(id=row[0], display_name=row[1], read_at=utc(row[2]) if row[2] else None)
        for row in rows
    ]
    return ReadPage(items=items, next_cursor=next_cursor)
