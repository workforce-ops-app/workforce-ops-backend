"""The rules for posting and managing announcements (docs/features/announcements.md).

Every function checks permission with authorize() before it reveals or changes anything,
writes its audit entry in the same transaction as the change, and commits once at the end.

Rules:
- The audience is exactly one of: the company, one department, or one team of the poster's
  company. The ID the type needs must be sent, and no other (422). An unknown department
  or team, or another company's, is 422 like any unknown reference in a body.
- Posting, editing, and archiving need announcement.create whose scope covers the audience
  (app/modules/announcements/scope.py): a company audience needs a company-wide
  assignment (403 otherwise). Anyone whose scope covers it may edit or archive it, not
  only its author.
- The audience is fixed once posted, so an announcement never moves to other people.
- No new announcement goes to an archived department or team (409).
- Title 1 to 120 characters, body 1 to 4,000, surrounding spaces removed (schemas.py);
  stored exactly as typed, never as HTML (T5) and never as a template (I7).
- An archived announcement cannot be edited, or archived again (409). Announcements are
  never deleted (decision 0020).
- The audit entries name the audience and the changed fields, never the text itself.
"""

import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.authz.check import authorize, scope_filter
from app.authz.scope import ScopeColumns
from app.db.base import utcnow
from app.modules.announcements import repository
from app.modules.announcements import scope as _scope  # noqa: F401  (registers the resolver)
from app.modules.announcements.models import Announcement
from app.modules.announcements.schemas import AnnouncementCreate, AnnouncementUpdate
from app.modules.org.models import User

PERMISSION = "announcement.create"


class Invalid(HTTPException):
    """422: the request itself is not acceptable."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=422, detail=detail)


class Conflict(HTTPException):
    """409: not allowed in the announcement's (or its audience's) current state."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=409, detail=detail)


class NotFound(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=404, detail="Not found.")


def post_announcement(db: Session, user: User, body: AnnouncementCreate) -> Announcement:
    """Post a new announcement to one audience."""
    # 1. The audience: exactly the ID its type needs, and no other.
    if body.audience_type == "company" and (body.department_id or body.team_id):
        raise Invalid("A company-wide announcement has no department or team.")
    if body.audience_type == "department" and (body.department_id is None or body.team_id):
        raise Invalid("A department announcement needs a department_id and no team_id.")
    if body.audience_type == "team" and (body.team_id is None or body.department_id):
        raise Invalid("A team announcement needs a team_id and no department_id.")

    # 2. The department or team must exist in the user's company. Another company's is
    #    hidden by the company filter, so it gets exactly the answer of one that does not
    #    exist (no hint that it exists elsewhere).
    archived = False
    if body.department_id is not None:
        dept = repository.department(db, body.department_id)
        if dept is None:
            raise Invalid("Unknown department.")
        archived = dept.archived_at is not None
    if body.team_id is not None:
        crew = repository.team(db, body.team_id)
        if crew is None:
            raise Invalid("Unknown team.")
        archived = crew.archived_at is not None

    # 3. The new announcement, not saved yet. The author and the company come from the
    #    session, never from the body (T2).
    item = Announcement(
        company_id=user.company_id,
        author_id=user.id,
        audience_type=body.audience_type,
        department_id=body.department_id,
        team_id=body.team_id,
        title=body.title,
        body=body.body,
    )

    # 4. May the user post to this audience? (E11: a team lead cannot write to the whole
    #    department or the company.)
    authorize(db, user, PERMISSION, item)

    # 5. Nothing new goes to an archived department or team (organization.md); its
    #    existing announcements stay as history.
    if archived:
        raise Conflict("This department or team is archived. Announcements cannot be posted to it.")

    # 6. Save it, with its audit entry in the same transaction. The text is not copied into
    #    the audit log, only who it was for.
    db.add(item)
    db.flush()  # gives the announcement its ID
    audience_id = item.department_id or item.team_id  # none for the company
    record(
        db,
        actor=Actor.user(user.id),
        action="announcement.posted",
        target_type="announcement",
        target_id=item.id,
        details={
            "audience_type": item.audience_type,
            "audience_id": str(audience_id) if audience_id else None,
        },
    )
    db.commit()
    return item


def _changeable(db: Session, user: User, announcement_id: uuid.UUID) -> Announcement:
    """The announcement, checked and locked for a change by this user.

    1. It must exist in the user's company (404 otherwise, another company's too).
    2. The user's announcement.create must cover its audience (403).
    3. Its row is locked and read fresh, so a change that waited for someone else's
       archive sees the announcement as archived.
    4. An archived announcement is history: it cannot be changed (409).
    """
    item = repository.announcement(db, announcement_id)
    if item is None:
        raise NotFound()
    authorize(db, user, PERMISSION, item)
    # Permission is checked before the lock, so someone who may not change it never
    # waits for, or holds, its lock. The audience never changes, so the check still holds
    # for the fresh copy.
    item = repository.announcement(db, announcement_id, lock=True)
    if item is None:  # announcements are never deleted, so this does not happen
        raise NotFound()
    if item.archived_at is not None:
        raise Conflict("This announcement is archived and can no longer be changed.")
    return item


def edit_announcement(
    db: Session, user: User, announcement_id: uuid.UUID, body: AnnouncementUpdate
) -> Announcement:
    """Correct the title or the body. Only the fields sent are changed (and are listed in
    the audit entry by name, never with their text). Who has read it stays as it was."""
    # 1. Found, allowed, locked, and not archived (see _changeable).
    item = _changeable(db, user, announcement_id)

    # 2. Apply the fields that were sent. Sending one as null is a mistake: an
    #    announcement always has a title and a body.
    changed = sorted(body.model_fields_set)
    for field in changed:
        value = getattr(body, field)
        if value is None:
            raise Invalid("An announcement must have a title and a body.")
        setattr(item, field, value)

    # 3. Mark it edited and record the change (nothing sent: nothing changed, nothing
    #    recorded).
    if changed:
        item.edited_at = utcnow()
        record(
            db,
            actor=Actor.user(user.id),
            action="announcement.edited",
            target_type="announcement",
            target_id=item.id,
            details={"fields": changed},
        )
    db.commit()
    return item


def archive_announcement(db: Session, user: User, announcement_id: uuid.UUID) -> Announcement:
    """Archive an announcement: readers no longer see it; it stays for history."""
    # 1. Found, allowed, locked, and not archived already (see _changeable).
    item = _changeable(db, user, announcement_id)
    # 2. Archive it, with its audit entry.
    item.archived_at = utcnow()
    record(
        db,
        actor=Actor.user(user.id),
        action="announcement.archived",
        target_type="announcement",
        target_id=item.id,
    )
    db.commit()
    return item


def list_managed(
    db: Session,
    user: User,
    *,
    cursor: str | None,
    limit: int,
    include_archived: bool,
) -> tuple[list[Any], dict[uuid.UUID, tuple[int, int]], str | None]:
    """A page of the announcements whose audience the user's assignments cover, newest
    first; their (read_count, audience_count); and the cursor for the next page."""
    # 1. The cursor must be one of ours.
    after = None
    if cursor is not None:
        after = repository.decode_cursor(cursor)
        if after is None:
            raise Invalid("This cursor is not valid.")

    # 2. May the user manage announcements anywhere? Someone who may not (an employee)
    #    gets 403, not an empty list.
    authorize(db, user, PERMISSION)

    # 3. Only the rows the user's assignments cover, by the same rules as authorize()
    #    (the scope filter with the announcement's department and team columns).
    columns = ScopeColumns(department=Announcement.department_id, team=Announcement.team_id)
    allowed = scope_filter(db, user, PERMISSION, columns)

    # 4. One page, plus one row to tell whether another page exists.
    rows = repository.list_managed(
        db, allowed=allowed, include_archived=include_archived, after=after, limit=limit
    )
    page, more = rows[:limit], len(rows) > limit
    next_cursor = repository.encode_cursor(page[-1][0]) if more else None

    # 5. The read counts for this page only, in one query.
    counted = repository.counts(db, [row[0].id for row in page])
    return page, counted, next_cursor


def counts_for(db: Session, item: Announcement) -> tuple[int, int]:
    """(read_count, audience_count) of one announcement, for the answer to a change. The
    caller has already been authorized for it."""
    return repository.counts(db, [item.id]).get(item.id, (0, 0))
