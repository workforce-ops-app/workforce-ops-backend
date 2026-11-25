"""Every database query of the announcements module (the only file here that talks to the
database).

All queries are built with SQLAlchemy, so every value is sent as a bound parameter, never
pasted into SQL text (SQL injection, threat T1), and the company filter adds "company_id =
<the session's company>" to each of them, joins included (tenancy.md).
"""

import base64
import binascii
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ColumnElement, and_, func, or_, select
from sqlalchemy.orm import Session

from app.modules.announcements.models import Announcement, AnnouncementRead
from app.modules.org.models import Department, Team, TeamMember, User


def department(db: Session, department_id: uuid.UUID) -> Department | None:
    """A department of the session's company (another company's looks like none)."""
    return db.get(Department, department_id)


def team(db: Session, team_id: uuid.UUID) -> Team | None:
    """A team of the session's company (another company's looks like none)."""
    return db.get(Team, team_id)


def announcement(
    db: Session, announcement_id: uuid.UUID, *, lock: bool = False
) -> Announcement | None:
    """One announcement of the session's company (another company's looks like none: 404).

    lock=True locks its row until the transaction ends (SELECT ... FOR UPDATE) and reads
    its newest committed version, replacing the copy this session already loaded
    (populate_existing). An edit that waited for someone else's archive then sees the
    announcement as archived, and is refused (409) instead of changing it.
    """
    return db.get(Announcement, announcement_id, with_for_update=lock, populate_existing=lock)


# --- The managed list -------------------------------------------------------------------


def encode_cursor(item: Announcement) -> str:
    """A bookmark to the last announcement of a page: when it was posted, and its ID (the
    list's sort order)."""
    raw = json.dumps({"c": item.created_at.isoformat(), "i": str(item.id)}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID] | None:
    """The bookmark inside a cursor, or None if it is not one of ours."""
    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        return datetime.fromisoformat(raw["c"]), uuid.UUID(raw["i"])
    except (binascii.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def list_managed(
    db: Session,
    *,
    allowed: ColumnElement[bool],
    include_archived: bool,
    after: tuple[datetime, uuid.UUID] | None,
    limit: int,
) -> list[Any]:
    """One page of the announcements the user manages, newest first, with the names the
    answer shows: the author's, and the audience's department or team.

    Course topic: SQL JOINs. One query joins each announcement to its author (INNER JOIN:
    every announcement has one) and to its department and its team (LEFT OUTER JOINs: a
    company audience has neither, a department audience no team, a team audience no
    department, and each must still be listed). In SQL it is roughly:

        SELECT announcements.*, users.display_name, departments.name, teams.name
          FROM announcements
          JOIN users ON users.id = announcements.author_id
          LEFT OUTER JOIN departments ON departments.id = announcements.department_id
          LEFT OUTER JOIN teams ON teams.id = announcements.team_id
         WHERE <the user's scopes> AND announcements.archived_at IS NULL
         ORDER BY announcements.created_at DESC, announcements.id DESC
         LIMIT :limit

    The company filter adds "company_id = :company" for all four tables, and `allowed` is
    the scope condition from authz (only the announcements the user's assignments cover).
    """
    conditions = [allowed]
    if not include_archived:
        conditions.append(Announcement.archived_at.is_(None))
    if after is not None:
        # Everything after the bookmark in the sort order (newest first, then by ID).
        posted, last_id = after
        conditions.append(
            or_(
                Announcement.created_at < posted,
                and_(Announcement.created_at == posted, Announcement.id < last_id),
            )
        )
    query = (
        select(Announcement, User.id, User.display_name, Department.name, Team.name)
        .join(User, User.id == Announcement.author_id)
        .outerjoin(Department, Department.id == Announcement.department_id)
        .outerjoin(Team, Team.id == Announcement.team_id)
        .where(*conditions)
        .order_by(Announcement.created_at.desc(), Announcement.id.desc())
        .limit(limit + 1)  # one more than asked: tells whether another page exists
    )
    return list(db.execute(query).all())


def names(db: Session, item: Announcement) -> tuple[str, str | None, str | None]:
    """The author's display name and the audience's department and team names, for one
    announcement's answer (the same names the list joins in)."""
    author = db.get(User, item.author_id)
    dept = db.get(Department, item.department_id) if item.department_id else None
    crew = db.get(Team, item.team_id) if item.team_id else None
    return (
        author.display_name if author is not None else "",
        dept.name if dept is not None else None,
        crew.name if crew is not None else None,
    )


def counts(db: Session, announcement_ids: list[uuid.UUID]) -> dict[uuid.UUID, tuple[int, int]]:
    """For each announcement: (read_count, audience_count), counted in one query.

    The audience is worked out now, as when someone reads (announcements.md): for a team,
    its members; for a department, the people whose home department it is; for the
    company, everyone. Deactivated people are in no audience, and an archived team's
    audience is empty (archived scopes cover nothing). read_count counts only the people
    in the audience now, so it matches the read list (AN2).

    Course topic: SQL JOINs. Each announcement is joined to the people in its audience,
    and each of those people to their read mark, if any. Grouping by announcement then
    counts the people (audience_count) and the marks found (read_count). In SQL, roughly:

        SELECT announcements.id, COUNT(users.id), COUNT(announcement_reads.user_id)
          FROM announcements
          LEFT OUTER JOIN teams ON teams.id = announcements.team_id
          LEFT OUTER JOIN team_members
            ON team_members.team_id = teams.id AND teams.archived_at IS NULL
          JOIN users ON users.deactivated_at IS NULL AND (
                announcements.audience_type = 'company'
             OR (announcements.audience_type = 'department'
                 AND users.department_id = announcements.department_id)
             OR (announcements.audience_type = 'team' AND users.id = team_members.user_id))
          LEFT OUTER JOIN announcement_reads
            ON announcement_reads.announcement_id = announcements.id
           AND announcement_reads.user_id = users.id
         WHERE announcements.id IN (:page)
         GROUP BY announcements.id

    The LEFT OUTER JOIN to team_members keeps company and department audiences (they have
    no team) in the result. An announcement whose audience is empty has no rows at all
    after the inner join to users, so it is counted as 0 by the caller.

    Every joined model has a column in the select list (the team counts are not used
    otherwise), so the company filter sees each of them and adds its company condition
    to each join (tenancy.md: joins).
    """
    if not announcement_ids:
        return {}
    in_audience = and_(
        User.deactivated_at.is_(None),
        or_(
            Announcement.audience_type == "company",
            and_(
                Announcement.audience_type == "department",
                User.department_id == Announcement.department_id,
            ),
            and_(Announcement.audience_type == "team", User.id == TeamMember.user_id),
        ),
    )
    query = (
        select(
            Announcement.id,
            func.count(User.id),
            func.count(AnnouncementRead.user_id),
            func.count(Team.id),
            func.count(TeamMember.user_id),
        )
        .outerjoin(Team, Team.id == Announcement.team_id)
        .outerjoin(TeamMember, and_(TeamMember.team_id == Team.id, Team.archived_at.is_(None)))
        .join(User, in_audience)
        .outerjoin(
            AnnouncementRead,
            and_(
                AnnouncementRead.announcement_id == Announcement.id,
                AnnouncementRead.user_id == User.id,
            ),
        )
        .where(Announcement.id.in_(announcement_ids))
        .group_by(Announcement.id)
    )
    return {row[0]: (row[2], row[1]) for row in db.execute(query)}
