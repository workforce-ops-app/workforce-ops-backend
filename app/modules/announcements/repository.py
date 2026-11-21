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

from sqlalchemy import ColumnElement, Select, and_, func, or_, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.modules.announcements.models import Announcement, AnnouncementRead
from app.modules.org.models import Department, Team, TeamMember, User


def department(db: Session, department_id: uuid.UUID) -> Department | None:
    """A department of the session's company (another company's looks like none)."""
    return db.get(Department, department_id)


def team(db: Session, team_id: uuid.UUID) -> Team | None:
    """A team of the session's company (another company's looks like none)."""
    return db.get(Team, team_id)


def person(db: Session, user_id: uuid.UUID) -> User | None:
    """A person of the session's company (another company's looks like none)."""
    return db.get(User, user_id)


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


# --- The managed list and the reader's list ---------------------------------------------


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


def _after(after: tuple[datetime, uuid.UUID]) -> ColumnElement[bool]:
    """Everything after a bookmark in the lists' sort order (newest first, then by ID)."""
    posted, last_id = after
    return or_(
        Announcement.created_at < posted,
        and_(Announcement.created_at == posted, Announcement.id < last_id),
    )


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
        conditions.append(_after(after))
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


def active_department(db: Session, department_id: uuid.UUID) -> Department | None:
    """A department of the session's company that is not archived."""
    found = db.get(Department, department_id)
    return found if found is not None and found.archived_at is None else None


def active_team_ids(db: Session, user_id: uuid.UUID) -> list[uuid.UUID]:
    """The active teams this person is on (an archived team reaches nobody).

    Looked up first, in a query of their own, because the company filter refuses
    subqueries: the reader's list then asks for "team_id IN (these teams)", as the scope
    filter does (app/authz/scope.py). Both joined models have a column in the select list,
    so the filter adds its company condition to each.
    """
    query = (
        select(Team.id, TeamMember.user_id)
        .join(TeamMember, TeamMember.team_id == Team.id)
        .where(TeamMember.user_id == user_id, Team.archived_at.is_(None))
    )
    return [row[0] for row in db.execute(query)]


def list_for_reader(
    db: Session,
    *,
    reader_id: uuid.UUID,
    department_id: uuid.UUID | None,
    team_ids: list[uuid.UUID],
    after: tuple[datetime, uuid.UUID] | None,
    limit: int,
) -> list[Any]:
    """One page of the active announcements whose audience includes the reader, newest
    first, with the author's name, the audience's names, and when the reader read each one.

    department_id is the reader's home department (None when it is archived) and team_ids
    the active teams they are on (active_team_ids), so the WHERE clause names exactly the
    reader's audiences and the database never even loads announcements meant for anyone
    else (the audience filter, threat I9).

    Explain in the presentation (course topic: SQL JOINs). One query does it all. It joins
    each announcement to its author (INNER JOIN: every announcement has one), to its
    department and its team (LEFT OUTER JOINs: a company audience has neither), and to the
    reader's own read mark (LEFT OUTER JOIN: no mark means not read yet). The WHERE clause
    keeps only the reader's audiences. In SQL it is roughly:

        SELECT announcements.*, users.display_name, departments.name, teams.name,
               announcement_reads.read_at
          FROM announcements
          JOIN users ON users.id = announcements.author_id
          LEFT OUTER JOIN departments ON departments.id = announcements.department_id
          LEFT OUTER JOIN teams ON teams.id = announcements.team_id
          LEFT OUTER JOIN announcement_reads
            ON announcement_reads.announcement_id = announcements.id
           AND announcement_reads.user_id = :reader
         WHERE announcements.archived_at IS NULL
           AND (announcements.audience_type = 'company'
             OR (announcements.audience_type = 'department'
                 AND announcements.department_id = :home)
             OR (announcements.audience_type = 'team'
                 AND announcements.team_id IN (:teams)))
         ORDER BY announcements.created_at DESC, announcements.id DESC
         LIMIT :limit

    The condition on the reader's ID sits in the ON clause, not in WHERE: in WHERE it would
    drop every announcement the reader has not read yet, which would turn the outer join
    into an inner one. The company filter adds "company_id = :company" to all five tables.
    """
    # 1. The reader's audiences: always the company; their home department, if active;
    #    the active teams they are on.
    audiences: list[ColumnElement[bool]] = [Announcement.audience_type == "company"]
    if department_id is not None:
        audiences.append(
            and_(
                Announcement.audience_type == "department",
                Announcement.department_id == department_id,
            )
        )
    if team_ids:
        audiences.append(
            and_(Announcement.audience_type == "team", Announcement.team_id.in_(team_ids))
        )
    # 2. Only active announcements: archived ones disappear for readers.
    conditions = [Announcement.archived_at.is_(None), or_(*audiences)]
    # 3. Everything after the bookmark, if there is one.
    if after is not None:
        conditions.append(_after(after))
    # 4. The query of the docstring, one row more than asked: tells whether another page
    #    exists.
    query = (
        select(
            Announcement,
            User.id,
            User.display_name,
            Department.name,
            Team.name,
            AnnouncementRead.read_at,
        )
        .join(User, User.id == Announcement.author_id)
        .outerjoin(Department, Department.id == Announcement.department_id)
        .outerjoin(Team, Team.id == Announcement.team_id)
        .outerjoin(
            AnnouncementRead,
            and_(
                AnnouncementRead.announcement_id == Announcement.id,
                AnnouncementRead.user_id == reader_id,
            ),
        )
        .where(*conditions)
        .order_by(Announcement.created_at.desc(), Announcement.id.desc())
        .limit(limit + 1)
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


# --- Who is in an audience --------------------------------------------------------------


def _with_audience[*Columns](query: Select[*Columns]) -> Select[*Columns]:
    """The query, joined from each announcement to the people in its audience now, and from
    each of those people to their read mark, if any.

    This is the one definition of "in the audience" for the read counts, the read list, and
    the check on one person (in_audience), so the three always agree. The reader's own list
    (list_for_reader) asks the same question the other way round, from one person to their
    announcements, and the tests compare the two for every person and audience.

    Who is in it is worked out now, as when someone reads (announcements.md): for a team,
    its members; for a department, the people whose home department it is; for the
    company, everyone. Deactivated people are in no audience, and an archived department or
    team reaches nobody (archived scopes cover nothing). Invited people (no password yet)
    are in it: they see it once they have set up their account.

    Course topic: SQL JOINs. In SQL it is roughly:

          FROM announcements
          LEFT OUTER JOIN departments ON departments.id = announcements.department_id
          LEFT OUTER JOIN teams ON teams.id = announcements.team_id
          LEFT OUTER JOIN team_members
            ON team_members.team_id = teams.id AND teams.archived_at IS NULL
          JOIN users ON users.deactivated_at IS NULL AND (
                announcements.audience_type = 'company'
             OR (announcements.audience_type = 'department'
                 AND users.department_id = announcements.department_id
                 AND departments.archived_at IS NULL)
             OR (announcements.audience_type = 'team' AND users.id = team_members.user_id))
          LEFT OUTER JOIN announcement_reads
            ON announcement_reads.announcement_id = announcements.id
           AND announcement_reads.user_id = users.id

    The LEFT OUTER JOINs to departments, teams, and team_members keep company audiences (no
    department, no team) and department audiences (no team) in the result. The inner join
    to users then leaves one row per person in the audience, and none at all when the
    audience is empty. The join to the read marks is outer again, so people who have not
    read it stay in, with no mark.

    The caller selects at least one column of every joined model, so the company filter
    sees each of them and adds its company condition to each join (tenancy.md: joins).
    """
    in_audience = and_(
        User.deactivated_at.is_(None),
        or_(
            Announcement.audience_type == "company",
            and_(
                Announcement.audience_type == "department",
                User.department_id == Announcement.department_id,
                Department.archived_at.is_(None),
            ),
            and_(Announcement.audience_type == "team", User.id == TeamMember.user_id),
        ),
    )
    return (
        query.select_from(Announcement)
        .outerjoin(Department, Department.id == Announcement.department_id)
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
    )


def counts(db: Session, announcement_ids: list[uuid.UUID]) -> dict[uuid.UUID, tuple[int, int]]:
    """For each announcement: (read_count, audience_count), counted in one query.

    The people in each audience come from _with_audience (one row per person). Grouping by
    announcement then counts the people (audience_count) and the read marks found among
    them (read_count), so read_count counts only the people in the audience now and
    matches the read list. In SQL, roughly:

        SELECT announcements.id, COUNT(users.id), COUNT(announcement_reads.user_id)
          <the joins of _with_audience>
         WHERE announcements.id IN (:page)
         GROUP BY announcements.id

    An announcement whose audience is empty has no rows at all, so the caller counts it as
    (0, 0). The department, team, and team member counts are not used: they are there so
    the company filter sees those joined models.
    """
    if not announcement_ids:
        return {}
    query = _with_audience(
        select(
            Announcement.id,
            func.count(User.id),
            func.count(AnnouncementRead.user_id),
            func.count(Department.id),
            func.count(Team.id),
            func.count(TeamMember.user_id),
        )
    )
    query = query.where(Announcement.id.in_(announcement_ids)).group_by(Announcement.id)
    return {row[0]: (row[2], row[1]) for row in db.execute(query)}


def in_audience(db: Session, announcement_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """Whether this person is in this announcement's audience now (the definition of
    _with_audience, asked for one person)."""
    query = _with_audience(
        select(
            User.id,
            # Not used: there so the company filter sees every joined model.
            Announcement.id,
            Department.id,
            Team.id,
            TeamMember.user_id,
            AnnouncementRead.user_id,
        )
    )
    query = query.where(Announcement.id == announcement_id, User.id == user_id).limit(1)
    return db.execute(query).first() is not None


def list_reads(
    db: Session,
    announcement_id: uuid.UUID,
    *,
    after: tuple[str, uuid.UUID] | None,
    limit: int,
) -> list[Any]:
    """One page of the people in an announcement's audience now, in name order (display
    name, then ID), each with when they read it (None: not yet).

    The people come from _with_audience, so this list holds exactly the people that
    audience_count counts, and its read marks exactly the ones read_count counts. Paging
    is done in the database (ORDER BY ... LIMIT), so a company-wide announcement never
    loads everyone at once (threat D2).
    """
    conditions: list[ColumnElement[bool]] = [Announcement.id == announcement_id]
    if after is not None:
        # Everyone after the bookmark in name order (then by ID, for people with the same
        # name).
        name, last_id = after
        conditions.append(
            or_(User.display_name > name, and_(User.display_name == name, User.id > last_id))
        )
    query = _with_audience(
        select(
            User.id,
            User.display_name,
            AnnouncementRead.read_at,
            # Not used: there so the company filter sees every joined model.
            Announcement.id,
            Department.id,
            Team.id,
            TeamMember.user_id,
        )
    )
    query = (
        query.where(*conditions)
        .order_by(User.display_name, User.id)
        .limit(limit + 1)  # one more than asked: tells whether another page exists
    )
    return list(db.execute(query).all())


# --- Read marks -------------------------------------------------------------------------


def read_mark(
    db: Session, announcement_id: uuid.UUID, user_id: uuid.UUID
) -> AnnouncementRead | None:
    """This person's read mark on this announcement, if they have read it."""
    return db.get(AnnouncementRead, (announcement_id, user_id))


def add_read_mark(db: Session, announcement_id: uuid.UUID, user_id: uuid.UUID) -> None:
    """Add a read mark (the company filter fills in the session's company). It is sent to
    the database at the caller's commit, where the primary key refuses a second one."""
    db.add(AnnouncementRead(announcement_id=announcement_id, user_id=user_id, read_at=utcnow()))
