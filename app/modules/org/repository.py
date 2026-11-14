"""Database queries for organization data (the only file here that talks to the database).

All queries are built with SQLAlchemy, so every value is sent as a bound parameter, never
pasted into SQL text (SQL injection, threat T1), and the company filter adds "company_id =
<the session's company>" to each of them (tenancy.md).
"""

import base64
import binascii
import json
import uuid
from datetime import datetime

from sqlalchemy import ColumnElement, and_, delete, func, or_, select
from sqlalchemy.orm import Session

from app.modules.org.models import Department, Team, TeamMember, User

# --- Cursors (shared by the department and team lists) ------------------------------


def encode_cursor(item_id: uuid.UUID) -> str:
    """Encode the last item's ID as the next-page bookmark."""

    raw = json.dumps({"i": str(item_id)}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> uuid.UUID | None:
    """Decode one of these lists' bookmarks, or return None when it is invalid."""

    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        return uuid.UUID(raw["i"])
    except (
        binascii.Error,
        UnicodeDecodeError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ):
        return None


# --- Departments -----------------------------------------------------------------------


def department(db: Session, department_id: uuid.UUID, *, lock: bool = False) -> Department | None:
    """A department of the session's company, archived or not (another company's looks like
    none: 404). lock=True locks its row until the transaction ends (SELECT ... FOR UPDATE)
    and reads it fresh, so changes to one department take turns."""
    return db.get(Department, department_id, with_for_update=lock, populate_existing=lock)


def active_department(db: Session, department_id: uuid.UUID) -> Department | None:
    """Find an active department in the current tenant."""

    return db.scalar(
        select(Department).where(
            Department.id == department_id,
            Department.archived_at.is_(None),
        )
    )


def department_named(db: Session, name: str) -> Department | None:
    """The company's department with this name, archived or not, ignoring case.

    Ignoring case matches MySQL, whose text comparison does not tell "Kitchen" from
    "kitchen", so the same name is refused on SQLite (the tests) as in production.
    """
    return db.scalar(select(Department).where(func.lower(Department.name) == name.lower()))


def list_active_departments(
    db: Session,
    *,
    after: tuple[str, uuid.UUID] | None,
    limit: int,
) -> list[Department]:
    """Return one page of the current tenant's active departments in name order."""

    # Course topic: SQL. The WHERE leaves out archived rows, ORDER BY makes paging
    # predictable, and LIMIT asks for one extra row so the service can detect another
    # page. The tenant-aware session automatically adds WHERE company_id = :company.
    statement = (
        select(Department)
        .where(Department.archived_at.is_(None))
        .order_by(Department.name, Department.id)
        .limit(limit + 1)
    )
    if after is not None:
        name, last_id = after
        statement = statement.where(
            or_(
                Department.name > name,
                and_(Department.name == name, Department.id > last_id),
            )
        )
    return list(db.scalars(statement))


# The next three checks decide whether a department may be archived. archive_department()
# runs them after it has locked the department, and each one is a locking read
# (FOR SHARE). Why: under MySQL's default isolation (REPEATABLE READ), an ordinary SELECT
# sees the database as it was at the transaction's FIRST read, and the request has always
# read something before it gets here (its session and permission checks). After waiting
# for the department's lock it would still miss a team, a shift, or a person committed
# meanwhile, and archive the department anyway. A locking read always sees the newest
# committed rows, and holds them until this transaction ends, so they cannot be changed
# under the archive either. The same fix as for double-booking
# (app/modules/schedules/repository.py, has_overlap). SQLite, which the tests use, has no
# row locks and ignores FOR SHARE; scripts/check_migrations.py tries the race on MySQL.


def is_anyones_home(db: Session, department_id: uuid.UUID) -> bool:
    """Whether the department is the home department of anyone not deactivated (a fresh,
    locking read: see above)."""
    found = db.scalar(
        select(User.id)
        .where(User.department_id == department_id, User.deactivated_at.is_(None))
        .limit(1)
        .with_for_update(read=True)  # FOR SHARE: the newest committed rows
    )
    return found is not None


def has_upcoming_shifts(db: Session, department_id: uuid.UUID, now: datetime) -> bool:
    """Whether the department has a shift that has not ended yet and is not cancelled (a
    fresh, locking read: see above)."""
    # The schedules module owns shifts; imported here, inside the function, because
    # schedules itself builds on the org models (a module-level import would be circular).
    from app.modules.schedules.models import Shift

    found = db.scalar(
        select(Shift.id)
        .where(
            Shift.department_id == department_id,
            Shift.status != "cancelled",
            Shift.ends_at > now,
        )
        .limit(1)
        .with_for_update(read=True)  # FOR SHARE: the newest committed rows
    )
    return found is not None


def has_active_teams(db: Session, department_id: uuid.UUID) -> bool:
    """Whether the department still has a team that is not archived (a fresh, locking
    read: see above). A team created by create_team() cannot slip past this: creating one
    locks the department first, so it either committed before this request got the
    department's lock (and this read sees it) or waits until this request has finished."""
    found = db.scalar(
        select(Team.id)
        .where(Team.department_id == department_id, Team.archived_at.is_(None))
        .limit(1)
        .with_for_update(read=True)  # FOR SHARE: the newest committed rows
    )
    return found is not None


# --- Teams -----------------------------------------------------------------------------


def team(db: Session, team_id: uuid.UUID, *, lock: bool = False) -> Team | None:
    """A team of the session's company, archived or not (another company's: 404).

    lock=True locks its row until the transaction ends (SELECT ... FOR UPDATE) and reads
    its newest committed version, replacing any copy this session already holds
    (populate_existing). So two changes to one team take turns, and a change that waited
    for an archive sees the team as archived rather than as it was when the request began.
    """
    return db.get(Team, team_id, with_for_update=lock, populate_existing=lock)


def team_named(db: Session, department_id: uuid.UUID, name: str) -> Team | None:
    """The department's team with this name, archived or not, ignoring case (as MySQL)."""
    return db.scalar(
        select(Team).where(
            Team.department_id == department_id, func.lower(Team.name) == name.lower()
        )
    )


def list_active_teams(
    db: Session,
    *,
    department_id: uuid.UUID | None,
    after: tuple[str, uuid.UUID] | None,
    limit: int,
) -> list[Team]:
    """One page of the company's active teams in name order, optionally of one department."""
    statement = (
        select(Team)
        .where(Team.archived_at.is_(None))
        .order_by(Team.name, Team.id)
        .limit(limit + 1)  # one more than asked: tells whether another page exists
    )
    if department_id is not None:
        statement = statement.where(Team.department_id == department_id)
    if after is not None:
        name, last_id = after
        statement = statement.where(
            or_(Team.name > name, and_(Team.name == name, Team.id > last_id))
        )
    return list(db.scalars(statement))


def active_team(db: Session, team_id: uuid.UUID) -> Team | None:
    """An active team of the session's company (for the list's cursor)."""
    return db.scalar(select(Team).where(Team.id == team_id, Team.archived_at.is_(None)))


# --- Team members ----------------------------------------------------------------------


def person(db: Session, user_id: uuid.UUID, *, lock: bool = False) -> User | None:
    """A person of the session's company (another company's looks like none: 404).

    lock=True locks their row until the transaction ends (SELECT ... FOR UPDATE) and reads
    its newest committed version, replacing any copy this session already holds. Every
    change to a person's account locks it, and so do putting someone on a team and giving
    someone a shift: so a deactivation and a new team or shift take turns, and whichever
    waited sees the person as the other left them.
    """
    return db.get(User, user_id, with_for_update=lock, populate_existing=lock)


def membership(db: Session, team_id: uuid.UUID, user_id: uuid.UUID) -> TeamMember | None:
    """The person's membership of the team, if they are on it."""
    return db.get(TeamMember, (team_id, user_id))


# --- People ----------------------------------------------------------------------------


def list_people(
    db: Session,
    *,
    visible: ColumnElement[bool],
    after: tuple[str, uuid.UUID] | None,
    limit: int,
) -> list[User]:
    """One page of the company's people in name order, deactivated ones included.

    `visible` is the scope filter's condition (check.scope_filter): only the people the
    user may see are ever loaded, never a whole list that is then trimmed.
    """
    statement = (
        select(User)
        .where(visible)
        .order_by(User.display_name, User.id)
        .limit(limit + 1)  # one more than asked: tells whether another page exists
    )
    if after is not None:
        name, last_id = after
        statement = statement.where(
            or_(User.display_name > name, and_(User.display_name == name, User.id > last_id))
        )
    return list(db.scalars(statement))


def team_ids_by_person(db: Session, user_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[uuid.UUID]]:
    """The teams each of these people is on, in one query for a whole page of people."""
    found: dict[uuid.UUID, list[uuid.UUID]] = {user_id: [] for user_id in user_ids}
    if not user_ids:
        return found
    rows = db.execute(
        select(TeamMember.user_id, TeamMember.team_id)
        .where(TeamMember.user_id.in_(user_ids))
        .order_by(TeamMember.team_id)
    )
    for user_id, team_id in rows:
        found[user_id].append(team_id)
    return found


def upcoming_shift_ids(db: Session, user_id: uuid.UUID, now: datetime) -> list[uuid.UUID]:
    """The person's shifts that have not ended and are not cancelled, soonest first."""
    # Imported here for the same reason as in has_upcoming_shifts() above.
    from app.modules.schedules.models import Shift

    return list(
        db.scalars(
            select(Shift.id)
            .where(Shift.employee_id == user_id, Shift.status != "cancelled", Shift.ends_at > now)
            .order_by(Shift.starts_at, Shift.id)
        )
    )


def end_sessions(db: Session, user_id: uuid.UUID) -> int:
    """Delete every session of the person, so each of their browsers is signed out at
    once; return how many there were. A delete with a where clause: the company filter
    adds the company condition too, so it can only reach this company's sessions."""
    # The sessions table belongs to the sign-in code (app/auth/); imported here, as above.
    from app.auth.models import UserSession

    result = db.execute(delete(UserSession).where(UserSession.user_id == user_id))
    return int(result.rowcount or 0)  # type: ignore[attr-defined]
