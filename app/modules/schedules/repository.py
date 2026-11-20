"""Every database query of the schedules module (the only file here that talks to the database).

All queries are built with SQLAlchemy, so every value is sent as a bound parameter, never
pasted into SQL text (SQL injection, threat T1), and the company filter adds "company_id =
<the session's company>" to each of them (tenancy.md).
"""

import base64
import binascii
import json
import uuid
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import ColumnElement, and_, or_, select
from sqlalchemy.orm import Session, aliased

from app.authz.models import Role, RoleAssignment
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.modules.schedules.models import Shift


def department(db: Session, department_id: uuid.UUID) -> Department | None:
    """A department of the session's company (another company's looks like none)."""
    return db.get(Department, department_id)


def workplace_zone(db: Session, dept: Department) -> str:
    """The workplace time zone: the department's own, or else the company's."""
    if dept.timezone:
        return dept.timezone
    company = db.get(Company, dept.company_id)
    if company is None:  # the session's own company is always visible to it
        raise RuntimeError("the department's company is missing")
    return company.timezone


def person(db: Session, user_id: uuid.UUID, *, lock: bool = False) -> User | None:
    """A person of the session's company. lock=True locks their row until the transaction
    ends (SELECT ... FOR UPDATE) and reads its newest committed version: two managers giving
    the same person overlapping shifts at the same moment then take turns, and a person
    deactivated meanwhile is seen as deactivated. Together with the fresh read in
    has_overlap(), the double-booking check cannot be raced."""
    return db.get(User, user_id, with_for_update=lock, populate_existing=lock)


def has_overlap(
    db: Session,
    employee_id: uuid.UUID,
    starts_at: datetime,
    ends_at: datetime,
    ignore: uuid.UUID | None,
    also_ignore: uuid.UUID | None = None,
) -> bool:
    """Whether the person already has a (not cancelled) shift overlapping this time.
    `ignore` (and `also_ignore`) leave shifts out: the one being changed, or the two
    shifts of a swap (coverage.md), which trade places and so never clash with each other.

    Two time ranges overlap when each starts before the other ends.

    Callers lock the person's row first (person(..., lock=True)), so two changes to one
    person take turns. That alone is not enough: under MySQL's default isolation
    (REPEATABLE READ), an ordinary SELECT sees the database as it was at the
    transaction's FIRST read. A request has always read something before it gets here
    (its session and permission checks), so after waiting for the lock it would still
    miss a shift that the other request committed meanwhile, and both would be saved.
    A locking read (FOR SHARE) always sees the newest committed rows, so this query is
    one. The same fix as for reporting lines (app/authz/chain.py, is_above_in_chain_fresh).

    The read locks only this person's shifts in the time range (it uses the
    company, employee, start index), so other people's bookings are not held up.
    SQLite, which the tests use, has no row locks and ignores FOR SHARE;
    scripts/check_migrations.py tries the race on MySQL.
    """
    conditions = [
        Shift.employee_id == employee_id,
        Shift.status != "cancelled",
        Shift.starts_at < ends_at,
        Shift.ends_at > starts_at,
    ]
    for left_out in (ignore, also_ignore):
        if left_out is not None:
            conditions.append(Shift.id != left_out)
    # read=True makes it FOR SHARE: other readers may share the lock, but nobody can
    # change these rows until this transaction ends.
    found = select(Shift.id).where(*conditions).limit(1).with_for_update(read=True)
    return db.scalar(found) is not None


def assignable(db: Session, person: User | None, department_id: uuid.UUID) -> bool:
    """Whether the person could be given a shift in this department (schedules.md, states
    and rules): active, set up (not just "invited"), and the department is their home or
    they are on an active team in it. An archived team keeps its member list for history
    (organization.md), but being listed on it no longer makes anyone eligible.

    Shared by assigning (service.py) and by coworkers' offers (app/modules/time_off/
    offers.py), so the two can never disagree about who may work a shift.
    """
    if person is None or person.deactivated_at is not None or person.password_hash is None:
        return False
    if person.department_id == department_id:
        return True
    on_team = db.execute(
        select(TeamMember.user_id, Team.id)
        .join(Team, Team.id == TeamMember.team_id)
        .where(
            TeamMember.user_id == person.id,
            Team.department_id == department_id,
            Team.archived_at.is_(None),
        )
        .limit(1)
    ).first()
    return on_team is not None


def on_time_off(db: Session, person: User, starts_at: datetime, ends_at: datetime) -> bool:
    """Whether the person has APPROVED time off overlapping this time (schedules.md, states
    and rules: nobody is assigned during their approved time off).

    Time off is whole days in the person's workplace zone (time-off.md), so each approved
    request is turned into the UTC moments where its first day begins and its last day
    ends, the same way the approval works out which shifts to open
    (app/modules/time_off/days.py). A shift overlaps it when each starts before the other
    ends, as in has_overlap(). Only "approved" counts: a request still waiting, declined,
    or cancelled blocks nothing.

    Races: the caller holds the person's row lock (person(..., lock=True)), and approving
    time off takes that same lock first (app/modules/time_off/service.py), so an approval
    and an assignment take turns. As in has_overlap(), the read is FOR SHARE so that, after
    waiting for the lock, it sees an approval committed meanwhile.
    """
    # Imported here, not at the top: the time-off module already imports this one
    # (days.py uses workplace_zone), and a top-level import both ways would be circular.
    from app.modules.time_off.models import TimeOffRequest

    # Step 1: the person's workplace zone, and the shift's first and last calendar day in
    # it. Only requests touching those days (one day either side, for safety at the edges)
    # can overlap, which keeps the read to a few rows on the (company, employee, first_day)
    # index.
    home = db.get(Department, person.department_id)
    if home is None:  # everyone has a home department of their own company
        raise RuntimeError("the person's home department is missing")
    zone = ZoneInfo(workplace_zone(db, home))
    first = starts_at.replace(tzinfo=UTC).astimezone(zone).date() - timedelta(days=1)
    last = ends_at.replace(tzinfo=UTC).astimezone(zone).date() + timedelta(days=1)
    requests = db.scalars(
        select(TimeOffRequest)
        .where(
            TimeOffRequest.employee_id == person.id,
            TimeOffRequest.status == "approved",
            TimeOffRequest.first_day <= last,
            TimeOffRequest.last_day >= first,
        )
        .with_for_update(read=True)
    )
    # Step 2: compare exactly, with the days turned into UTC moments (stored without a zone,
    # like the shift times).
    for request in requests:
        begins = _day_starts(zone, request.first_day)
        ends = _day_starts(zone, request.last_day + timedelta(days=1))
        if starts_at < ends and ends_at > begins:
            return True
    return False


def _day_starts(zone: ZoneInfo, day: date) -> datetime:
    """The UTC moment (without zone, as stored) where a day begins in a zone. The same rule
    as day_starts() in app/modules/time_off/days.py, kept here so this module does not
    import that one (it imports this one)."""
    return datetime.combine(day, time(0), zone).astimezone(UTC).replace(tzinfo=None)


def shift(db: Session, shift_id: uuid.UUID, *, lock: bool = False) -> Shift | None:
    """One shift of the session's company (another company's looks like none: 404).

    lock=True locks the shift's row until the transaction ends (SELECT ... FOR UPDATE) and
    reads its newest committed version, replacing the copy this session already loaded
    (populate_existing). A locking read is never served from the old view, so this is how
    a change learns what the shift looks like now, not when the request started.
    """
    return db.get(Shift, shift_id, with_for_update=lock, populate_existing=lock)


def names(db: Session, item: Shift) -> tuple[str, str | None]:
    """The department's name and the person's display name, for one shift's answer."""
    dept = db.get(Department, item.department_id)
    person_name = None
    if item.employee_id is not None:
        employee = db.get(User, item.employee_id)
        person_name = employee.display_name if employee is not None else None
    return (dept.name if dept is not None else ""), person_name


# The order of the people menu's sections (frontend #83): the starting roles from the top
# of a company down, with the roles a company added in between (by name), and Employee
# last, since nearly everyone holds it.
_ROLE_RANK = {"owner": 0, "administrator": 1, "manager": 2, None: 3, "employee": 4}

# Who works where: a person and the department of a shift they work.
PersonInDepartment = tuple[uuid.UUID, uuid.UUID]

# Each person's roles in a department, as roles_of answers: (name, built_in) pairs.
RolesByPerson = dict[PersonInDepartment, list[tuple[str, str | None]]]


def _covers(
    department_id: uuid.UUID,
    scope_type: str,
    scope_department: uuid.UUID | None,
    team_department: uuid.UUID | None,
    covered_department: uuid.UUID | None,
) -> bool:
    """Whether a role assignment applies in this department (decided 2026-11-17: the
    calendar shows each person's roles in the department being viewed, not elsewhere).

    A company-wide assignment applies everywhere; a department assignment in its own
    department; a team assignment in the team's department; an assignment for one person
    in that person's home department (where their records are).
    """
    if scope_type == "company":
        return True
    if scope_type == "department":
        return scope_department == department_id
    if scope_type == "team":
        return team_department == department_id
    return covered_department == department_id  # "employee": one person


def roles_of(db: Session, people: list[PersonInDepartment]) -> RolesByPerson:
    """Each person's active roles in a department, as (name, built_in) pairs in the menu's
    order: owner, administrator, manager, the company's own roles by name, employee.

    people pairs each person with the department of a shift they work. A role counts there
    only if its assignment applies in that department (_covers), so a manager of a Kitchen
    team shows as a manager on Kitchen's calendar and not on Front's.

    "Active" means what it means for permissions (app/authz/check.py, _active_assignments):
    the role is not archived, the assignment is not for an archived department or team, and
    the person is not deactivated. A role held in several scopes is listed once; the scopes
    themselves stay on the server.

    One query for all the people in an answer, not one per shift. The IDs are looked up
    first and passed in, since the company filter refuses subqueries (tenancy.md). Every
    joined model (and the alias) has a column in the select list, so the company filter
    limits each to the session's company. In SQL it is roughly:

        SELECT role_assignments.user_id, roles.name, roles.built_in,
               role_assignments.scope_type, role_assignments.department_id,
               teams.department_id, covered.department_id
          FROM role_assignments
          JOIN roles ON roles.id = role_assignments.role_id
          JOIN users ON users.id = role_assignments.user_id
          LEFT OUTER JOIN departments ON departments.id = role_assignments.department_id
          LEFT OUTER JOIN teams ON teams.id = role_assignments.team_id
          LEFT OUTER JOIN users AS covered ON covered.id = role_assignments.employee_id
         WHERE role_assignments.user_id IN (:people)
           AND roles.archived_at IS NULL AND users.deactivated_at IS NULL
           AND departments.archived_at IS NULL AND teams.archived_at IS NULL

    Which department each assignment applies in is then decided in Python (_covers), since
    one person can work shifts in several departments in the same answer.
    """
    # 1. Nobody to look up (a page of open shifts only): no query at all.
    if not people:
        return {}
    # 2. Every pair gets an entry, so someone with no role there gets an empty list.
    found: dict[PersonInDepartment, set[tuple[str, str | None]]] = {pair: set() for pair in people}
    departments_of: dict[uuid.UUID, set[uuid.UUID]] = {}
    for person, department in people:
        departments_of.setdefault(person, set()).add(department)
    # 3. The query of the docstring. "covered" is the person an employee-scoped assignment
    #    is about (a second copy of the users table).
    covered = aliased(User)
    rows = db.execute(
        select(
            RoleAssignment.user_id,
            Role.name,
            Role.built_in,
            RoleAssignment.scope_type,
            RoleAssignment.department_id,
            Team.department_id,
            covered.department_id,
            User.id,
            Department.id,
        )
        .join(Role, Role.id == RoleAssignment.role_id)
        .join(User, User.id == RoleAssignment.user_id)
        # Outer joins: each assignment has at most one of a department, a team, and a
        # person, and then the archived_at conditions below are true for the others.
        .outerjoin(Department, Department.id == RoleAssignment.department_id)
        .outerjoin(Team, Team.id == RoleAssignment.team_id)
        .outerjoin(covered, covered.id == RoleAssignment.employee_id)
        .where(
            RoleAssignment.user_id.in_(list(departments_of)),
            Role.archived_at.is_(None),
            User.deactivated_at.is_(None),
            Department.archived_at.is_(None),
            Team.archived_at.is_(None),
        )
    )
    # 4. Each assignment counts in the departments it applies in; a set per pair drops the
    #    same role held in several scopes.
    for person, name, built_in, scope_type, scope_dept, team_dept, covered_dept, *_ in rows:
        for department in departments_of[person]:
            if _covers(department, scope_type, scope_dept, team_dept, covered_dept):
                found[(person, department)].add((name, built_in))
    # 5. The menu's order: by rank, then by name (which only matters among added roles).
    return {
        pair: sorted(roles, key=lambda role: (_ROLE_RANK.get(role[1], 3), role[0].casefold()))
        for pair, roles in found.items()
    }


# --- The list ---------------------------------------------------------------------------


def encode_cursor(item: Shift) -> str:
    """A bookmark to the last shift of a page: its start and ID (the list's sort order)."""
    raw = json.dumps({"s": item.starts_at.isoformat(), "i": str(item.id)}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID] | None:
    """The bookmark inside a cursor, or None if it is not one of ours."""
    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        return datetime.fromisoformat(raw["s"]), uuid.UUID(raw["i"])
    except (binascii.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def _day_range(zone: str, first: date, last: date) -> tuple[datetime, datetime]:
    """The UTC moments where the days first..last (both included) begin and end in a zone."""
    tz = ZoneInfo(zone)
    start = datetime.combine(first, time(0), tz).astimezone(UTC)
    end = datetime.combine(last + timedelta(days=1), time(0), tz).astimezone(UTC)
    return start.replace(tzinfo=None), end.replace(tzinfo=None)


def list_shifts(
    db: Session,
    *,
    allowed: ColumnElement[bool],
    first: date,
    last: date,
    department_id: uuid.UUID | None,
    after: tuple[datetime, uuid.UUID] | None,
    limit: int,
) -> list[Any]:
    """One page of shifts, with their department's and person's names.

    Course topic: SQL JOINs. One query joins each shift to its department (INNER JOIN:
    every shift has one) and to its person (LEFT OUTER JOIN: an open shift has none, and
    must still be listed). In SQL it is roughly:

        SELECT shifts.*, departments.name, users.display_name
          FROM shifts
          JOIN departments ON departments.id = shifts.department_id
          LEFT OUTER JOIN users ON users.id = shifts.employee_id
         WHERE <the user's scopes> AND <the days> AND shifts.status <> 'cancelled'
         ORDER BY shifts.starts_at, shifts.id
         LIMIT :limit

    The company filter adds "company_id = :company" for all three tables, and `allowed` is
    the scope condition from authz (only the shifts the user may see).
    """
    base = [allowed, Shift.status != "cancelled"]
    if department_id is not None:
        base.append(Shift.department_id == department_id)

    # "A shift belongs to the day it starts in its workplace zone." Each zone has its own
    # midnight, so the days are turned into UTC once per zone the shifts use, and each
    # shift is compared with its own zone's range. The zones come from shifts starting
    # around those days (a day either side covers every offset in the world).
    near_start, near_end = _day_range("UTC", first - timedelta(days=1), last + timedelta(days=1))
    zones = db.scalars(
        select(Shift.timezone)
        .distinct()
        .where(*base, Shift.starts_at >= near_start, Shift.starts_at < near_end)
    ).all()
    if not zones:
        return []
    in_days = or_(
        *(
            and_(Shift.timezone == zone, Shift.starts_at >= start, Shift.starts_at < end)
            for zone in zones
            for start, end in [_day_range(zone, first, last)]
        )
    )

    query = (
        select(Shift, Department.id, Department.name, User.id, User.display_name)
        .join(Department, Department.id == Shift.department_id)
        .outerjoin(User, User.id == Shift.employee_id)
        .where(*base, in_days)
        .order_by(Shift.starts_at, Shift.id)
        .limit(limit + 1)  # one more than asked: tells whether another page exists
    )
    if after is not None:
        # Everything after the bookmark in the sort order (start time, then ID).
        starts, last_id = after
        query = query.where(
            or_(Shift.starts_at > starts, and_(Shift.starts_at == starts, Shift.id > last_id))
        )
    return list(db.execute(query).all())
