"""authorize(): the one check every service function makes before it acts (authorization.md).

    authorize(db, user, "schedule.edit", shift)    # may this user edit this shift?
    authorize(db, user, "user.manage", person)     # ...act on this person's account?
    authorize(db, user, "settings.manage")         # ...change company settings?

It follows the flowchart on the authorization page, top to bottom:

1. A target from another company does not exist for the user: 404 (tenancy already hides
   such rows; this is the last line).
2. Deactivated people may do nothing.
3. The user's active role assignments that grant the permission are loaded. Archived roles
   grant nothing, and neither does an assignment for an archived department or team
   (archived scopes cover nothing, organization.md). None at all: 403. Everything is
   denied unless a rule below allows it.
4. Then by the permission's kind:
   - self:    the target must be the user's own (themselves, or a record of theirs).
   - company: one of the assignments must be for the whole company.
   - record:  one of the assignments' scopes must cover the target.
   - person:  the target must be someone else, an assignment's scope must cover them, AND
              the user must be above them: the Owner is above everyone; anyone else
              through reporting lines (app/authz/chain.py).

Without a target, record and person checks ask "anywhere at all?": used before listing,
where scope_filter() (below) then limits the rows. Company and self checks work the same
with or without one.

Permissions are read from the database on every call, so a role change takes effect at
once (no stale copy in the session).

Fresh reads: grants(), effective_permissions(), is_owner(), and authorize() take
`fresh=True` for checks made after a lock (for example the company's lock in
chain.lock_reporting_lines). Under MySQL's default isolation (REPEATABLE READ) an ordinary
SELECT sees the database as it was at the transaction's first read, so a request that
waited for the lock could still act on permissions taken away meanwhile. With fresh=True
the person's row and their role rows are read with locking reads (FOR SHARE), which always
see the newest committed rows (chain.is_above_in_chain_fresh explains the same problem for
reporting lines).
"""

import uuid

from fastapi import HTTPException
from sqlalchemy import ColumnElement, and_, false, or_, select, true
from sqlalchemy.orm import Session
from sqlalchemy.sql.selectable import GenerativeSelect

from app.authz.chain import is_above_in_chain, people_below
from app.authz.models import Role, RoleAssignment, RolePermission
from app.authz.registry import Kind, all_permissions, get_permission
from app.authz.scope import Grant, Scope, ScopeColumns, condition_for, covers, resolve
from app.modules.org.models import Department, Team, User


class Forbidden(HTTPException):
    """403: the user may not do this. One message, whatever the reason."""

    def __init__(self) -> None:
        super().__init__(status_code=403, detail="You do not have permission to do this.")


class NotFound(HTTPException):
    """404: the target is not in the user's company, so for them it does not exist."""

    def __init__(self) -> None:
        super().__init__(status_code=404, detail="Not found.")


def _maybe_fresh[Q: GenerativeSelect](query: Q, fresh: bool) -> Q:
    """The query as a locking read (FOR SHARE) when fresh is asked for, otherwise unchanged.

    FOR SHARE reads the newest committed rows and keeps them from changing until this
    transaction ends, so a check made after a lock cannot act on an old copy (top of this
    file). SQLite, which the tests use, has no row locks and leaves the clause out.
    """
    return query.with_for_update(read=True) if fresh else query


def _deactivated(db: Session, user: User, fresh: bool) -> bool:
    """Whether the user is deactivated; with fresh=True their row is read again first
    (FOR SHARE), so a deactivation committed while this request waited is seen."""
    if fresh:
        # populate_existing replaces the copy this session already holds with the new read.
        current = db.get(User, user.id, with_for_update={"read": True}, populate_existing=True)
        return current is None or current.deactivated_at is not None
    return user.deactivated_at is not None


def _active_assignments(user: User) -> list[ColumnElement[bool]]:
    """The conditions for the user's assignments that can grant anything right now.

    Every query that uses these also LEFT OUTER JOINs the assignment's department and team
    (always both, since the conditions name their columns). An assignment for a whole
    company or one employee has neither, so the join finds no row, and the archived_at
    conditions below are true for it. The company filter adds its condition to each join,
    as for every other join (tenancy.md: joins).
    """
    return [
        RoleAssignment.user_id == user.id,
        # Archived roles grant nothing.
        Role.archived_at.is_(None),
        # Nor do assignments for an archived department or team: the scope still exists for
        # history, but it covers nothing.
        Department.archived_at.is_(None),
        Team.archived_at.is_(None),
    ]


def grants(db: Session, user: User, code: str, *, fresh: bool = False) -> list[Grant]:
    """The user's active assignments whose role grants this permission: where each applies.
    fresh=True reads them with locking reads (top of this file)."""
    if _deactivated(db, user, fresh):
        return []
    # The Owner holds every permission, including ones a module adds after the company's
    # roles were created (the Owner role is locked, so its rows are never edited to catch
    # up). An active, company-wide Owner assignment therefore grants any registered code,
    # everywhere. This is checked first, not only when nothing else was found: another of
    # the owner's roles may grant the same code for one department, team, or person, and
    # that narrower grant must not take the place of the company-wide one.
    if is_owner(db, user, fresh=fresh):
        return [Grant("company", None, None, None)]
    # Every joined model has a column in the select list, so the company filter sees it and
    # limits it to the session's company too (tenancy.md: joins).
    query = (
        select(
            RoleAssignment.scope_type,
            RoleAssignment.department_id,
            RoleAssignment.team_id,
            RoleAssignment.employee_id,
            Role.id,
            RolePermission.role_id,
            Department.id,
            Team.id,
        )
        .join(Role, Role.id == RoleAssignment.role_id)
        .join(RolePermission, RolePermission.role_id == Role.id)
        # The assignment's department and team, if it has one (see _active_assignments).
        .outerjoin(Department, Department.id == RoleAssignment.department_id)
        .outerjoin(Team, Team.id == RoleAssignment.team_id)
        .where(*_active_assignments(user), RolePermission.permission_code == code)
    )
    rows = db.execute(_maybe_fresh(query, fresh))
    return [Grant(*row[:4]) for row in rows]


def effective_permissions(db: Session, user: User, *, fresh: bool = False) -> list[str]:
    """Every permission the user holds somewhere, sorted (for the interface's menu).
    fresh=True reads them with locking reads (top of this file)."""
    if _deactivated(db, user, fresh):
        return []
    if is_owner(db, user, fresh=fresh):
        return sorted(all_permissions())  # the Owner holds every permission
    query = (
        select(RolePermission.permission_code, Role.id, RoleAssignment.id, Department.id, Team.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(RoleAssignment, RoleAssignment.role_id == Role.id)
        .outerjoin(Department, Department.id == RoleAssignment.department_id)
        .outerjoin(Team, Team.id == RoleAssignment.team_id)
        .where(*_active_assignments(user))
    )
    rows = db.execute(_maybe_fresh(query, fresh))
    return sorted({row[0] for row in rows})


def department_permissions(db: Session, user: User) -> dict[uuid.UUID, set[str]]:
    """For each active department where the user holds any role, the permissions they hold
    there (the department picker and its screens; found in review: a Kitchen manager saw
    every department in the picker, and the manager buttons followed her into them).

    Where an assignment counts, the same rule as the role groups on the department view
    (roles_of, docs/features/schedules.md):
    - company-wide: every active department;
    - a department: that one;
    - a team: the team's department;
    - one person: that person's home department.

    A team or one-person grant does not cover the whole department (authorize() still
    decides each record); listing it here only says the person has something to do
    there, so the screen offers the matching tools and the API checks the rest.
    """
    if user.deactivated_at is not None:
        return {}
    # Step 1: the company's active departments (the company filter keeps it to this one).
    active = set(db.scalars(select(Department.id).where(Department.archived_at.is_(None))))
    # Step 2: the Owner holds everything, everywhere.
    if is_owner(db, user):
        everything = set(all_permissions())
        return {department: set(everything) for department in active}
    # Step 3: every active assignment with the permission codes its role grants, and where
    # it applies. Archived roles, departments, and teams grant nothing (_active_assignments).
    rows = db.execute(
        select(
            RolePermission.permission_code,
            RoleAssignment.scope_type,
            RoleAssignment.department_id,
            Team.department_id,
            RoleAssignment.employee_id,
            Role.id,
            Department.id,
        )
        .join(Role, Role.id == RolePermission.role_id)
        .join(RoleAssignment, RoleAssignment.role_id == Role.id)
        .outerjoin(Department, Department.id == RoleAssignment.department_id)
        .outerjoin(Team, Team.id == RoleAssignment.team_id)
        .where(*_active_assignments(user))
    ).all()
    # Step 4: a one-person assignment counts in that person's home department, so look
    # those homes up in one query.
    people = {row[4] for row in rows if row[1] == "employee" and row[4] is not None}
    homes = dict(db.execute(select(User.id, User.department_id).where(User.id.in_(people))).all())
    # Step 5: add each code to every department its assignment counts in.
    found: dict[uuid.UUID, set[str]] = {}
    for code, scope_type, department_id, team_department, employee_id, _, _ in rows:
        places: set[uuid.UUID | None]
        if scope_type == "company":
            places = set(active)
        elif scope_type == "department":
            places = {department_id}
        elif scope_type == "team":
            places = {team_department}
        elif scope_type == "employee" and employee_id is not None:
            places = {homes.get(employee_id)}
        else:
            places = set()  # an unknown scope type grants nothing
        for place in places:
            if place is not None and place in active:
                found.setdefault(place, set()).add(code)
    return found


def is_owner(db: Session, user: User, *, fresh: bool = False) -> bool:
    """Whether the user holds the (active) Owner role for the whole company.
    fresh=True reads it with a locking read (top of this file)."""
    if _deactivated(db, user, fresh):
        return False
    # A company-wide assignment has no department or team, but the conditions in
    # _active_assignments name their columns, so the joins are always there.
    query = (
        select(RoleAssignment.id, Role.id, Department.id, Team.id)
        .join(Role, Role.id == RoleAssignment.role_id)
        .outerjoin(Department, Department.id == RoleAssignment.department_id)
        .outerjoin(Team, Team.id == RoleAssignment.team_id)
        .where(
            *_active_assignments(user),
            Role.built_in == "owner",
            RoleAssignment.scope_type == "company",
        )
        .limit(1)
    )
    found = db.scalar(_maybe_fresh(query, fresh))
    return found is not None


# The admin-level permissions (authorization.md, "Sensitive actions"): changing who holds
# them, or deactivating someone who does, needs the password re-entered.
ADMIN_LEVEL = frozenset(
    {"user.manage", "role.manage", "role.assign", "reporting_line.manage", "settings.manage"}
)


def holds_admin_level(db: Session, person: User) -> bool:
    """Whether the person holds an admin-level permission anywhere right now.

    Read from the permissions their roles actually grant (effective_permissions), not from
    role names, so a company's own roles count as soon as they include one of these codes.
    Archived roles and assignments for archived scopes grant nothing, so they do not count.
    """
    return not ADMIN_LEVEL.isdisjoint(effective_permissions(db, person))


def is_above(db: Session, user: User, person: User) -> bool:
    """Whether the user is above the person in the reporting chain.

    The Owner is above everyone; anyone else only through reporting lines. Nobody is above
    themselves, and a deactivated user is above nobody.
    """
    if user.id == person.id or user.deactivated_at is not None:
        return False
    return is_owner(db, user) or is_above_in_chain(db, user.id, person.id)


def _owner_of(db: Session, target: object) -> uuid.UUID | None:
    """Whose own the target is: a person is their own; a record belongs to its employee."""
    if isinstance(target, User):
        return target.id
    return resolve(db, target).employee_id


def authorize(
    db: Session, user: User, code: str, target: object | None = None, *, fresh: bool = False
) -> None:
    """Allow, or raise Forbidden (403) or NotFound (404). See the top of this file.

    fresh=True is for a second check after a lock: the grants are read with locking reads,
    so permissions taken away while the request waited are seen (top of this file). It
    covers the grants; person checks also ask is_above(), which reads the chain normally,
    so callers that need a fresh chain use chain.is_above_in_chain_fresh themselves.
    """
    permission = get_permission(code)  # an unknown code is a bug: LookupError

    # 1. Another company's target does not exist for this user.
    if target is not None and getattr(target, "company_id", user.company_id) != user.company_id:
        raise NotFound()

    # 2 and 3. The assignments that grant it (none for deactivated people or archived roles).
    found = grants(db, user, code, fresh=fresh)
    if not found:
        raise Forbidden()

    # 4. By kind.
    if permission.kind is Kind.SELF:
        if target is not None and _owner_of(db, target) != user.id:
            raise Forbidden()
        return

    if permission.kind is Kind.COMPANY:
        if not any(grant.scope_type == "company" for grant in found):
            raise Forbidden()
        return

    if permission.kind is Kind.RECORD:
        if target is not None:
            scope = resolve(db, target)
            if not any(covers(grant, scope) for grant in found):
                raise Forbidden()
        return

    # Person: someone else, in scope, and the user is above them.
    if target is not None:
        if not isinstance(target, User) or target.id == user.id:
            raise Forbidden()
        scope = resolve(db, target)
        if not any(covers(grant, scope) for grant in found) or not is_above(db, user, target):
            raise Forbidden()


def covers_department(db: Session, user: User, code: str, department_id: uuid.UUID) -> bool:
    """Whether the user holds the permission for people whose home is this department.

    For a person who is about to be placed there: a new account, or someone moved to
    another home department. authorize() checks the person as they are now; this checks
    where they are going, so nobody can create or move a person into a department they
    could not act on afterwards. A team or one-person grant cannot cover somebody who is
    not on the team (or not that person) yet, so only company and department grants count.
    """
    home = Scope(frozenset({department_id}), frozenset(), None)
    return any(covers(grant, home) for grant in grants(db, user, code))


def scope_filter(db: Session, user: User, code: str, columns: ScopeColumns) -> ColumnElement[bool]:
    """A database condition for the rows of a list the user may see with this permission.

        query.where(scope_filter(db, user, "user.view", ScopeColumns(User.department_id, User.id)))

    Exactly the rules of authorize(), per kind, so a list never shows a row that a direct
    request for it would refuse:
    - self:    the user's own rows;
    - company: every row, but only with a company-wide assignment;
    - record:  the rows the assignments' scopes cover;
    - person:  the rows the scopes cover, of people the user is above, never their own.
    Without an assignment: nothing.
    """
    permission = get_permission(code)
    found = grants(db, user, code)
    if not found:
        return false()

    if permission.kind is Kind.SELF:
        return columns.employee == user.id if columns.employee is not None else false()

    if permission.kind is Kind.COMPANY:
        return true() if any(g.scope_type == "company" for g in found) else false()

    in_scope = or_(false(), *(condition_for(db, grant, columns) for grant in found))
    if permission.kind is Kind.RECORD:
        return in_scope

    # Person: only people the user is above, and never the user themselves. The Owner is
    # above everyone; anyone else only above the people below them in the chain, which
    # are looked up first and then matched by ID (chain.people_below explains why).
    if columns.employee is None:
        return false()
    if is_owner(db, user):
        return and_(in_scope, columns.employee != user.id)
    below = people_below(db, user.id)
    if not below:
        return false()
    return and_(in_scope, columns.employee.in_(below))
