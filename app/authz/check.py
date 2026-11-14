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
"""

import uuid

from fastapi import HTTPException
from sqlalchemy import ColumnElement, and_, false, or_, select, true
from sqlalchemy.orm import Session

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


def grants(db: Session, user: User, code: str) -> list[Grant]:
    """The user's active assignments whose role grants this permission: where each applies."""
    if user.deactivated_at is not None:
        return []
    # The Owner holds every permission, including ones a module adds after the company's
    # roles were created (the Owner role is locked, so its rows are never edited to catch
    # up). An active, company-wide Owner assignment therefore grants any registered code,
    # everywhere. This is checked first, not only when nothing else was found: another of
    # the owner's roles may grant the same code for one department, team, or person, and
    # that narrower grant must not take the place of the company-wide one.
    if is_owner(db, user):
        return [Grant("company", None, None, None)]
    # Every joined model has a column in the select list, so the company filter sees it and
    # limits it to the session's company too (tenancy.md: joins).
    rows = db.execute(
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
    return [Grant(*row[:4]) for row in rows]


def effective_permissions(db: Session, user: User) -> list[str]:
    """Every permission the user holds somewhere, sorted (for the interface's menu)."""
    if user.deactivated_at is not None:
        return []
    if is_owner(db, user):
        return sorted(all_permissions())  # the Owner holds every permission
    rows = db.execute(
        select(RolePermission.permission_code, Role.id, RoleAssignment.id, Department.id, Team.id)
        .join(Role, Role.id == RolePermission.role_id)
        .join(RoleAssignment, RoleAssignment.role_id == Role.id)
        .outerjoin(Department, Department.id == RoleAssignment.department_id)
        .outerjoin(Team, Team.id == RoleAssignment.team_id)
        .where(*_active_assignments(user))
    )
    return sorted({row[0] for row in rows})


def is_owner(db: Session, user: User) -> bool:
    """Whether the user holds the (active) Owner role for the whole company."""
    if user.deactivated_at is not None:
        return False
    # A company-wide assignment has no department or team, but the conditions in
    # _active_assignments name their columns, so the joins are always there.
    found = db.scalar(
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
    return found is not None


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


def authorize(db: Session, user: User, code: str, target: object | None = None) -> None:
    """Allow, or raise Forbidden (403) or NotFound (404). See the top of this file."""
    permission = get_permission(code)  # an unknown code is a bug: LookupError

    # 1. Another company's target does not exist for this user.
    if target is not None and getattr(target, "company_id", user.company_id) != user.company_id:
        raise NotFound()

    # 2 and 3. The assignments that grant it (none for deactivated people or archived roles).
    found = grants(db, user, code)
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
