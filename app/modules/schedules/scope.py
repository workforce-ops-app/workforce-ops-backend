"""Where a shift belongs, for authorize() (authorization.md, scope resolvers).

A shift belongs to its department and, when someone works it, to that person, their home
department, and their teams. So a Kitchen manager covers Kitchen's shifts and the shifts
of Kitchen's people; a Weekend Crew manager covers the shifts of the crew's members; an
open shift belongs to its department alone. The list filter (scope_filter with
ScopeColumns(Shift.department_id, Shift.employee_id)) follows the same rules.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authz.scope import Scope, scope_resolver
from app.modules.org.models import TeamMember, User
from app.modules.schedules.models import Shift


@scope_resolver(Shift)
def shift_scope(db: Session, shift: Shift) -> Scope:
    departments = {shift.department_id}
    teams: set = set()
    if shift.employee_id is not None:
        employee = db.get(User, shift.employee_id)
        if employee is not None:
            departments.add(employee.department_id)
            teams |= set(
                db.scalars(select(TeamMember.team_id).where(TeamMember.user_id == employee.id))
            )
    return Scope(frozenset(departments), frozenset(teams), shift.employee_id)
