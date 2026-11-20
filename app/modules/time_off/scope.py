"""Where a time-off request belongs, for authorize() (authorization.md, scope resolvers):
to its employee, and through them to their home department and teams."""

from sqlalchemy.orm import Session

from app.authz.scope import Scope, person_scope, scope_resolver
from app.modules.org.models import User
from app.modules.time_off.models import TimeOffRequest


@scope_resolver(TimeOffRequest)
def time_off_scope(db: Session, request: TimeOffRequest) -> Scope:
    employee = db.get(User, request.employee_id)
    if employee is None:  # people are never deleted
        return Scope(frozenset(), frozenset(), request.employee_id)
    return person_scope(db, employee)
