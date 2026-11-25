"""Where an announcement belongs, for authorize() (announcements.md, scope resolver).

An announcement belongs to its audience:
- a department audience to that department, so a department assignment covers it;
- a team audience to the team and to the team's department, so a team assignment and an
  assignment for the department around it both cover it;
- a company audience to no department and no team, so only a company-wide assignment
  covers it.
It belongs to no employee, so no self permission ever applies to it.

An archived team covers nothing (organization.md), so a team audience whose team is
archived does not belong to its department any more either: only a company-wide
assignment still covers it. (A department is only archived after all its teams are, so
an active team never sits in an archived department; and assignments for an archived
department grant nothing anyway, app/authz/check.py.)

The managed list (scope_filter with ScopeColumns(department=Announcement.department_id,
team=Announcement.team_id)) follows the same rules, so it shows exactly the announcements
a direct request would allow.
"""

from sqlalchemy.orm import Session

from app.authz.scope import Scope, scope_resolver
from app.modules.announcements.models import Announcement
from app.modules.org.models import Team


@scope_resolver(Announcement)
def announcement_scope(db: Session, announcement: Announcement) -> Scope:
    # A department audience: that department.
    if announcement.audience_type == "department" and announcement.department_id is not None:
        return Scope(frozenset({announcement.department_id}), frozenset(), None)
    # A team audience: the team, and its department while the team is active.
    if announcement.audience_type == "team" and announcement.team_id is not None:
        team = db.get(Team, announcement.team_id)
        if team is None or team.archived_at is not None:
            return Scope(frozenset(), frozenset({announcement.team_id}), None)
        return Scope(frozenset({team.department_id}), frozenset({team.id}), None)
    # The company audience: no department and no team.
    return Scope(frozenset(), frozenset(), None)
