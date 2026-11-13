"""Changes to departments and teams that meet another request on the way (review on #136).

The row locks and locking reads themselves only work in MySQL (scripts/check_migrations.py
tries real races there). Two parts can be shown on SQLite too, and are here:

- A duplicate that only the database notices (two requests passed the service's own name
  check at the same moment) is answered 409, not 500, wherever the database refuses it:
  at a flush, inside the audit entry's flush, or at the commit.
- A team change reads the team fresh. A request that already holds an old copy of the
  team (as an endpoint does, from an earlier read) and then finds it archived by someone
  else is refused (409) instead of changing an archived team.
"""

import uuid
from collections.abc import Callable

import pytest
from sqlalchemy import func, select

from app.audit.models import AuditEvent
from app.modules.org import repository, service
from app.modules.org.models import Department, Team, TeamMember, User
from app.modules.org.schemas import DepartmentCreate, DepartmentUpdate, TeamCreate
from tests.shift_data import ShiftSetup, shifts

__all__ = ["shifts"]  # the fixture, imported so pytest finds it


def _audit_count(setup: ShiftSetup) -> int:
    """How many audit entries the company has (a refused change must add none)."""
    with setup.db() as db:
        return (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.chain_id == setup.company_a)
            )
            or 0
        )


# Each case: which of the service's own duplicate checks to blind (as if the other request
# had not committed yet when it ran), and the change that then runs into the database's
# unique key. The ID names say where the database refuses it.
CASES: dict[str, tuple[str, Callable[[ShiftSetup, object, User], object]]] = {
    # The new department's row is sent by an explicit flush (to get its ID).
    "new department, at the flush": (
        "department_named",
        lambda s, db, owner: service.create_department(db, owner, DepartmentCreate(name="Kitchen")),
    ),
    # The new name is sent by record(), which flushes the change with its audit entry.
    "renamed department, in the audit entry": (
        "department_named",
        lambda s, db, owner: service.update_department(
            db, owner, s.ids["front"], DepartmentUpdate(name="Kitchen")
        ),
    ),
    "new team, at the flush": (
        "team_named",
        lambda s, db, owner: service.create_team(
            db, owner, TeamCreate(department_id=s.ids["kitchen"], name="Weekend Crew")
        ),
    ),
    # The new membership row is sent by record() as well.
    "new member, in the audit entry": (
        "membership",
        lambda s, db, owner: service.add_member(db, owner, s.ids["crew"], s.ids["ben"]),
    ),
}


@pytest.mark.parametrize("case", list(CASES))
def test_a_duplicate_only_the_database_notices_is_a_409(
    shifts: ShiftSetup, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    check, change = CASES[case]
    # The service's own check finds nothing, as when both requests checked before either
    # had saved. The database's unique key is now the only thing left to refuse it.
    monkeypatch.setattr(repository, check, lambda *_args, **_kwargs: None)
    entries_before = _audit_count(shifts)

    with shifts.db() as db:
        owner = db.get(User, shifts.ids["owner"])
        assert owner is not None
        # Before the fix, only the commit was covered, so this was a 500.
        with pytest.raises(service.Conflict):
            change(shifts, db, owner)

    # The attacker's view: nothing of the refused change was saved, audit entry included.
    assert _audit_count(shifts) == entries_before
    with shifts.db() as db:
        kitchens = select(func.count(Department.id)).where(Department.name == "Kitchen")
        assert db.scalar(kitchens) == 1
        crews = select(func.count(Team.id)).where(Team.name == "Weekend Crew")
        assert db.scalar(crews) == 1
        assert db.get(TeamMember, (shifts.ids["crew"], shifts.ids["ben"])) is not None


# The changes that start from _changeable_team: each must be refused once the team it
# holds an old copy of has been archived by someone else.
TEAM_CHANGES: dict[str, Callable[[ShiftSetup, object, User, uuid.UUID], object]] = {
    "rename": lambda s, db, owner, team: service.rename_team(db, owner, team, "Late Crew"),
    "add a member": lambda s, db, owner, team: service.add_member(db, owner, team, s.ids["ana"]),
    "remove a member": lambda s, db, owner, team: service.remove_member(
        db, owner, team, s.ids["ben"]
    ),
    "archive again": lambda s, db, owner, team: service.archive_team(db, owner, team),
}


@pytest.mark.parametrize("change", list(TEAM_CHANGES))
def test_a_team_change_that_waited_for_an_archive_is_refused(
    shifts: ShiftSetup, change: str
) -> None:
    team_id = shifts.ids["crew"]
    with shifts.db() as db:
        owner = db.get(User, shifts.ids["owner"])
        assert owner is not None
        # This request read the team first, while it was active. The copy is kept in a
        # variable, as an endpoint keeps it: the session only remembers objects still in
        # use, and a forgotten copy would simply be read again.
        stale = repository.team(db, team_id)
        assert stale is not None and stale.archived_at is None
        # Meanwhile another request archives the team and commits.
        response = shifts.browser("owner").post(f"/api/teams/{team_id}/archive")
        assert response.status_code == 200, response.text
        # Now this request makes its change. Before the fix, the old copy was used (it
        # still said "active"), and the archived team was changed.
        with pytest.raises(service.Conflict):
            TEAM_CHANGES[change](shifts, db, owner, team_id)

    # The attacker's view: the archived team is exactly as the archive left it.
    with shifts.db() as db:
        saved = db.get(Team, team_id)
        assert saved is not None and saved.name == "Weekend Crew"
        assert db.get(TeamMember, (team_id, shifts.ids["ben"])) is not None
        assert db.get(TeamMember, (team_id, shifts.ids["ana"])) is None
