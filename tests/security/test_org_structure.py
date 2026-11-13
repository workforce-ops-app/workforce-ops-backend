"""The company's structure against the threats on the organization page (I1, T2, T3, E1).

Every request here goes through the real app: the session, the CSRF check, the company
filter, and authorize(). Each test is someone reaching for departments, teams, or team
members they should not see or change.
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.audit import Actor
from app.audit.models import AuditEvent
from app.authz.models import Role
from app.authz.roles import assign_role
from app.modules.org.models import Department, Team, TeamMember
from tests.shift_data import BASE_URL, ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


def every_change(
    client: TestClient, department_id: object, team_id: object, user_id: object
) -> dict[str, int]:
    """The status of every changing endpoint for one department, team, and person."""
    dept, team = f"/api/departments/{department_id}", f"/api/teams/{team_id}"
    return {
        "rename department": client.patch(dept, json={"name": "Taken over"}).status_code,
        "archive department": client.post(f"{dept}/archive").status_code,
        "add team": client.post(
            "/api/teams", json={"department_id": str(department_id), "name": "Ours now"}
        ).status_code,
        "rename team": client.patch(team, json={"name": "Taken over"}).status_code,
        "archive team": client.post(f"{team}/archive").status_code,
        "add member": client.post(f"{team}/members", json={"user_id": str(user_id)}).status_code,
        "remove member": client.delete(f"{team}/members/{user_id}").status_code,
    }


def _nothing_changed(setup: ShiftSetup, company_id: uuid.UUID, prefix: str) -> None:
    """The company's Kitchen, Weekend Crew, and the crew's members are as they were."""
    with setup.db(company_id) as db:
        kitchen = db.get(Department, setup.ids[f"{prefix}kitchen"])
        crew = db.get(Team, setup.ids[f"{prefix}crew"])
        assert kitchen is not None and kitchen.name == "Kitchen" and kitchen.archived_at is None
        assert crew is not None and crew.name == "Weekend Crew" and crew.archived_at is None
        teams = list(db.scalars(select(Team.name)))
        members = list(db.scalars(select(TeamMember.user_id)))
    assert "Ours now" not in teams
    assert members == ([setup.ids["ben"]] if prefix == "" else [])


# --- I1, T3: other companies -----------------------------------------------------------


def test_another_companys_structure_cannot_be_changed(shifts: ShiftSetup) -> None:
    # Company A's owner holds org.manage, but only in company A: company B's department,
    # team, and person do not exist for them. The team's department is a body reference,
    # so creating a team there is 422 (an unknown department), like any unknown ID.
    statuses = every_change(
        shifts.browser("owner"), shifts.ids["b_kitchen"], shifts.ids["b_crew"], shifts.ids["b_ana"]
    )
    assert statuses == {
        "rename department": 404,
        "archive department": 404,
        "add team": 422,
        "rename team": 404,
        "archive team": 404,
        "add member": 404,
        "remove member": 404,
    }
    _nothing_changed(shifts, shifts.company_b, "b_")


def test_another_companys_person_cannot_be_put_on_a_team(shifts: ShiftSetup) -> None:
    # Our own team, their person: refused as an unknown person, and nothing is added.
    url = f"/api/teams/{shifts.ids['crew']}/members"
    response = shifts.browser("owner").post(url, json={"user_id": str(shifts.ids["b_ana"])})
    assert response.status_code == 422
    _nothing_changed(shifts, shifts.company_a, "")


def test_lists_never_show_another_companys_departments_or_teams(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    departments = {d["id"] for d in owner.get("/api/departments").json()["items"]}
    teams = {t["id"] for t in owner.get("/api/teams").json()["items"]}
    assert departments == {str(shifts.ids["kitchen"]), str(shifts.ids["front"])}
    assert teams == {str(shifts.ids["crew"])}
    # Asking for their department's teams finds nothing rather than their teams.
    theirs = owner.get("/api/teams", params={"department_id": shifts.ids["b_kitchen"]})
    assert theirs.status_code == 200 and theirs.json()["items"] == []


# --- E1: only org.manage changes the structure ---------------------------------------


def test_only_org_manage_changes_the_structure(shifts: ShiftSetup) -> None:
    # A department manager, a team manager, and an employee: all may see the structure,
    # none may change it. Every endpoint answers 403 before revealing anything else.
    for name in ("chef", "lead", "ana"):
        client = shifts.browser(name)
        statuses = every_change(
            client, shifts.ids["kitchen"], shifts.ids["crew"], shifts.ids["ana"]
        )
        assert set(statuses.values()) == {403}, (name, statuses)
        assert client.post("/api/departments", json={"name": "Mine"}).status_code == 403
        assert client.get("/api/departments").status_code == 200
        assert client.get("/api/teams").status_code == 200
    _nothing_changed(shifts, shifts.company_a, "")
    with shifts.db() as db:
        refused = db.scalars(
            select(AuditEvent.action).where(
                AuditEvent.action.like("department.%") | AuditEvent.action.like("team%")
            )
        ).all()
    assert refused == []


def test_signed_out_and_cross_site_requests_change_nothing(shifts: ShiftSetup) -> None:
    # Not signed in: 401. Signed in but without the CSRF token (a forged request from
    # another site rides on the cookie alone): 403.
    stranger = TestClient(shifts.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]
    assert stranger.get("/api/teams").status_code == 401
    assert stranger.post("/api/departments", json={"name": "X"}).status_code in (401, 403)
    forged = shifts.browser("owner")
    token = forged.headers.pop("X-CSRF-Token")
    try:
        statuses = every_change(
            forged, shifts.ids["kitchen"], shifts.ids["crew"], shifts.ids["ana"]
        )
    finally:
        forged.headers["X-CSRF-Token"] = token
    assert set(statuses.values()) == {403}, statuses
    _nothing_changed(shifts, shifts.company_a, "")


# --- E1: archived scopes cover nothing -------------------------------------------------


def test_a_role_for_an_archived_team_grants_nothing(shifts: ShiftSetup) -> None:
    # lead manages the Weekend Crew. Once the team is archived, the assignment still exists
    # for history but no longer lets them plan the crew's shifts.
    shift = shifts.new_shift("owner", employee_id=shifts.ids["ben"])
    lead = shifts.browser("lead")
    assert lead.get(f"/api/shifts/{shift['id']}").status_code == 200
    shifts.browser("owner").post(f"/api/teams/{shifts.ids['crew']}/archive")
    assert lead.get(f"/api/shifts/{shift['id']}").status_code == 403
    assert lead.patch(f"/api/shifts/{shift['id']}", json={"notes": "mine"}).status_code == 403
    assert "schedule.edit" not in lead.get("/api/sessions/current").json()["permissions"]


def test_a_role_for_an_archived_department_grants_nothing(shifts: ShiftSetup) -> None:
    # Make a department with a manager of its own, then archive it: their department-wide
    # role covers nothing, so no shift can be planned there through it.
    owner = shifts.browser("owner")
    made = owner.post("/api/departments", json={"name": "Patio"}).json()
    with shifts.db() as db:
        manager = db.scalars(select(Role).where(Role.built_in == "manager")).one()
        assign_role(
            db,
            Actor.system(),
            user_id=shifts.ids["chef"],
            role=manager,
            scope_type="department",
            scope_id=uuid.UUID(made["id"]),
        )
        db.commit()
    body = {"department_id": made["id"], "starts_at": iso(soon()), "ends_at": iso(soon(1, 18))}
    chef = shifts.browser("chef")
    first = chef.post("/api/shifts", json=body)
    assert first.status_code == 201, first.text
    owner.post(f"/api/shifts/{first.json()['id']}/cancel")
    assert owner.post(f"/api/departments/{made['id']}/archive").status_code == 200
    # The role is for an archived department, so it grants nothing there: 403. Even the
    # owner, whose role is company-wide, cannot add a shift to it: 409.
    assert chef.post("/api/shifts", json=body).status_code == 403
    assert owner.post("/api/shifts", json=body).status_code == 409
    # Their Kitchen role is untouched.
    assert shifts.new_shift("chef")["department"]["name"] == "Kitchen"
