"""Departments, teams, and team members over HTTP (docs/features/organization.md).

The happy paths and the rules, as the company's owner (who holds org.manage). Who may do
these things, and other companies, are in tests/security/test_org_structure.py.
"""

from datetime import timedelta

from sqlalchemy import select

from app.audit.models import AuditEvent
from app.modules.org.models import TeamMember
from tests.shift_data import ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


def _actions(setup: ShiftSetup, prefix: str) -> list[str]:
    """The company's audit actions starting with prefix, oldest first."""
    with setup.db() as db:
        return [
            e.action
            for e in db.scalars(
                select(AuditEvent)
                .where(AuditEvent.chain_id == setup.company_a, AuditEvent.action.like(f"{prefix}%"))
                .order_by(AuditEvent.seq)
            )
        ]


# --- Departments -----------------------------------------------------------------------


def test_a_department_is_created_renamed_and_archived(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    created = owner.post("/api/departments", json={"name": "  Bakery  ", "timezone": None})
    assert created.status_code == 201
    body = created.json()
    # Surrounding spaces are removed; no zone means the company's zone applies.
    assert body | {"id": None} == {
        "id": None,
        "name": "Bakery",
        "timezone": None,
        "archived": False,
    }
    url = f"/api/departments/{body['id']}"

    renamed = owner.patch(url, json={"name": "Pastry", "timezone": "Europe/Paris"})
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "Pastry" and renamed.json()["timezone"] == "Europe/Paris"
    # Sending the zone as null goes back to the company's zone; the name stays.
    reset = owner.patch(url, json={"timezone": None})
    assert reset.json()["timezone"] is None and reset.json()["name"] == "Pastry"

    archived = owner.post(f"{url}/archive")
    assert archived.status_code == 200 and archived.json()["archived"] is True
    # Archived: gone from the list, and history from now on.
    names = [d["name"] for d in owner.get("/api/departments").json()["items"]]
    assert "Pastry" not in names
    assert owner.patch(url, json={"name": "Again"}).status_code == 409
    assert owner.post(f"{url}/archive").status_code == 409

    assert _actions(shifts, "department.") == [
        "department.created",
        "department.updated",
        "department.updated",
        "department.archived",
    ]
    with shifts.db() as db:
        first_update = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.action == "department.updated")
            .order_by(AuditEvent.seq)
        ).first()
    assert first_update is not None
    assert first_update.details == {"fields": ["name", "timezone"]}


def test_department_names_are_unique_ignoring_case(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    assert owner.post("/api/departments", json={"name": "kitchen"}).status_code == 409
    # Renaming into another department's name too; changing only the case of its own is fine.
    front = f"/api/departments/{shifts.ids['front']}"
    assert owner.patch(front, json={"name": "KITCHEN"}).status_code == 409
    assert owner.patch(front, json={"name": "FRONT"}).status_code == 200
    # An archived department's name stays taken, so history cannot be confused.
    made = owner.post("/api/departments", json={"name": "Old"}).json()
    owner.post(f"/api/departments/{made['id']}/archive")
    assert owner.post("/api/departments", json={"name": "old"}).status_code == 409


def test_department_input_is_checked(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    for body in (
        {"name": ""},
        {"name": "   "},
        {"name": "x" * 121},
        {"name": "Bar", "timezone": "Mars/Olympus"},
        {"name": "Bar", "company_id": str(shifts.company_b)},  # unknown fields refused
        {"name": "Bar", "archived_at": None},
    ):
        assert owner.post("/api/departments", json=body).status_code == 422, body
    front = f"/api/departments/{shifts.ids['front']}"
    assert owner.patch(front, json={"name": None}).status_code == 422


def test_a_department_people_depend_on_cannot_be_archived(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    # Kitchen is the home of chef, ana, cara, newbie: refused, whatever else.
    kitchen = f"/api/departments/{shifts.ids['kitchen']}"
    response = owner.post(f"{kitchen}/archive")
    assert response.status_code == 409 and "home department" in response.json()["detail"]

    # A department with an upcoming shift (and nobody's home).
    made = owner.post("/api/departments", json={"name": "Patio"}).json()
    shift = owner.post(
        "/api/shifts",
        json={
            "department_id": made["id"],
            "starts_at": iso(soon()),
            "ends_at": iso(soon() + timedelta(hours=4)),
        },
    )
    assert shift.status_code == 201, shift.text
    url = f"/api/departments/{made['id']}"
    response = owner.post(f"{url}/archive")
    assert response.status_code == 409 and "upcoming shifts" in response.json()["detail"]
    # Once the shift is cancelled, only an active team stands in the way.
    owner.post(f"/api/shifts/{shift.json()['id']}/cancel")
    team = owner.post("/api/teams", json={"department_id": made["id"], "name": "Lunch"}).json()
    response = owner.post(f"{url}/archive")
    assert response.status_code == 409 and "teams" in response.json()["detail"]
    owner.post(f"/api/teams/{team['id']}/archive")
    assert owner.post(f"{url}/archive").status_code == 200


def test_an_unknown_department_is_not_found(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    url = "/api/departments/00000000-0000-0000-0000-000000000000"
    assert owner.patch(url, json={"name": "X"}).status_code == 404
    assert owner.post(f"{url}/archive").status_code == 404


# --- Teams -----------------------------------------------------------------------------


def test_a_team_is_created_listed_renamed_and_archived(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    created = owner.post(
        "/api/teams", json={"department_id": str(shifts.ids["front"]), "name": "Bar"}
    )
    assert created.status_code == 201
    team = created.json()
    assert team | {"id": None} == {
        "id": None,
        "department_id": str(shifts.ids["front"]),
        "name": "Bar",
        "archived": False,
    }

    # Anyone signed in can list them (screens need the names), by department too.
    everyone = shifts.browser("ana").get("/api/teams").json()
    assert [t["name"] for t in everyone["items"]] == ["Bar", "Weekend Crew"]
    front = shifts.browser("ana").get("/api/teams", params={"department_id": shifts.ids["front"]})
    assert [t["name"] for t in front.json()["items"]] == ["Bar"]

    url = f"/api/teams/{team['id']}"
    assert owner.patch(url, json={"name": "Cocktail Bar"}).json()["name"] == "Cocktail Bar"
    # The department never changes: the field is refused.
    moved = owner.patch(url, json={"name": "Bar", "department_id": str(shifts.ids["kitchen"])})
    assert moved.status_code == 422
    assert owner.post(f"{url}/archive").json()["archived"] is True
    assert [t["name"] for t in owner.get("/api/teams").json()["items"]] == ["Weekend Crew"]
    assert owner.patch(url, json={"name": "Again"}).status_code == 409

    assert _actions(shifts, "team.") == ["team.created", "team.updated", "team.archived"]


def test_the_team_list_pages_with_a_cursor(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    for name in ("Alpha", "Beta"):
        owner.post("/api/teams", json={"department_id": str(shifts.ids["kitchen"]), "name": name})
    first = owner.get("/api/teams", params={"limit": 2}).json()
    second = owner.get("/api/teams", params={"limit": 2, "cursor": first["next_cursor"]}).json()
    assert [t["name"] for t in first["items"]] == ["Alpha", "Beta"]
    assert [t["name"] for t in second["items"]] == ["Weekend Crew"]
    assert second["next_cursor"] is None
    assert owner.get("/api/teams", params={"cursor": "nonsense"}).status_code == 422


def test_team_names_are_unique_within_their_department(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    kitchen, front = str(shifts.ids["kitchen"]), str(shifts.ids["front"])
    assert (
        owner.post(
            "/api/teams", json={"department_id": kitchen, "name": "weekend crew"}
        ).status_code
        == 409
    )
    # The same name in another department is a different team.
    assert (
        owner.post("/api/teams", json={"department_id": front, "name": "Weekend Crew"}).status_code
        == 201
    )


def test_no_team_goes_into_an_archived_or_unknown_department(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    made = owner.post("/api/departments", json={"name": "Closed"}).json()
    owner.post(f"/api/departments/{made['id']}/archive")
    archived = owner.post("/api/teams", json={"department_id": made["id"], "name": "Late"})
    assert archived.status_code == 409
    unknown = owner.post(
        "/api/teams",
        json={"department_id": "00000000-0000-0000-0000-000000000000", "name": "Late"},
    )
    assert unknown.status_code == 422


# --- Team members ----------------------------------------------------------------------


def test_people_are_added_to_and_removed_from_a_team(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    url = f"/api/teams/{shifts.ids['crew']}/members"
    added = owner.post(url, json={"user_id": str(shifts.ids["ana"])})
    assert added.status_code == 201
    assert added.json() == {"team_id": str(shifts.ids["crew"]), "user_id": str(shifts.ids["ana"])}
    # Nobody is on a team twice.
    assert owner.post(url, json={"user_id": str(shifts.ids["ana"])}).status_code == 409

    removed = owner.delete(f"{url}/{shifts.ids['ana']}")
    assert removed.status_code == 204 and removed.content == b""
    # Not on it any more: nothing to remove.
    assert owner.delete(f"{url}/{shifts.ids['ana']}").status_code == 404

    assert _actions(shifts, "team_member.") == ["team_member.added", "team_member.removed"]
    with shifts.db() as db:
        entry = db.scalars(select(AuditEvent).where(AuditEvent.action == "team_member.added")).one()
    assert entry.target_id == shifts.ids["crew"]
    assert entry.details == {"user_id": str(shifts.ids["ana"])}


def test_deactivated_and_unknown_people_cannot_join(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    url = f"/api/teams/{shifts.ids['crew']}/members"
    assert owner.post(url, json={"user_id": str(shifts.ids["gone"])}).status_code == 409
    unknown = owner.post(url, json={"user_id": "00000000-0000-0000-0000-000000000000"})
    assert unknown.status_code == 422


def test_an_archived_team_keeps_its_members_but_takes_no_changes(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    team = f"/api/teams/{shifts.ids['crew']}"
    owner.post(f"{team}/archive")
    # Ben stays listed for history.
    with shifts.db() as db:
        kept = db.get(TeamMember, (shifts.ids["crew"], shifts.ids["ben"]))
    assert kept is not None
    assert (
        owner.post(f"{team}/members", json={"user_id": str(shifts.ids["ana"])}).status_code == 409
    )
    assert owner.delete(f"{team}/members/{shifts.ids['ben']}").status_code == 409
