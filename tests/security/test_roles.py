"""Roles against the delegation limits (authorization.md; threats E2, E6, E9; rules AZ3,
AZ9, AZ11, AZ12, AZ13).

Every request goes through the real app (session, CSRF check, company filter,
authorize()). Each test is someone reaching for more than they should, and checks what the
attacker would see: the answer, and whether the role changed.

The people and reporting lines are in tests/people_data.py:
    owner > admin > chef > {ana, cara, newbie, gone, lead > ben}; dana has no manager.
chef and lead hold Manager; admin holds Administrator; everyone else holds Employee.
"""

from collections.abc import Iterator
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.audit import Actor
from app.authz import registry
from app.authz.chain import add_reporting_line
from app.authz.models import Role
from app.authz.registry import Kind, PermissionDef
from tests.people_data import actions, people
from tests.shift_data import PASSWORD, ShiftSetup, iso, shifts, soon

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here


def roles_by_kind(client: TestClient) -> dict[str, dict]:
    """The company's roles as the client sees them, by built_in (or name for others)."""
    listed = client.get("/api/roles")
    assert listed.status_code == 200, listed.text
    return {role["built_in"] or role["name"]: role for role in listed.json()["items"]}


def reenter(client: TestClient) -> None:
    """Enter the password again in this browser, as the interface asks before a sensitive
    action."""
    response = client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    assert response.status_code == 204, response.text


def a_shift(setup: ShiftSetup) -> dict:
    """A valid new Kitchen shift for tomorrow."""
    return {
        "department_id": str(setup.ids["kitchen"]),
        "starts_at": iso(soon()),
        "ends_at": iso(soon() + timedelta(hours=6)),
    }


def every_change(client: TestClient, role_id: object) -> dict[str, int]:
    """The status of every endpoint that changes one role."""
    url = f"/api/roles/{role_id}"
    return {
        "rename": client.patch(url, json={"name": "Taken over"}).status_code,
        "grant": client.patch(url, json={"permissions": ["schedule.view_self"]}).status_code,
        "archive": client.post(f"{url}/archive").status_code,
    }


# --- Who may see and change roles at all (AZ11) ----------------------------------------


def test_managers_and_employees_cannot_see_or_change_roles(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    before = roles_by_kind(owner)
    audited = actions(people, "role.")
    for name in ("chef", "ana"):
        client = people.browser(name)
        reenter(client)  # even with the password entered again
        assert client.get("/api/roles").status_code == 403
        assert client.get("/api/permissions").status_code == 403
        assert client.get(f"/api/roles/{before['manager']['id']}").status_code == 403
        assert client.post("/api/roles", json={"name": "Mine"}).status_code == 403
        assert set(every_change(client, before["employee"]["id"]).values()) == {403}
    assert roles_by_kind(owner) == before
    assert actions(people, "role.") == audited


def test_another_companys_roles_do_not_exist(people: ShiftSetup) -> None:
    with people.db(people.company_b) as db:
        theirs = db.scalars(select(Role.id).where(Role.built_in == "manager")).one()
    owner = people.browser("owner")
    reenter(owner)
    assert owner.get(f"/api/roles/{theirs}").status_code == 404
    assert set(every_change(owner, theirs).values()) == {404}
    assert str(theirs) not in {role["id"] for role in owner.get("/api/roles").json()["items"]}
    with people.db(people.company_b) as db:
        role = db.get(Role, theirs)
        assert role is not None and role.name == "Manager" and role.archived_at is None


def test_a_body_cannot_set_fields_the_rules_own(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    made = owner.post("/api/roles", json={"name": "Shadow Owner", "built_in": "owner"})
    assert made.status_code == 422
    manager = roles_by_kind(owner)["manager"]
    sneaky = owner.patch(f"/api/roles/{manager['id']}", json={"archived_at": None})
    assert sneaky.status_code == 422
    assert "Shadow Owner" not in roles_by_kind(owner)


# --- AZ3: nobody grants what they do not hold ------------------------------------------


def test_nobody_creates_a_role_with_a_permission_they_lack(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    # Administrators hold everything except company.transfer_ownership.
    made = admin.post(
        "/api/roles",
        json={"name": "Usurper", "permissions": ["schedule.view", "company.transfer_ownership"]},
    )
    assert made.status_code == 403
    assert "Usurper" not in roles_by_kind(admin)
    # The same list without it is fine, and is audited with what it grants (AZ12).
    made = admin.post("/api/roles", json={"name": "Scheduler", "permissions": ["schedule.edit"]})
    assert made.status_code == 201, made.text
    assert made.json()["permissions"] == ["schedule.edit"] and made.json()["built_in"] is None
    assert actions(people, "role.created")[-1:] == ["role.created"]


def test_nobody_adds_a_permission_they_lack_to_a_role(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    reenter(admin)
    manager = roles_by_kind(admin)["manager"]
    wanted = [*manager["permissions"], "company.transfer_ownership"]
    assert (
        admin.patch(f"/api/roles/{manager['id']}", json={"permissions": wanted}).status_code == 403
    )
    assert roles_by_kind(admin)["manager"] == manager


def test_unknown_permissions_are_refused_not_dropped(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    made = owner.post("/api/roles", json={"name": "Typo", "permissions": ["schedule.edti"]})
    assert made.status_code == 422
    assert "Typo" not in roles_by_kind(owner)


# --- AZ13: only someone above every holder changes a role ------------------------------


def test_nobody_changes_the_role_they_hold_themselves(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    reenter(admin)
    administrator = roles_by_kind(admin)["administrator"]
    # admin holds Administrator: not above themselves, so not above every holder.
    assert set(every_change(admin, administrator["id"]).values()) == {403}
    assert roles_by_kind(admin)["administrator"] == administrator


def test_a_role_with_a_holder_outside_your_chain_cannot_be_changed(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    reenter(admin)
    employee = roles_by_kind(admin)["employee"]
    # dana holds Employee and has no manager: only the owner is above her.
    assert set(every_change(admin, employee["id"]).values()) == {403}
    assert roles_by_kind(admin)["employee"] == employee
    # Once dana reports to chef (below admin), every holder is below admin.
    with people.db() as db:
        add_reporting_line(
            db, Actor.system(), manager_id=people.ids["chef"], employee_id=people.ids["dana"]
        )
        db.commit()
    renamed = admin.patch(f"/api/roles/{employee['id']}", json={"name": "Crew"})
    assert renamed.status_code == 200, renamed.text
    assert "role.renamed" in actions(people, "role.renamed")


def test_a_role_held_only_below_you_can_be_changed(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    manager = roles_by_kind(admin)["manager"]  # chef and lead, both below admin
    smaller = [code for code in manager["permissions"] if code != "schedule.edit"]
    # Changing what it grants needs the password entered again (decision 0025).
    refused = admin.patch(f"/api/roles/{manager['id']}", json={"permissions": smaller})
    assert refused.status_code == 403 and refused.json()["type"] == "reauth-required"
    assert roles_by_kind(admin)["manager"] == manager
    reenter(admin)
    changed = admin.patch(f"/api/roles/{manager['id']}", json={"permissions": smaller})
    assert changed.status_code == 200, changed.text
    assert "schedule.edit" not in changed.json()["permissions"]
    assert actions(people, "role.permission_removed") == ["role.permission_removed"]
    # It takes effect at once: chef can no longer create shifts.
    assert people.browser("chef").post("/api/shifts", json=a_shift(people)).status_code == 403


def test_a_rename_alone_needs_no_reentry(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    manager = roles_by_kind(admin)["manager"]
    renamed = admin.patch(f"/api/roles/{manager['id']}", json={"name": "Shift Lead"})
    assert renamed.status_code == 200 and renamed.json()["name"] == "Shift Lead"
    # Names stay unique, ignoring case.
    clash = admin.patch(f"/api/roles/{manager['id']}", json={"name": "employee"})
    assert clash.status_code == 409


# --- AZ9: the Owner role is locked -----------------------------------------------------


def test_the_owner_role_cannot_be_changed_even_by_the_owner(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    reenter(owner)
    owner_role = roles_by_kind(owner)["owner"]
    assert set(every_change(owner, owner_role["id"]).values()) == {409}
    assert roles_by_kind(owner)["owner"] == owner_role


# --- Archiving -------------------------------------------------------------------------


def test_an_archived_role_grants_nothing_and_cannot_be_changed(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    manager = roles_by_kind(owner)["manager"]
    refused = owner.post(f"/api/roles/{manager['id']}/archive")
    assert refused.status_code == 403 and refused.json()["type"] == "reauth-required"
    reenter(owner)
    archived = owner.post(f"/api/roles/{manager['id']}/archive")
    assert archived.status_code == 200 and archived.json()["archived"] is True
    assert actions(people, "role.archived") == ["role.archived"]
    assert people.browser("chef").post("/api/shifts", json=a_shift(people)).status_code == 403
    assert set(every_change(owner, manager["id"]).values()) == {409}


# --- New permissions need no reseeding (agreed in #81) ---------------------------------


@pytest.fixture
def new_permission() -> Iterator[str]:
    """A permission a module "adds" after the companies were created."""
    original = registry._declared

    def declared() -> list[PermissionDef]:
        added = PermissionDef("report.export", Kind.COMPANY, "Export reports", "reports")
        return [*original(), added]

    registry.all_permissions.cache_clear()
    registry._declared = declared  # type: ignore[assignment]
    yield "report.export"
    registry._declared = original  # type: ignore[assignment]
    registry.all_permissions.cache_clear()


def test_a_permission_added_later_can_be_granted_without_reseeding(
    people: ShiftSetup, new_permission: str
) -> None:
    owner = people.browser("owner")
    reenter(owner)
    administrator = roles_by_kind(owner)["administrator"]
    wanted = [*administrator["permissions"], new_permission]
    changed = owner.patch(f"/api/roles/{administrator['id']}", json={"permissions": wanted})
    assert changed.status_code == 200, changed.text
    assert new_permission in changed.json()["permissions"]
