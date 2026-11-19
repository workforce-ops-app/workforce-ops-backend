"""Giving and removing roles against the delegation limits (authorization.md; threats E1,
E2, E3, E6; rules AZ1, AZ3, AZ4, AZ5, AZ11, AZ12, AZ14).

Every request goes through the real app. Each test is someone trying to hand out more
than they hold, or to raise themselves or a friend, and checks what the attacker sees:
the answer, and which roles people actually hold afterwards.

People and lines (tests/people_data.py):
    owner > admin > chef > {ana, cara, newbie, gone, lead > ben}; dana has no manager.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.approvals.models import ApprovalRequest
from app.audit import Actor
from app.authz.models import Role, RoleAssignment, RolePermission
from app.authz.roles import assign_role
from tests.people_data import actions, people
from tests.shift_data import PASSWORD, ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/role-assignments"


def reenter(client: TestClient) -> None:
    response = client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    assert response.status_code == 204, response.text


def role_id(setup: ShiftSetup, key: str, company: uuid.UUID | None = None) -> uuid.UUID:
    """A role's ID, by built_in or by name."""
    with setup.db(company) as db:
        return db.scalars(select(Role.id).where((Role.built_in == key) | (Role.name == key))).one()


def held(setup: ShiftSetup, name: str) -> set[tuple[str, str, uuid.UUID | None]]:
    """(role, scope type, scope id) for every role the person holds, as stored."""
    with setup.db() as db:
        rows = db.execute(
            select(RoleAssignment, Role)
            .join(Role, Role.id == RoleAssignment.role_id)
            .where(RoleAssignment.user_id == setup.ids[name])
        )
        return {
            (
                role.built_in or role.name,
                item.scope_type,
                item.department_id or item.team_id or item.employee_id,
            )
            for item, role in rows
        }


def pending(setup: ShiftSetup) -> list[ApprovalRequest]:
    with setup.db() as db:
        rows = list(db.scalars(select(ApprovalRequest)))
        for row in rows:
            db.expunge(row)
        return rows


def give(
    client: TestClient,
    setup: ShiftSetup,
    who: str,
    role: uuid.UUID,
    scope: str = "company",
    where: object = None,
) -> int:
    body = {"user_id": str(setup.ids[who]), "role_id": str(role), "scope_type": scope}
    if where is not None:
        body["scope_id"] = str(where)
    return client.post(URL, json=body).status_code


@pytest.fixture
def scheduler(people: ShiftSetup) -> uuid.UUID:
    """A small role of the company's own: editing schedules only."""
    with people.db() as db:
        role = Role(name="Scheduler")
        db.add(role)
        db.flush()
        db.add(RolePermission(role_id=role.id, permission_code="schedule.edit"))
        db.commit()
        return role.id


@pytest.fixture
def kitchen_admin(people: ShiftSetup) -> ShiftSetup:
    """chef also holds a role with role.assign, but only for Kitchen."""
    with people.db() as db:
        role = Role(name="Kitchen Admin")
        db.add(role)
        db.flush()
        for code in ("role.assign", "user.view", "schedule.edit", "schedule.view"):
            db.add(RolePermission(role_id=role.id, permission_code=code))
        assign_role(
            db,
            Actor.system(),
            user_id=people.ids["chef"],
            role=role,
            scope_type="department",
            scope_id=people.ids["kitchen"],
        )
        db.commit()
    return people


# --- AZ1, AZ5, AZ11: whom you may give roles to ----------------------------------------


def test_nobody_gives_themselves_a_role(people: ShiftSetup, scheduler: uuid.UUID) -> None:
    for name in ("owner", "admin", "chef", "ana"):
        client = people.browser(name)
        reenter(client)
        assert give(client, people, name, scheduler) == 403, name
        assert ("Scheduler", "company", None) not in held(people, name)


def test_nobody_gives_roles_to_peers_or_superiors(people: ShiftSetup, scheduler: uuid.UUID) -> None:
    admin = people.browser("admin")
    reenter(admin)
    assert give(admin, people, "owner", scheduler) == 403  # above admin
    assert give(admin, people, "dana", scheduler) == 403  # outside admin's chain
    assert held(people, "dana") == {("employee", "department", people.ids["front"])}


def test_without_role_assign_nobody_gives_roles(people: ShiftSetup, scheduler: uuid.UUID) -> None:
    chef = people.browser("chef")  # Manager: no role.assign
    assert give(chef, people, "ana", scheduler) == 403
    assert ("Scheduler", "company", None) not in held(people, "ana")


def test_another_companys_people_roles_and_places_are_unknown(
    people: ShiftSetup, scheduler: uuid.UUID
) -> None:
    owner = people.browser("owner")
    reenter(owner)
    theirs = role_id(people, "manager", people.company_b)
    assert give(owner, people, "b_ana", scheduler) == 422
    assert give(owner, people, "ana", theirs) == 422
    assert give(owner, people, "ana", scheduler, "department", people.ids["b_kitchen"]) == 422
    assert owner.get(URL, params={"user_id": str(people.ids["b_ana"])}).status_code == 404
    with people.db(people.company_b) as db:
        assert (
            db.scalars(
                select(RoleAssignment).where(RoleAssignment.user_id == people.ids["b_ana"])
            ).all()
            != []
        )
    assert ("Scheduler", "company", None) not in held(people, "ana")


# --- AZ3, AZ4: only what you hold, only as wide as you hold it -------------------------


def test_a_department_admin_cannot_give_a_company_wide_role(
    kitchen_admin: ShiftSetup, scheduler: uuid.UUID
) -> None:
    chef = kitchen_admin.browser("chef")
    # schedule.edit for Kitchen only: never for the whole company (AZ4)...
    assert give(chef, kitchen_admin, "ana", scheduler) == 403
    # ...nor for another department.
    assert (
        give(chef, kitchen_admin, "ana", scheduler, "department", kitchen_admin.ids["front"]) == 403
    )
    # For Kitchen, or one of its teams, it is smaller than chef's own: given at once.
    assert (
        give(chef, kitchen_admin, "ana", scheduler, "department", kitchen_admin.ids["kitchen"])
        == 201
    )
    assert give(chef, kitchen_admin, "cara", scheduler, "team", kitchen_admin.ids["crew"]) == 201
    assert ("Scheduler", "department", kitchen_admin.ids["kitchen"]) in held(kitchen_admin, "ana")
    assert actions(kitchen_admin, "role_assignment.added")[-2:] == ["role_assignment.added"] * 2


def test_nobody_gives_a_role_with_a_permission_they_lack(kitchen_admin: ShiftSetup) -> None:
    chef = kitchen_admin.browser("chef")
    reenter(chef)
    administrator = role_id(kitchen_admin, "administrator")
    kitchen = kitchen_admin.ids["kitchen"]
    assert give(chef, kitchen_admin, "ana", administrator, "department", kitchen) == 403
    assert all(role != "administrator" for role, _, _ in held(kitchen_admin, "ana"))


def test_the_owner_role_is_never_given_here(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    reenter(owner)
    assert give(owner, people, "admin", role_id(people, "owner")) == 409
    assert ("owner", "company", None) not in held(people, "admin")


# --- AZ14: a role at your own level waits for approval from above ----------------------


def test_a_role_at_your_own_level_only_opens_a_request(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    administrator = role_id(people, "administrator")
    # Admin-level: the password first (decision 0025).
    body = {
        "user_id": str(people.ids["chef"]),
        "role_id": str(administrator),
        "scope_type": "company",
    }
    refused = admin.post(URL, json=body)
    assert refused.status_code == 403 and refused.json()["type"] == "reauth-required"
    reenter(admin)
    asked = admin.post(URL, json=body)
    assert asked.status_code == 202, asked.text
    assert asked.json()["status"] == "pending" and asked.json()["kind"] == "role_assignment"
    # Nothing is granted while it waits.
    assert ("administrator", "company", None) not in held(people, "chef")
    [request] = pending(people)
    assert (
        request.requested_by == people.ids["admin"]
        and request.subject_user_id == people.ids["chef"]
    )
    assert actions(people, "approval.requested") == ["approval.requested"]
    # Asking twice is refused.
    assert admin.post(URL, json=body).status_code == 409


def test_a_smaller_role_is_given_at_once(people: ShiftSetup, scheduler: uuid.UUID) -> None:
    admin = people.browser("admin")
    assert give(admin, people, "chef", scheduler) == 201  # not admin-level: no re-entry
    assert ("Scheduler", "company", None) in held(people, "chef")
    assert pending(people) == []
    assert give(admin, people, "chef", scheduler) == 409  # already held


def test_the_owner_gives_administrator_at_once(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    reenter(owner)
    assert give(owner, people, "chef", role_id(people, "administrator")) == 201
    assert ("administrator", "company", None) in held(people, "chef")


# --- Places and people that grant nothing ----------------------------------------------


def test_deactivated_people_and_archived_places_get_no_roles(
    people: ShiftSetup, scheduler: uuid.UUID
) -> None:
    owner = people.browser("owner")
    assert give(owner, people, "gone", scheduler) == 409
    assert give(owner, people, "ana", scheduler, "employee", people.ids["gone"]) == 409
    assert give(owner, people, "ana", scheduler, "department") == 422  # no scope_id
    assert give(owner, people, "ana", scheduler, "company", people.ids["kitchen"]) == 422


# --- Removing roles --------------------------------------------------------------------


def test_removing_a_role_follows_the_same_limits(people: ShiftSetup) -> None:
    listed = people.browser("owner").get(URL, params={"user_id": str(people.ids["chef"])})
    [manager] = [item for item in listed.json()["items"] if item["built_in"] == "manager"]
    admin_roles = people.browser("owner").get(URL, params={"user_id": str(people.ids["admin"])})
    [own] = admin_roles.json()["items"]

    admin = people.browser("admin")
    reenter(admin)
    assert admin.delete(f"{URL}/{own['id']}").status_code == 403  # their own (AZ1)
    assert people.browser("chef").delete(f"{URL}/{manager['id']}").status_code == 403  # own
    assert admin.delete(f"{URL}/{manager['id']}").status_code == 204
    assert all(role != "manager" for role, _, _ in held(people, "chef"))
    assert actions(people, "role_assignment.removed") == ["role_assignment.removed"]
    assert admin.delete(f"{URL}/{manager['id']}").status_code == 404  # already gone
    # The owner's role is never removed here.
    owner_roles = people.browser("owner").get(URL, params={"user_id": str(people.ids["owner"])})
    [owner_role] = owner_roles.json()["items"]
    assert admin.delete(f"{URL}/{owner_role['id']}").status_code == 403  # not above the owner


# --- Seeing roles (agreed in #81) ------------------------------------------------------


def test_managers_see_their_peoples_roles_and_nobody_elses(people: ShiftSetup) -> None:
    chef, ana = people.browser("chef"), people.browser("ana")
    assert chef.get(URL, params={"user_id": str(people.ids["ana"])}).status_code == 200
    assert ana.get(URL, params={"user_id": str(people.ids["ana"])}).status_code == 200  # own
    assert ana.get(URL, params={"user_id": str(people.ids["chef"])}).status_code == 403
    assert chef.get(URL, params={"user_id": str(people.ids["dana"])}).status_code == 403  # Front
