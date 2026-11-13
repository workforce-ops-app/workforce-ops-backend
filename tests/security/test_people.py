"""People's accounts against the threats on the organization page (I1, I2, I3, T3, E3, E8).

Every request here goes through the real app: the session, the CSRF check, the company
filter, and authorize(). Each test is someone reaching for accounts they should not see or
change, and each checks the result the way the attacker would: the answer they get, and
whether anything changed.
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.audit.models import AuditEvent
from app.modules.org.models import User
from tests.people_data import actions, people, person
from tests.shift_data import BASE_URL, ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here


def every_change(client: TestClient, user_id: object, department_id: object) -> dict[str, int]:
    """The status of every endpoint that changes one person's account."""
    url = f"/api/users/{user_id}"
    return {
        "change": client.patch(url, json={"display_name": "Taken over"}).status_code,
        "move": client.patch(url, json={"department_id": str(department_id)}).status_code,
        "deactivate": client.post(f"{url}/deactivate").status_code,
        "reactivate": client.post(f"{url}/reactivate").status_code,
        "unlock": client.post(f"{url}/unlock").status_code,
        "sign out": client.delete(f"{url}/sessions").status_code,
    }


def _unchanged(setup: ShiftSetup, name: str) -> None:
    """The person's account is as the setup made it, and nothing about it was audited."""
    found = person(setup, name)
    assert found.display_name == name.removeprefix("b_").title()
    assert found.deactivated_at is None
    company = setup.company_b if name.startswith("b_") else setup.company_a
    with setup.db(company) as db:
        audited = db.scalars(
            select(AuditEvent.action).where(
                AuditEvent.target_id == setup.ids[name],
                AuditEvent.action.like("user.%") | AuditEvent.action.like("auth.%"),
                AuditEvent.action != "auth.signed_in",
            )
        ).all()
    assert audited == []


# --- I1, T3: other companies -----------------------------------------------------------


def test_another_companys_people_do_not_exist(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    # Every action on their person: 404, as for an ID that does not exist anywhere.
    statuses = every_change(owner, people.ids["b_ana"], people.ids["front"])
    assert set(statuses.values()) == {404}, statuses
    assert owner.get(f"/api/users/{people.ids['b_ana']}").status_code == 404
    # The list never shows them.
    listed = {p["id"] for p in owner.get("/api/users", params={"limit": 200}).json()["items"]}
    assert str(people.ids["b_ana"]) not in listed and str(people.ids["b_chef"]) not in listed
    _unchanged(people, "b_ana")


def test_a_new_account_cannot_point_into_another_company(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    body = {"display_name": "Mole", "email": "mole@northwind.example"}
    # Their department, or their person as manager: unknown references (422).
    into = owner.post("/api/users", json=body | {"department_id": str(people.ids["b_kitchen"])})
    under = owner.post(
        "/api/users",
        json=body
        | {"department_id": str(people.ids["kitchen"]), "manager_id": str(people.ids["b_chef"])},
    )
    assert into.status_code == 422 and under.status_code == 422
    with people.db(people.company_b) as db:
        assert db.scalars(select(User).where(User.email == "mole@northwind.example")).all() == []
    # And not in our company either: nothing half-made.
    with people.db() as db:
        assert db.scalars(select(User).where(User.email == "mole@northwind.example")).all() == []


def test_a_taken_email_never_says_which_company_has_it(people: ShiftSetup) -> None:
    """I3: the answer for an address used in the other company is byte for byte the answer
    for one used in this company, so creating accounts cannot be used to find out who
    else has an account on the platform."""
    owner = people.browser("owner")
    body = {"display_name": "Probe", "department_id": str(people.ids["kitchen"])}
    ours = owner.post("/api/users", json=body | {"email": "ana@northwind.example"})
    theirs = owner.post("/api/users", json=body | {"email": "b_ana@summit.example"})
    assert (ours.status_code, ours.content) == (theirs.status_code, theirs.content)
    # Renaming into it too.
    url = f"/api/users/{people.ids['cara']}"
    renamed = owner.patch(url, json={"email": "b_ana@summit.example"})
    assert (renamed.status_code, renamed.json()["detail"]) == (409, ours.json()["detail"])
    # The other company's person is untouched.
    assert person(people, "b_ana").email == "b_ana@summit.example"


# --- E3: only someone above the person, with user.manage -------------------------------


def test_managers_and_employees_cannot_change_accounts(people: ShiftSetup) -> None:
    # chef holds user.view over Kitchen and is above ana in the chain, but has no
    # user.manage: 403 for everything, before anything is revealed or changed.
    for name in ("chef", "lead", "ana"):
        client = people.browser(name)
        statuses = every_change(client, people.ids["cara"], people.ids["front"])
        assert set(statuses.values()) == {403}, (name, statuses)
        body = {
            "display_name": "Mine",
            "email": f"mine-{name}@northwind.example",
            "department_id": str(people.ids["kitchen"]),
        }
        assert client.post("/api/users", json=body).status_code == 403
    _unchanged(people, "cara")


def test_user_manage_without_a_place_above_is_refused(people: ShiftSetup) -> None:
    """AZ5: the administrator holds user.manage for the whole company, but is above
    nobody who does not report to them: dana (no manager) and the owner."""
    admin = people.browser("admin")
    for name in ("dana", "owner"):
        statuses = every_change(admin, people.ids[name], people.ids["kitchen"])
        assert set(statuses.values()) == {403}, (name, statuses)
        _unchanged(people, name)
    # Below them (chef reports to admin): allowed, which shows the refusals are the chain.
    assert admin.post(f"/api/users/{people.ids['chef']}/unlock").status_code == 200


def test_an_ended_reporting_line_ends_the_reach(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    assert (
        admin.patch(f"/api/users/{people.ids['ana']}", json={"display_name": "Ana"}).status_code
        == 200
    )
    # chef no longer reports to admin: everyone under chef is out of the admin's reach.
    from app.authz.models import ReportingLine
    from app.db.base import utcnow

    with people.db() as db:
        line = db.scalars(
            select(ReportingLine).where(
                ReportingLine.manager_id == people.ids["admin"],
                ReportingLine.employee_id == people.ids["chef"],
            )
        ).one()
        line.ended_at = utcnow()
        db.commit()
    statuses = every_change(admin, people.ids["ana"], people.ids["kitchen"])
    assert set(statuses.values()) == {403}, statuses


def test_a_new_account_cannot_be_hung_under_someone_out_of_reach(people: ShiftSetup) -> None:
    """Without this, an administrator could create an account under the owner (or anyone
    else not below them) and so place a person where the chain gives them no reach."""
    admin = people.browser("admin")
    body = {
        "display_name": "Plant",
        "email": "plant@northwind.example",
        "department_id": str(people.ids["kitchen"]),
    }
    for name in ("owner", "dana"):
        assert (
            admin.post("/api/users", json=body | {"manager_id": str(people.ids[name])}).status_code
            == 403
        )
    assert actions(people, "user.created") == []


def test_nobody_moves_a_person_out_of_their_own_reach(people: ShiftSetup) -> None:
    """A department-scoped user.manage covers that department's people only: moving
    someone to another department, or creating someone there, is refused (403)."""
    from app.audit import Actor
    from app.authz.models import Role, RolePermission
    from app.authz.roles import assign_role

    with people.db() as db:
        # A custom role: user.manage for the Kitchen department only, given to chef.
        role = Role(name="Kitchen admin")
        db.add(role)
        db.flush()
        db.add(RolePermission(role_id=role.id, permission_code="user.manage"))
        assign_role(
            db,
            Actor.system(),
            user_id=people.ids["chef"],
            role=role,
            scope_type="department",
            scope_id=people.ids["kitchen"],
        )
        db.commit()
    chef = people.browser("chef")
    url = f"/api/users/{people.ids['ana']}"
    # Inside Kitchen: allowed (chef is above ana).
    assert chef.patch(url, json={"display_name": "Ana K."}).status_code == 200
    # Out to Front, where chef's role does not reach: refused, and she stays in Kitchen.
    assert chef.patch(url, json={"department_id": str(people.ids["front"])}).status_code == 403
    assert person(people, "ana").department_id == people.ids["kitchen"]
    created = chef.post(
        "/api/users",
        json={
            "display_name": "Elsewhere",
            "email": "elsewhere@northwind.example",
            "department_id": str(people.ids["front"]),
            "manager_id": str(people.ids["chef"]),
        },
    )
    assert created.status_code == 403


# --- I2: seeing people outside one's scope ---------------------------------------------


def test_a_manager_never_sees_people_outside_their_scope(people: ShiftSetup) -> None:
    chef = people.browser("chef")
    listed = {p["id"] for p in chef.get("/api/users", params={"limit": 200}).json()["items"]}
    outside = {"owner", "admin", "lead", "ben", "dana"}
    assert not listed & {str(people.ids[name]) for name in outside}
    for name in outside:
        assert chef.get(f"/api/users/{people.ids[name]}").status_code == 403, name
    # A bookmark naming someone outside the scope is refused, not used to page past them.
    from app.modules.org.repository import encode_cursor

    peek = chef.get("/api/users", params={"cursor": encode_cursor(people.ids["ben"])})
    assert peek.status_code == 422


# --- E8: forged and signed-out requests ------------------------------------------------


def test_signed_out_and_cross_site_requests_change_nothing(people: ShiftSetup) -> None:
    stranger = TestClient(people.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]
    assert stranger.get("/api/users").status_code == 401
    assert stranger.get(f"/api/users/{people.ids['ana']}").status_code == 401
    forged = people.browser("owner")
    token = forged.headers.pop("X-CSRF-Token")
    try:
        statuses = every_change(forged, people.ids["ana"], people.ids["front"])
        created = forged.post(
            "/api/users",
            json={
                "display_name": "Forged",
                "email": "forged@northwind.example",
                "department_id": str(people.ids["kitchen"]),
            },
        )
    finally:
        forged.headers["X-CSRF-Token"] = token
    assert set(statuses.values()) == {403} and created.status_code == 403, statuses
    _unchanged(people, "ana")
    assert actions(people, "user.created") == []


# --- I5: what answers and the audit log keep -------------------------------------------


def test_the_audit_log_never_keeps_an_email(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    made = owner.post(
        "/api/users",
        json={
            "display_name": "Quiet",
            "email": "quiet@northwind.example",
            "department_id": str(people.ids["kitchen"]),
        },
    ).json()
    owner.patch(f"/api/users/{made['id']}", json={"email": "quieter@northwind.example"})
    with people.db() as db:
        details = db.scalars(
            select(AuditEvent.details).where(AuditEvent.target_id == uuid.UUID(made["id"]))
        ).all()
    assert len(details) == 2
    assert "quiet" not in str(details)
