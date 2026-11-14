"""People's accounts over HTTP (docs/features/organization.md, "People").

The happy paths and the rules, as the owner or the administrator. Other companies, people
outside someone's reach, and forged requests are in tests/security/test_people.py.
"""

import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.audit.models import AuditEvent
from app.auth.models import UserSession
from app.authz.models import ReportingLine, Role, RoleAssignment
from app.db.base import utcnow
from app.modules.org.models import User
from tests.people_data import actions, people, person
from tests.shift_data import BASE_URL, PASSWORD, ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here


def _new(setup: ShiftSetup, who: str = "owner", **fields: object) -> dict:
    """Create an account through the API (Kitchen by default) and return the answer."""
    body = {
        "display_name": "Dana Fox",
        "email": "dana.fox@northwind.example",
        "department_id": str(setup.ids["kitchen"]),
    } | {k: str(v) if v is not None else None for k, v in fields.items()}
    response = setup.browser(who).post("/api/users", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _browser(setup: ShiftSetup) -> TestClient:
    """A new browser, not signed in."""
    return TestClient(setup.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]


# --- Creating accounts -----------------------------------------------------------------


def test_the_owner_creates_an_account_with_no_password_yet(people: ShiftSetup) -> None:
    created = _new(people, email="  Dana.Fox@Northwind.example ")
    # Stored in lowercase without the spaces; invited until the setup link is used.
    assert created | {"id": None} == {
        "id": None,
        "display_name": "Dana Fox",
        "email": "dana.fox@northwind.example",
        "department_id": str(people.ids["kitchen"]),
        "team_ids": [],
        "status": "invited",
        "locked": False,
    }
    with people.db() as db:
        row = db.get(User, uuid.UUID(created["id"]))
        assert row is not None and row.password_hash is None
        # The owner is above everyone, so no reporting line was needed.
        assert (
            db.scalars(select(ReportingLine).where(ReportingLine.employee_id == row.id)).all() == []
        )
        entry = db.scalars(select(AuditEvent).where(AuditEvent.action == "user.created")).one()
    assert entry.details == {"department_id": str(people.ids["kitchen"]), "manager_id": None}
    # An account without a password cannot be signed into (authentication.md).
    tried = _browser(people).post(
        "/api/sessions", json={"email": "dana.fox@northwind.example", "password": PASSWORD}
    )
    assert tried.status_code == 401


def test_an_administrator_names_who_the_new_person_reports_to(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    body = {
        "display_name": "Dana Fox",
        "email": "dana.fox@northwind.example",
        "department_id": str(people.ids["kitchen"]),
    }
    # Only an owner may leave it out.
    missing = admin.post("/api/users", json=body)
    assert missing.status_code == 422 and "reports to" in missing.json()["detail"]

    # Someone the administrator is above: the Kitchen manager.
    created = _new(people, "admin", manager_id=people.ids["chef"])
    with people.db() as db:
        line = db.scalars(
            select(ReportingLine).where(ReportingLine.employee_id == uuid.UUID(created["id"]))
        ).one()
    assert line.manager_id == people.ids["chef"] and line.ended_at is None
    # The line puts the administrator above the new person at once: they can go on.
    renamed = admin.patch(f"/api/users/{created['id']}", json={"display_name": "Dana F."})
    assert renamed.status_code == 200
    # Audited together, the account first.
    assert actions(people, "user.created") == ["user.created"]
    assert actions(people, "reporting_line.added")[-1] == "reporting_line.added"

    # Or the administrator themselves.
    mine = _new(people, "admin", email="eve@northwind.example", manager_id=people.ids["admin"])
    with people.db() as db:
        line = db.scalars(
            select(ReportingLine).where(ReportingLine.employee_id == uuid.UUID(mine["id"]))
        ).one()
    assert line.manager_id == people.ids["admin"]


def test_the_manager_must_be_below_the_creator_and_active(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    body = {
        "display_name": "Dana Fox",
        "email": "dana.fox@northwind.example",
        "department_id": str(people.ids["kitchen"]),
    }
    # The owner and dana are not below the administrator: 403.
    for name in ("owner", "dana"):
        response = admin.post("/api/users", json=body | {"manager_id": str(people.ids[name])})
        assert response.status_code == 403, name
    # A deactivated manager: 409. Unknown: 422.
    gone = admin.post("/api/users", json=body | {"manager_id": str(people.ids["gone"])})
    assert gone.status_code == 409
    unknown = admin.post(
        "/api/users", json=body | {"manager_id": "00000000-0000-0000-0000-000000000000"}
    )
    assert unknown.status_code == 422
    # Nothing was created along the way.
    with people.db() as db:
        assert (
            db.scalars(select(User).where(User.email == "dana.fox@northwind.example")).all() == []
        )


def test_a_taken_email_gets_the_generic_answer(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    body = {"display_name": "Copy", "department_id": str(people.ids["kitchen"])}
    # Taken in this company (any case), and taken in the other company: the same answer.
    ours = owner.post("/api/users", json=body | {"email": "ANA@northwind.example"})
    theirs = owner.post("/api/users", json=body | {"email": "b_ana@summit.example"})
    assert ours.status_code == theirs.status_code == 409
    assert ours.json() == theirs.json()
    assert ours.json()["detail"] == "This email can't be used."
    assert actions(people, "user.created") == []


def test_account_input_is_checked(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    good = {
        "display_name": "Dana",
        "email": "dana.fox@northwind.example",
        "department_id": str(people.ids["kitchen"]),
    }
    for change in (
        {"display_name": ""},
        {"display_name": "x" * 121},
        {"email": "not-an-email"},
        {"email": "two@@northwind.example"},
        {"email": "spaces in@northwind.example"},
        {"email": "a@" + "x" * 250 + ".com"},
        {"department_id": "00000000-0000-0000-0000-000000000000"},  # unknown department
        # Fields that only the rules may set are refused, not ignored.
        {"password_hash": "x"},
        {"company_id": str(people.company_b)},
        {"deactivated_at": None},
    ):
        assert owner.post("/api/users", json=good | change).status_code == 422, change


def test_nobody_is_placed_in_an_archived_department(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    made = owner.post("/api/departments", json={"name": "Closed"}).json()
    owner.post(f"/api/departments/{made['id']}/archive")
    body = {"display_name": "Dana", "email": "d@northwind.example", "department_id": made["id"]}
    assert owner.post("/api/users", json=body).status_code == 409
    moved = owner.patch(f"/api/users/{people.ids['ana']}", json={"department_id": made["id"]})
    assert moved.status_code == 409


# --- Seeing people ---------------------------------------------------------------------


def test_the_owner_lists_everyone_by_name_in_pages(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    everyone = owner.get("/api/users", params={"limit": 200}).json()
    names = [p["display_name"] for p in everyone["items"]]
    assert names == sorted(names) and len(names) == 10 and everyone["next_cursor"] is None
    # Deactivated and invited people are listed too, with their state.
    states = {p["display_name"]: p["status"] for p in everyone["items"]}
    assert states["Gone"] == "deactivated" and states["Newbie"] == "invited"
    assert states["Ana"] == "active"
    # Ben's teams are in the answer.
    ben = next(p for p in everyone["items"] if p["display_name"] == "Ben")
    assert ben["team_ids"] == [str(people.ids["crew"])]

    first = owner.get("/api/users", params={"limit": 4}).json()
    rest = owner.get("/api/users", params={"limit": 200, "cursor": first["next_cursor"]}).json()
    assert [p["display_name"] for p in first["items"] + rest["items"]] == names
    assert owner.get("/api/users", params={"cursor": "nonsense"}).status_code == 422


def test_a_manager_lists_and_views_only_the_people_in_their_scope(people: ShiftSetup) -> None:
    # chef manages the Kitchen department: its people, including chef themselves (user.view
    # is a record permission, so the scope decides, not the chain).
    chef = people.browser("chef")
    seen = {p["display_name"] for p in chef.get("/api/users").json()["items"]}
    assert seen == {"Chef", "Ana", "Cara", "Newbie", "Gone"}
    assert chef.get(f"/api/users/{people.ids['ana']}").status_code == 200
    # Ben's home is Front: outside the Kitchen scope, though he is on a Kitchen team.
    assert chef.get(f"/api/users/{people.ids['ben']}").status_code == 403
    # lead manages the Weekend Crew: its member Ben only (and nobody else).
    lead = people.browser("lead")
    assert {p["display_name"] for p in lead.get("/api/users").json()["items"]} == {"Ben"}


def test_everyone_sees_their_own_account_but_employees_list_nobody(people: ShiftSetup) -> None:
    ana = people.browser("ana")
    mine = ana.get(f"/api/users/{people.ids['ana']}")
    assert mine.status_code == 200 and mine.json()["email"] == "ana@northwind.example"
    assert ana.get(f"/api/users/{people.ids['cara']}").status_code == 403
    assert ana.get("/api/users").status_code == 403


def test_answers_never_include_password_or_lockout_details(people: ShiftSetup) -> None:
    text = people.browser("owner").get("/api/users", params={"limit": 200}).text
    for word in ("password", "hash", "argon2", "failed_sign_ins", "locked_until"):
        assert word not in text


# --- Changing details ------------------------------------------------------------------


def test_details_are_changed_one_field_at_a_time(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    url = f"/api/users/{people.ids['ana']}"
    changed = admin.patch(
        url, json={"display_name": " Ana Lund ", "email": "ANA.L@northwind.example"}
    )
    assert changed.status_code == 200
    assert changed.json()["display_name"] == "Ana Lund"
    assert changed.json()["email"] == "ana.l@northwind.example"
    moved = admin.patch(url, json={"department_id": str(people.ids["front"])})
    assert moved.json()["department_id"] == str(people.ids["front"])
    # Sending nothing changes nothing and is not audited.
    assert admin.patch(url, json={}).status_code == 200

    with people.db() as db:
        entries = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "user.updated").order_by(AuditEvent.seq)
        ).all()
    # Which fields, never their values.
    assert [e.details for e in entries] == [
        {"fields": ["display_name", "email"]},
        {"fields": ["department_id"]},
    ]
    assert "ana" not in str([e.details for e in entries]).lower()


def test_changing_details_keeps_the_rules(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    url = f"/api/users/{people.ids['ana']}"
    taken = admin.patch(url, json={"email": "cara@northwind.example"})
    assert taken.status_code == 409 and taken.json()["detail"] == "This email can't be used."
    for body in (
        {"display_name": None},
        {"email": None},
        {"department_id": None},
        {"department_id": str(people.ids["b_kitchen"])},  # another company's: unknown
        {"password_hash": "x"},
    ):
        assert admin.patch(url, json=body).status_code == 422, body
    assert person(people, "ana").email == "ana@northwind.example"


# --- Deactivating and reactivating -----------------------------------------------------


def test_deactivating_ends_every_session_and_lists_upcoming_shifts(people: ShiftSetup) -> None:
    ana = people.browser("ana")
    assert ana.get("/api/sessions/current").status_code == 200
    shift = people.new_shift("chef", employee_id=people.ids["ana"])

    done = people.browser("admin").post(f"/api/users/{people.ids['ana']}/deactivate")
    assert done.status_code == 200
    assert done.json()["status"] == "deactivated"
    # The shift stays assigned, for the administrator to reassign.
    assert done.json()["upcoming_shift_ids"] == [shift["id"]]
    assert people.browser("owner").get(f"/api/shifts/{shift['id']}").json()["employee"] is not None
    # Her browser is signed out at once, and no session row is left.
    assert ana.get("/api/sessions/current").status_code == 401
    with people.db() as db:
        assert (
            db.scalars(select(UserSession).where(UserSession.user_id == people.ids["ana"])).all()
            == []
        )
        ended = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "auth.sessions_ended")
        ).one()
    assert ended.details == {"count": 1, "reason": "deactivated"}
    assert actions(people, "user.deactivated") == ["user.deactivated"]

    # Already deactivated: 409. And no new shift or team for her.
    assert (
        people.browser("admin").post(f"/api/users/{people.ids['ana']}/deactivate").status_code
        == 409
    )
    crew = f"/api/teams/{people.ids['crew']}/members"
    assert (
        people.browser("owner").post(crew, json={"user_id": str(people.ids["ana"])}).status_code
        == 409
    )


def test_an_owner_cannot_be_deactivated(people: ShiftSetup) -> None:
    # Make dana a second owner: still refused (owners leave through the owner change flow).
    with people.db() as db:
        owner_role = db.scalars(select(Role).where(Role.built_in == "owner")).one()
        db.add(
            RoleAssignment(user_id=people.ids["dana"], role_id=owner_role.id, scope_type="company")
        )
        db.commit()
    response = people.browser("owner").post(f"/api/users/{people.ids['dana']}/deactivate")
    assert response.status_code == 409 and "owner" in response.json()["detail"]
    assert person(people, "dana").deactivated_at is None


def test_reactivating_goes_back_to_invited(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    url = f"/api/users/{people.ids['cara']}"
    # Not deactivated: nothing to undo.
    assert admin.post(f"{url}/reactivate").status_code == 409
    admin.post(f"{url}/deactivate")
    back = admin.post(f"{url}/reactivate")
    assert back.status_code == 200 and back.json()["status"] == "invited"
    # The old password no longer works: she sets a new one with a setup link (#57).
    assert person(people, "cara").password_hash is None
    assert actions(people, "user.reactivated") == ["user.reactivated"]


def test_nobody_is_reactivated_into_an_archived_department(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    made = owner.post("/api/departments", json={"name": "Patio"}).json()
    owner.patch(f"/api/users/{people.ids['cara']}", json={"department_id": made["id"]})
    owner.post(f"/api/users/{people.ids['cara']}/deactivate")
    # Nobody active has it as home any more, so it can be archived.
    assert owner.post(f"/api/departments/{made['id']}/archive").status_code == 200
    refused = owner.post(f"/api/users/{people.ids['cara']}/reactivate")
    assert refused.status_code == 409 and "archived" in refused.json()["detail"]
    # Moved to an active department first, she can come back.
    owner.patch(
        f"/api/users/{people.ids['cara']}", json={"department_id": str(people.ids["kitchen"])}
    )
    assert owner.post(f"/api/users/{people.ids['cara']}/reactivate").status_code == 200


# --- Unlocking and signing out ---------------------------------------------------------


def test_unlocking_clears_a_lockout(people: ShiftSetup) -> None:
    with people.db() as db:
        ana = db.get(User, people.ids["ana"])
        assert ana is not None
        ana.failed_sign_ins, ana.locked_until = 7, utcnow() + timedelta(minutes=30)
        db.commit()
    admin = people.browser("admin")
    assert admin.get(f"/api/users/{people.ids['ana']}").json()["locked"] is True
    done = admin.post(f"/api/users/{people.ids['ana']}/unlock")
    assert done.status_code == 200 and done.json()["locked"] is False
    after = person(people, "ana")
    assert after.failed_sign_ins == 0 and after.locked_until is None
    # Nothing left to clear: still 200, but nothing happened, so nothing is audited.
    assert admin.post(f"/api/users/{people.ids['ana']}/unlock").status_code == 200
    assert actions(people, "auth.unlocked") == ["auth.unlocked"]


def test_signing_someone_out_everywhere(people: ShiftSetup) -> None:
    ana = people.browser("ana")
    second = _browser(people)  # a second browser where she is signed in
    second.post("/api/sessions", json={"email": "ana@northwind.example", "password": PASSWORD})
    done = people.browser("admin").delete(f"/api/users/{people.ids['ana']}/sessions")
    assert done.status_code == 204 and done.content == b""
    assert ana.get("/api/sessions/current").status_code == 401
    assert second.get("/api/sessions/current").status_code == 401
    with people.db() as db:
        entry = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "auth.sessions_ended")
        ).one()
    assert entry.details == {"count": 2, "reason": "signed_out"}
    # She can still sign in again: signing out is not deactivating.
    assert person(people, "ana").deactivated_at is None


def test_nobody_acts_on_their_own_account_through_these_actions(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    url = f"/api/users/{people.ids['owner']}"
    for response in (
        owner.patch(url, json={"display_name": "Me"}),
        owner.post(f"{url}/deactivate"),
        owner.post(f"{url}/unlock"),
        owner.delete(f"{url}/sessions"),
    ):
        assert response.status_code == 403
    assert owner.get("/api/sessions/current").status_code == 200
