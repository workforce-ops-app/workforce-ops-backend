"""Shifts against the threats on the schedules page (I1, I2, T2, T3, T5, D2, E8).

Every request here goes through the real app: the session, the CSRF check, the company
filter, and authorize(). Each test is someone reaching for shifts they should not see or
change.
"""

import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.authz.models import Role, RolePermission
from app.modules.schedules.models import Shift
from tests.shift_data import BASE_URL, ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


def every_endpoint(client: TestClient, shift_id: object) -> dict[str, int]:
    """The status of every shift endpoint for one shift ID."""
    url = f"/api/shifts/{shift_id}"
    return {
        "get": client.get(url).status_code,
        "patch": client.patch(url, json={"notes": "x"}).status_code,
        "assign": client.post(f"{url}/assign", json={"employee_id": None}).status_code,
        "cancel": client.post(f"{url}/cancel").status_code,
    }


# --- I1, T3: other companies -----------------------------------------------------------


def test_another_companys_shift_does_not_exist_on_any_endpoint(shifts: ShiftSetup) -> None:
    theirs = shifts.new_shift(
        "b_chef", department_id=shifts.ids["b_kitchen"], employee_id=shifts.ids["b_ana"]
    )
    # Even company A's owner gets exactly the answer for an ID that does not exist.
    assert every_endpoint(shifts.browser("owner"), theirs["id"]) == {
        "get": 404,
        "patch": 404,
        "assign": 404,
        "cancel": 404,
    }
    assert every_endpoint(shifts.browser("owner"), uuid.uuid4()) == {
        "get": 404,
        "patch": 404,
        "assign": 404,
        "cancel": 404,
    }


def test_another_companys_shifts_never_appear_in_a_list(shifts: ShiftSetup) -> None:
    shifts.new_shift("b_chef", department_id=shifts.ids["b_kitchen"])
    first = soon().date()
    # Even when asking for their department by ID.
    for params in ({}, {"department_id": str(shifts.ids["b_kitchen"])}):
        response = shifts.browser("owner").get(
            "/api/shifts",
            params={"from": str(first), "to": str(first + timedelta(days=6))} | params,
        )
        assert response.json()["items"] == []


def test_another_companys_department_or_person_cannot_be_used(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    body = {"starts_at": iso(soon()), "ends_at": iso(soon() + timedelta(hours=4))}
    # Their department: the same answer as one that does not exist.
    foreign = owner.post("/api/shifts", json=body | {"department_id": str(shifts.ids["b_kitchen"])})
    missing = owner.post("/api/shifts", json=body | {"department_id": str(uuid.uuid4())})
    assert foreign.status_code == missing.status_code == 422
    assert foreign.json()["detail"] == missing.json()["detail"]
    # Their person, on our shift.
    ours = shifts.new_shift("owner")
    assigned = owner.post(
        f"/api/shifts/{ours['id']}/assign", json={"employee_id": str(shifts.ids["b_ana"])}
    )
    assert assigned.status_code == 422


# --- I2: shifts outside your scope -----------------------------------------------------


def test_a_manager_cannot_see_or_change_another_departments_shifts(shifts: ShiftSetup) -> None:
    front = shifts.new_shift("owner", department_id=shifts.ids["front"])
    assert every_endpoint(shifts.browser("chef"), front["id"]) == {
        "get": 403,
        "patch": 403,
        "assign": 403,
        "cancel": 403,
    }
    body = {
        "department_id": str(shifts.ids["front"]),
        "starts_at": iso(soon()),
        "ends_at": iso(soon() + timedelta(hours=4)),
    }
    assert shifts.browser("chef").post("/api/shifts", json=body).status_code == 403


def test_a_managers_list_shows_only_their_scope(shifts: ShiftSetup) -> None:
    kitchen = shifts.new_shift("owner")
    shifts.new_shift(
        "owner", department_id=shifts.ids["front"], starts_at=iso(soon(2)), ends_at=iso(soon(2, 18))
    )
    first = soon().date()
    listed = shifts.browser("chef").get(
        "/api/shifts", params={"from": str(first), "to": str(first + timedelta(days=6))}
    )
    assert [s["id"] for s in listed.json()["items"]] == [kitchen["id"]]


def test_a_team_manager_covers_their_members_shifts_only(shifts: ShiftSetup) -> None:
    lead = shifts.browser("lead")
    # Ben is on the Weekend Crew: his Kitchen shift is the lead's business...
    bens = shifts.new_shift("owner", employee_id=shifts.ids["ben"])
    assert lead.patch(f"/api/shifts/{bens['id']}", json={"notes": "ok"}).status_code == 200
    # ...an open Kitchen shift is not...
    open_one = shifts.new_shift("owner", starts_at=iso(soon(2)), ends_at=iso(soon(2, 18)))
    assert lead.patch(f"/api/shifts/{open_one['id']}", json={"notes": "x"}).status_code == 403
    # ...and the lead cannot move Ben's shift to someone outside the crew (the shift would
    # leave their scope), even though Ana could work it.
    moved = lead.post(
        f"/api/shifts/{bens['id']}/assign", json={"employee_id": str(shifts.ids["ana"])}
    )
    assert moved.status_code == 403
    with shifts.db() as db:  # nothing changed
        assert db.get(Shift, uuid.UUID(bens["id"])).employee_id == shifts.ids["ben"]  # type: ignore[union-attr]


def test_employees_see_their_department_and_their_own_shifts_only(shifts: ShiftSetup) -> None:
    ana = shifts.browser("ana")
    kitchen = shifts.new_shift("owner")
    front = shifts.new_shift(
        "owner", department_id=shifts.ids["front"], starts_at=iso(soon(2)), ends_at=iso(soon(2, 18))
    )
    assert ana.get(f"/api/shifts/{kitchen['id']}").status_code == 200
    assert ana.get(f"/api/shifts/{front['id']}").status_code == 403
    # A shift belongs to its person's home department too: Ben (home Front) sees his
    # Kitchen shift through his Front scope.
    bens = shifts.new_shift(
        "owner", employee_id=shifts.ids["ben"], starts_at=iso(soon(3)), ends_at=iso(soon(3, 18))
    )
    assert shifts.browser("ben").get(f"/api/shifts/{bens['id']}").status_code == 200


def test_without_schedule_view_an_employee_sees_only_their_own_shifts(
    shifts: ShiftSetup,
) -> None:
    # An administrator removes schedule.view from the Employee role (authorization.md):
    # from the next request on, employees see only their own shifts.
    kitchen_open = shifts.new_shift("owner")
    own = shifts.new_shift(
        "owner", employee_id=shifts.ids["ana"], starts_at=iso(soon(2)), ends_at=iso(soon(2, 18))
    )
    with shifts.db() as db:
        employee_role = db.scalars(select(Role).where(Role.built_in == "employee")).one()
        db.execute(
            delete(RolePermission).where(
                RolePermission.role_id == employee_role.id,
                RolePermission.permission_code == "schedule.view",
            )
        )
        db.commit()

    ana = shifts.browser("ana")
    first = soon().date()
    days = {"from": str(first), "to": str(first + timedelta(days=6))}
    assert ana.get("/api/shifts", params=days).status_code == 403
    mine = ana.get("/api/shifts", params=days | {"mine": "true"}).json()["items"]
    assert [s["id"] for s in mine] == [own["id"]]
    assert ana.get(f"/api/shifts/{kitchen_open['id']}").status_code == 403
    assert ana.get(f"/api/shifts/{own['id']}").status_code == 200


# --- E8: employees calling the API directly --------------------------------------------


def test_an_employee_cannot_change_shifts_even_through_the_api(shifts: ShiftSetup) -> None:
    ana = shifts.browser("ana")
    own = shifts.new_shift(employee_id=shifts.ids["ana"])
    statuses = every_endpoint(ana, own["id"])
    statuses.pop("get")  # she may read her own shift
    assert statuses == {"patch": 403, "assign": 403, "cancel": 403}
    body = {
        "department_id": str(shifts.ids["kitchen"]),
        "starts_at": iso(soon(4)),
        "ends_at": iso(soon(4) + timedelta(hours=4)),
    }
    assert ana.post("/api/shifts", json=body).status_code == 403


def test_signed_out_and_forged_requests_are_refused(shifts: ShiftSetup) -> None:
    stranger = TestClient(shifts.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]
    first = str(soon().date())
    assert stranger.get("/api/shifts", params={"from": first, "to": first}).status_code == 401
    # A signed-in manager's browser, but the request comes without the CSRF token.
    chef = shifts.browser("chef")
    token = chef.headers.pop("X-CSRF-Token")
    body = {
        "department_id": str(shifts.ids["kitchen"]),
        "starts_at": iso(soon()),
        "ends_at": iso(soon() + timedelta(hours=4)),
    }
    assert chef.post("/api/shifts", json=body).status_code == 403
    chef.headers["X-CSRF-Token"] = token


# --- T2: setting the company or status directly ----------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"company_id": "00000000-0000-0000-0000-000000000000"},
        {"status": "cancelled"},
        {"id": "00000000-0000-0000-0000-000000000001"},
        {"timezone": "UTC"},
    ],
)
def test_fields_outside_the_rules_cannot_be_set(shifts: ShiftSetup, extra: dict) -> None:
    chef = shifts.browser("chef")
    body = {
        "department_id": str(shifts.ids["kitchen"]),
        "starts_at": iso(soon()),
        "ends_at": iso(soon() + timedelta(hours=4)),
    }
    assert chef.post("/api/shifts", json=body | extra).status_code == 422
    existing = shifts.new_shift(starts_at=iso(soon(5)), ends_at=iso(soon(5, 18)))
    changed = chef.patch(f"/api/shifts/{existing['id']}", json={"department_id": "x"} | extra)
    assert changed.status_code == 422


# --- T5: text is data, never markup ----------------------------------------------------


def test_text_fields_come_back_exactly_as_written(shifts: ShiftSetup) -> None:
    # The API stores and returns text unchanged, as a JSON string; the pages show it with
    # textContent, never as HTML (frontend), so a script tag stays harmless text.
    payload = '<img src=x onerror="alert(1)"> & "quotes"'
    created = shifts.new_shift(notes=payload, event_name="<b>Inventory</b>")
    assert created["notes"] == payload and created["event_name"] == "<b>Inventory</b>"


# --- D2: huge requests -----------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {"days": 31, "extra": {"limit": "201"}},
        {"days": 32, "extra": {}},
        {"days": -1, "extra": {}},
        {"days": 1, "extra": {"cursor": "not-a-cursor"}},
    ],
)
def test_oversized_or_malformed_list_requests_are_refused(shifts: ShiftSetup, params: dict) -> None:
    first = soon().date()
    query = {"from": str(first), "to": str(first + timedelta(days=params["days"] - 1))}
    response = shifts.browser("chef").get("/api/shifts", params=query | params["extra"])
    assert response.status_code == 422


def test_thirty_one_days_is_allowed(shifts: ShiftSetup) -> None:
    first = soon().date()
    query = {"from": str(first), "to": str(first + timedelta(days=30))}
    assert shifts.browser("chef").get("/api/shifts", params=query).status_code == 200
