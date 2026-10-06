"""Shifts through the API: the agreed answer, time zones, the list, paging, and the rules.

The attacks (other companies, scopes, employees calling the API directly, forged fields,
huge ranges) are in tests/security/test_shifts.py.
"""

from datetime import timedelta

from sqlalchemy import select

from app.audit.models import AuditEvent
from app.db.base import utcnow
from app.modules.schedules.models import Shift
from tests.shift_data import ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


def week(setup: ShiftSetup, who: str, **params: str) -> dict:
    first = soon().date()
    query = {"from": str(first), "to": str(first + timedelta(days=6))} | params
    response = setup.browser(who).get("/api/shifts", params=query)
    assert response.status_code == 200, response.text
    return response.json()


def test_a_created_shift_has_the_agreed_shape(shifts: ShiftSetup) -> None:
    created = shifts.new_shift(employee_id=shifts.ids["ana"], details="Register 2")

    assert set(created) == {
        "id",
        "department",
        "employee",
        "starts_at",
        "ends_at",
        "timezone",
        "status",
        "details",
        "notes",
        "event_name",
        "event_description",
    }
    assert created["department"] == {"id": str(shifts.ids["kitchen"]), "name": "Kitchen"}
    assert created["employee"] == {"id": str(shifts.ids["ana"]), "display_name": "Ana"}
    assert created["status"] == "scheduled"
    assert created["details"] == "Register 2"
    assert created["starts_at"].endswith("Z") or created["starts_at"].endswith("+00:00")


def test_an_open_shift_has_nobody(shifts: ShiftSetup) -> None:
    created = shifts.new_shift()
    assert created["employee"] is None and created["status"] == "open"


def test_the_workplace_zone_is_copied_onto_the_shift(shifts: ShiftSetup) -> None:
    # Kitchen has no zone of its own: the company's. Front has its own.
    assert shifts.new_shift()["timezone"] == "America/Chicago"
    front = shifts.new_shift("owner", department_id=shifts.ids["front"])
    assert front["timezone"] == "America/New_York"


def test_the_week_lists_shifts_with_names_and_leaves_out_cancelled_ones(
    shifts: ShiftSetup,
) -> None:
    kept = shifts.new_shift(employee_id=shifts.ids["ana"])
    gone = shifts.new_shift(starts_at=iso(soon(2)), ends_at=iso(soon(2) + timedelta(hours=4)))
    shifts.browser("chef").post(f"/api/shifts/{gone['id']}/cancel")

    listed = week(shifts, "chef")
    assert [s["id"] for s in listed["items"]] == [kept["id"]]
    assert listed["items"][0]["employee"]["display_name"] == "Ana"
    assert listed["next_cursor"] is None


def test_a_shift_belongs_to_the_day_it_starts_in_its_workplace_zone(shifts: ShiftSetup) -> None:
    # 22:00 in Chicago is already the next day in UTC; the shift still belongs to its own day.
    day = soon(3).date()
    late = soon(3, hour=3)  # 03:00 UTC on day+3 is 22:00 (CDT) or 21:00 (CST) on day+2 in Chicago
    shifts.new_shift(starts_at=iso(late), ends_at=iso(late + timedelta(hours=2)))
    local_day = str(day - timedelta(days=1))
    on_local_day = shifts.browser("chef").get(
        "/api/shifts", params={"from": local_day, "to": local_day}
    )
    on_utc_day = shifts.browser("chef").get(
        "/api/shifts", params={"from": str(day), "to": str(day)}
    )
    assert len(on_local_day.json()["items"]) == 1
    assert on_utc_day.json()["items"] == []


def test_long_lists_come_a_page_at_a_time(shifts: ShiftSetup) -> None:
    made = [
        shifts.new_shift(starts_at=iso(soon(d)), ends_at=iso(soon(d) + timedelta(hours=2)))["id"]
        for d in (1, 2, 3, 4, 5)
    ]
    seen, cursor = [], None
    while True:
        params = {"limit": "2"} | ({"cursor": cursor} if cursor else {})
        page = week(shifts, "chef", **params)
        seen += [s["id"] for s in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == made  # every shift once, in order, none skipped or repeated


def test_mine_lists_only_your_own_shifts(shifts: ShiftSetup) -> None:
    mine = shifts.new_shift(employee_id=shifts.ids["ana"])
    shifts.new_shift(
        employee_id=shifts.ids["cara"], starts_at=iso(soon(2)), ends_at=iso(soon(2, 18))
    )
    listed = week(shifts, "ana", mine="true")
    assert [s["id"] for s in listed["items"]] == [mine["id"]]


def test_a_department_filter_narrows_the_list(shifts: ShiftSetup) -> None:
    shifts.new_shift("owner")
    front = shifts.new_shift(
        "owner", department_id=shifts.ids["front"], starts_at=iso(soon(2)), ends_at=iso(soon(2, 18))
    )
    listed = week(shifts, "owner", department_id=str(shifts.ids["front"]))
    assert [s["id"] for s in listed["items"]] == [front["id"]]


def test_changing_assigning_opening_and_cancelling(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    item = shifts.new_shift()
    url = f"/api/shifts/{item['id']}"

    changed = chef.patch(url, json={"notes": "Bring the keys", "details": None})
    assert changed.status_code == 200 and changed.json()["notes"] == "Bring the keys"
    assigned = chef.post(f"{url}/assign", json={"employee_id": str(shifts.ids["ana"])})
    assert assigned.json()["status"] == "scheduled"
    opened = chef.post(f"{url}/assign", json={"employee_id": None})
    assert opened.json()["status"] == "open" and opened.json()["employee"] is None
    cancelled = chef.post(f"{url}/cancel")
    assert cancelled.json()["status"] == "cancelled"
    # Cancelled is history.
    assert chef.patch(url, json={"notes": "again"}).status_code == 409

    with shifts.db() as db:
        actions = [
            e.action
            for e in db.scalars(
                select(AuditEvent)
                .where(AuditEvent.chain_id == shifts.company_a, AuditEvent.action.like("shift.%"))
                .order_by(AuditEvent.seq)
            )
        ]
        updated = db.scalars(select(AuditEvent).where(AuditEvent.action == "shift.updated")).one()
    assert actions == [
        "shift.created",
        "shift.updated",
        "shift.assigned",
        "shift.opened",
        "shift.cancelled",
    ]
    # The audit entry names the changed fields, never their text.
    assert updated.details == {"fields": ["details", "notes"]}


def test_times_must_make_sense(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    base = {"department_id": str(shifts.ids["kitchen"])}
    backwards = base | {"starts_at": iso(soon(1, 18)), "ends_at": iso(soon(1, 10))}
    too_long = base | {"starts_at": iso(soon(1, 0)), "ends_at": iso(soon(1, 13))}
    past = base | {"starts_at": iso(soon(-3)), "ends_at": iso(soon(-3) + timedelta(hours=2))}
    no_offset = base | {"starts_at": "2030-01-01T09:00:00", "ends_at": "2030-01-01T12:00:00"}
    for body in (backwards, too_long, past, no_offset):
        assert chef.post("/api/shifts", json=body).status_code == 422, body
    exactly_12 = base | {"starts_at": iso(soon(1, 0)), "ends_at": iso(soon(1, 12))}
    assert chef.post("/api/shifts", json=exactly_12).status_code == 201


def test_nobody_is_booked_twice_at_the_same_time(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    first = shifts.new_shift(employee_id=shifts.ids["ana"])  # tomorrow 14:00 to 20:00
    overlapping = {
        "department_id": str(shifts.ids["kitchen"]),
        "employee_id": str(shifts.ids["ana"]),
        "starts_at": iso(soon(1, 19)),
        "ends_at": iso(soon(1, 23)),
    }
    assert chef.post("/api/shifts", json=overlapping).status_code == 409

    # Back to back is fine; then stretching the first into the second is not.
    after = overlapping | {"starts_at": iso(soon(1, 20))}
    second = chef.post("/api/shifts", json=after)
    assert second.status_code == 201
    stretched = chef.patch(f"/api/shifts/{first['id']}", json={"ends_at": iso(soon(1, 21))})
    assert stretched.status_code == 409

    # Giving an open shift at the same time to her is refused too.
    open_one = shifts.new_shift(starts_at=iso(soon(1, 15)), ends_at=iso(soon(1, 17)))
    taken = chef.post(
        f"/api/shifts/{open_one['id']}/assign", json={"employee_id": str(shifts.ids["ana"])}
    )
    assert taken.status_code == 409


def test_only_people_who_can_work_the_shift_are_assigned(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    item = shifts.new_shift("owner")
    url = f"/api/shifts/{item['id']}/assign"
    # Dana's home is Front and she is on no Kitchen team; newbie has not set a password
    # yet; gone is deactivated.
    for name in ("dana", "newbie", "gone"):
        response = owner.post(url, json={"employee_id": str(shifts.ids[name])})
        assert response.status_code == 422, name
    # Ben's home is Front, but he is on the Weekend Crew, a Kitchen team.
    assert owner.post(url, json={"employee_id": str(shifts.ids["ben"])}).status_code == 200


def test_a_shift_that_has_ended_is_locked(shifts: ShiftSetup) -> None:
    # Written straight to the database: the API never creates a shift in the past.
    with shifts.db() as db:
        old = Shift(
            company_id=shifts.company_a,
            department_id=shifts.ids["kitchen"],
            employee_id=shifts.ids["ana"],
            status="scheduled",
            timezone="America/Chicago",
            starts_at=utcnow() - timedelta(days=2, hours=4),
            ends_at=utcnow() - timedelta(days=2),
        )
        db.add(old)
        db.commit()
        old_id = old.id
    chef = shifts.browser("chef")
    assert chef.patch(f"/api/shifts/{old_id}", json={"notes": "late"}).status_code == 409
    assert chef.post(f"/api/shifts/{old_id}/cancel").status_code == 409
    assert chef.post(f"/api/shifts/{old_id}/assign", json={"employee_id": None}).status_code == 409
    # Still readable: it is history.
    assert chef.get(f"/api/shifts/{old_id}").status_code == 200
