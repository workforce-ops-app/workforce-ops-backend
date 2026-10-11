"""Several shifts at once through the API (POST /api/shifts/batch): creating on several
days, cancelling and reassigning a selection, the count confirmation, and all or nothing.

The attacks (other companies, scopes, employees, the count confirmation as a safeguard)
are in tests/security/test_shift_batch.py.
"""

from datetime import timedelta

from sqlalchemy import func, select

from app.audit.models import AuditEvent
from app.modules.schedules.models import Shift
from tests.shift_data import ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


def days(count: int, hour: int = 14, length: int = 6) -> list[dict]:
    """The same shift (hour:00 UTC, `length` hours) on each of the next `count` days."""
    return [
        {
            "starts_at": iso(soon(day, hour)),
            "ends_at": iso(soon(day, hour) + timedelta(hours=length)),
        }
        for day in range(1, count + 1)
    ]


def audit_actions(setup: ShiftSetup) -> list[str]:
    """Company A's shift audit entries, oldest first."""
    with setup.db() as db:
        return list(
            db.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.chain_id == setup.company_a, AuditEvent.action.like("shift.%"))
                .order_by(AuditEvent.seq)
            )
        )


def shift_count(setup: ShiftSetup) -> int:
    with setup.db() as db:
        return db.scalar(select(func.count(Shift.id))) or 0


def test_the_same_shift_is_created_on_several_days(shifts: ShiftSetup) -> None:
    response = shifts.browser("chef").post(
        "/api/shifts/batch",
        json={
            "action": "create",
            "department_id": str(shifts.ids["kitchen"]),
            "employee_id": str(shifts.ids["ana"]),
            "times": days(3),
            "details": "Grill",
        },
    )

    assert response.status_code == 200, response.text
    answer = response.json()
    assert answer["action"] == "create" and answer["count"] == 3
    # Each item has the same shape as a single shift, in the order the days were sent.
    assert [item["starts_at"][:10] for item in answer["items"]] == [
        t["starts_at"][:10] for t in days(3)
    ]
    assert {item["employee"]["display_name"] for item in answer["items"]} == {"Ana"}
    assert {item["details"] for item in answer["items"]} == {"Grill"}
    # One entry per shift, then one for the batch.
    assert audit_actions(shifts) == ["shift.created"] * 3 + ["shift.batch_changed"]


def test_the_batch_entry_lists_the_action_count_and_shifts(shifts: ShiftSetup) -> None:
    created = shifts.browser("chef").post(
        "/api/shifts/batch",
        json={"action": "create", "department_id": str(shifts.ids["kitchen"]), "times": days(2)},
    )
    ids = [item["id"] for item in created.json()["items"]]

    with shifts.db() as db:
        entry = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "shift.batch_changed")
        ).one()
    assert (entry.actor_type, entry.actor_id) == ("user", shifts.ids["chef"])
    assert entry.details == {"action": "create", "count": 2, "shift_ids": ids}


def test_a_selection_is_cancelled_or_reassigned_together(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    ids = [shifts.new_shift(starts_at=t["starts_at"], ends_at=t["ends_at"])["id"] for t in days(3)]

    given = chef.post(
        "/api/shifts/batch",
        json={"action": "assign", "shift_ids": ids, "employee_id": str(shifts.ids["cara"])},
    )
    assert given.status_code == 200, given.text
    assert {item["status"] for item in given.json()["items"]} == {"scheduled"}
    assert {item["employee"]["display_name"] for item in given.json()["items"]} == {"Cara"}

    # employee_id null makes them open again.
    opened = chef.post(
        "/api/shifts/batch", json={"action": "assign", "shift_ids": ids, "employee_id": None}
    )
    assert {item["status"] for item in opened.json()["items"]} == {"open"}

    cancelled = chef.post("/api/shifts/batch", json={"action": "cancel", "shift_ids": ids[:2]})
    assert [item["status"] for item in cancelled.json()["items"]] == ["cancelled", "cancelled"]
    assert chef.get(f"/api/shifts/{ids[2]}").json()["status"] == "open"


def test_ten_or_more_shifts_need_the_count_repeated(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    body = {"action": "create", "department_id": str(shifts.ids["kitchen"]), "times": days(10)}

    missing = chef.post("/api/shifts/batch", json=body)
    assert missing.status_code == 409
    # The answer says how many shifts the batch would change, so the screen can ask.
    assert "10 shifts" in missing.json()["detail"]
    assert chef.post("/api/shifts/batch", json=body | {"confirm_count": 9}).status_code == 409
    assert shift_count(shifts) == 0

    confirmed = chef.post("/api/shifts/batch", json=body | {"confirm_count": 10})
    assert confirmed.status_code == 200 and confirmed.json()["count"] == 10


def test_nine_shifts_need_no_count_but_a_wrong_one_is_refused(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    body = {"action": "create", "department_id": str(shifts.ids["kitchen"]), "times": days(9)}
    # A count that is sent must match, even below 10: the screen and the server disagree.
    assert chef.post("/api/shifts/batch", json=body | {"confirm_count": 8}).status_code == 409
    assert chef.post("/api/shifts/batch", json=body).status_code == 200


def test_one_bad_shift_saves_nothing(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    # Ana already works on day 2, so the second of three new shifts would double-book her.
    shifts.new_shift(
        employee_id=shifts.ids["ana"], starts_at=iso(soon(2, 15)), ends_at=iso(soon(2, 16))
    )
    before_shifts, before_audit = shift_count(shifts), audit_actions(shifts)

    response = chef.post(
        "/api/shifts/batch",
        json={
            "action": "create",
            "department_id": str(shifts.ids["kitchen"]),
            "employee_id": str(shifts.ids["ana"]),
            "times": days(3),
        },
    )

    assert response.status_code == 409
    # Day 1 passed its checks before day 2 failed, but it was rolled back with the rest:
    # no shift and no audit entry from this batch exists.
    assert shift_count(shifts) == before_shifts
    assert audit_actions(shifts) == before_audit


def test_shifts_in_the_same_batch_cannot_overlap_each_other(shifts: ShiftSetup) -> None:
    times = [
        {"starts_at": iso(soon(1, 10)), "ends_at": iso(soon(1, 16))},
        {"starts_at": iso(soon(1, 14)), "ends_at": iso(soon(1, 20))},
    ]
    response = shifts.browser("chef").post(
        "/api/shifts/batch",
        json={
            "action": "create",
            "department_id": str(shifts.ids["kitchen"]),
            "employee_id": str(shifts.ids["ana"]),
            "times": times,
        },
    )
    assert response.status_code == 409
    assert shift_count(shifts) == 0


def test_malformed_batches_are_refused(shifts: ShiftSetup) -> None:
    chef = shifts.browser("chef")
    some_id = shifts.new_shift()["id"]
    kitchen = str(shifts.ids["kitchen"])
    create = {"action": "create", "department_id": kitchen}
    bodies = [
        create | {"times": []},  # nothing to do
        create | {"times": days(101), "confirm_count": 101},  # more than 100 at once
        create | {"times": days(1) * 2},  # the same times twice
        create | {"times": days(1), "shift_ids": [some_id]},  # a field of another action
        {"action": "cancel", "shift_ids": [some_id, some_id]},  # the same shift twice
        {"action": "assign", "shift_ids": [some_id]},  # employee_id left out
        {"action": "delete", "shift_ids": [some_id]},  # no such action
        {"shift_ids": [some_id]},  # no action at all
    ]
    for body in bodies:
        assert chef.post("/api/shifts/batch", json=body).status_code == 422, body
    assert chef.get(f"/api/shifts/{some_id}").json()["status"] == "open"
