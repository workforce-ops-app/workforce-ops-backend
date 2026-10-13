"""Several shifts at once against the threats on the schedules page (D3, I1, I2, E8).

A batch is the easiest way to do a lot of damage with one request, so each test checks
both the answer and that nothing at all changed: no shift and no audit entry.
"""

from datetime import timedelta

from sqlalchemy import func, select

from app.audit.models import AuditEvent
from app.modules.schedules.models import Shift
from tests.shift_data import ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


def planned(setup: ShiftSetup, count: int, who: str = "chef", **fields: object) -> list[str]:
    """`count` shifts on the next days, created one at a time; their IDs."""
    return [
        setup.new_shift(
            who,
            starts_at=iso(soon(day)),
            ends_at=iso(soon(day) + timedelta(hours=6)),
            **fields,
        )["id"]
        for day in range(1, count + 1)
    ]


def snapshot(setup: ShiftSetup) -> tuple[list[tuple[str, str | None]], int]:
    """Every shift's status and person, and the number of audit entries, to compare."""
    with setup.db() as db:
        rows = [
            (s.status, str(s.employee_id) if s.employee_id else None)
            for s in db.scalars(select(Shift).order_by(Shift.starts_at, Shift.id))
        ]
        entries = db.scalar(select(func.count(AuditEvent.id))) or 0
    return rows, entries


# --- D3: destroying data from inside -----------------------------------------------------


def test_cancelling_ten_shifts_without_the_right_count_changes_nothing(shifts: ShiftSetup) -> None:
    ids = planned(shifts, 10)
    before = snapshot(shifts)
    chef = shifts.browser("chef")

    for extra in ({}, {"confirm_count": None}, {"confirm_count": 9}, {"confirm_count": 11}):
        body = {"action": "cancel", "shift_ids": ids} | extra
        assert chef.post("/api/shifts/batch", json=body).status_code == 409, extra
        assert snapshot(shifts) == before, extra

    # The same request with the count repeated goes through.
    body = {"action": "cancel", "shift_ids": ids, "confirm_count": 10}
    assert chef.post("/api/shifts/batch", json=body).status_code == 200


def test_reassigning_ten_shifts_without_the_right_count_changes_nothing(
    shifts: ShiftSetup,
) -> None:
    ids = planned(shifts, 10, employee_id=shifts.ids["ana"])
    before = snapshot(shifts)
    body = {"action": "assign", "shift_ids": ids, "employee_id": None}
    assert shifts.browser("chef").post("/api/shifts/batch", json=body).status_code == 409
    assert snapshot(shifts) == before


# --- I1: other companies ------------------------------------------------------------------


def test_one_shift_of_another_company_stops_the_whole_batch(shifts: ShiftSetup) -> None:
    ours = planned(shifts, 2, "owner")
    theirs = shifts.new_shift("b_chef", department_id=shifts.ids["b_kitchen"])["id"]
    before = snapshot(shifts)

    body = {"action": "cancel", "shift_ids": [*ours, theirs]}
    # Their shift does not exist for company A: the same 404 as an unknown ID.
    assert shifts.browser("owner").post("/api/shifts/batch", json=body).status_code == 404
    assert snapshot(shifts) == before
    with shifts.db(shifts.company_b) as db:
        assert db.scalars(select(Shift.status)).one() == "open"


def test_a_batch_cannot_create_in_another_companys_department(shifts: ShiftSetup) -> None:
    body = {
        "action": "create",
        "department_id": str(shifts.ids["b_kitchen"]),
        "times": [{"starts_at": iso(soon()), "ends_at": iso(soon() + timedelta(hours=4))}],
    }
    assert shifts.browser("owner").post("/api/shifts/batch", json=body).status_code == 422
    with shifts.db(shifts.company_b) as db:
        assert db.scalar(select(func.count(Shift.id))) == 0


# --- I2: outside your scope -------------------------------------------------------------


def test_one_shift_outside_the_managers_department_stops_the_whole_batch(
    shifts: ShiftSetup,
) -> None:
    kitchen = planned(shifts, 2)
    front = shifts.new_shift(
        "owner",
        department_id=shifts.ids["front"],
        starts_at=iso(soon(5)),
        ends_at=iso(soon(5) + timedelta(hours=4)),
    )["id"]
    before = snapshot(shifts)

    body = {"action": "cancel", "shift_ids": [*kitchen, front]}
    assert shifts.browser("chef").post("/api/shifts/batch", json=body).status_code == 403
    assert snapshot(shifts) == before


def test_a_batch_cannot_give_shifts_to_someone_who_cannot_work_them(shifts: ShiftSetup) -> None:
    ids = planned(shifts, 2)
    before = snapshot(shifts)
    # Dana's home is Front and she is on no Kitchen team.
    body = {"action": "assign", "shift_ids": ids, "employee_id": str(shifts.ids["dana"])}
    assert shifts.browser("chef").post("/api/shifts/batch", json=body).status_code == 422
    assert snapshot(shifts) == before


# --- E8: employees calling the API directly ---------------------------------------------


def test_an_employee_cannot_use_a_batch_even_with_the_right_count(shifts: ShiftSetup) -> None:
    ids = planned(shifts, 10, employee_id=shifts.ids["ana"])
    ana = shifts.browser("ana")  # signed in first: signing in writes its own audit entry
    before = snapshot(shifts)
    bodies = [
        {"action": "cancel", "shift_ids": ids, "confirm_count": 10},
        {"action": "assign", "shift_ids": ids[:1], "employee_id": None},
        {
            "action": "create",
            "department_id": str(shifts.ids["kitchen"]),
            "times": [{"starts_at": iso(soon(20)), "ends_at": iso(soon(20) + timedelta(hours=2))}],
        },
    ]
    for body in bodies:
        # 403 before any count check: she learns nothing about how many shifts there are.
        assert ana.post("/api/shifts/batch", json=body).status_code == 403, body["action"]
    assert snapshot(shifts) == before
