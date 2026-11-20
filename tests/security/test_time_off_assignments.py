"""Nobody is put on a shift during their approved time off (docs/features/schedules.md,
states and rules; time-off.md), through the real app.

Approving time off opens the person's shifts on those days. Each test is a manager trying
to put them back on a shift there anyway, by every way a person gets a shift: creating
one for them, assigning an open one, moving a shift's times into the days off, and a
batch. Each checks the answer (409 with the reason) and that nothing was saved. Requests
that are not approved (waiting, declined, cancelled) block nothing.

People (tests/people_data.py): chef manages Kitchen and is ana's only manager, so chef
approves ana's requests alone. Northwind runs on America/Chicago.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.modules.schedules.models import Shift
from tests.people_data import people
from tests.shift_data import ShiftSetup, iso, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/time-off-requests"
CHICAGO = ZoneInfo("America/Chicago")
UTC = ZoneInfo("UTC")
ON_TIME_OFF = "This person has approved time off then."


def at(offset: int, hour: int) -> datetime:
    """`hour` o'clock in Northwind's zone, `offset` days from today."""
    day = datetime.now(CHICAGO).date() + timedelta(days=offset)
    return datetime.combine(day, datetime.min.time(), CHICAGO).replace(hour=hour)


def times(starts: datetime, hours: int) -> dict[str, str]:
    """A shift's start and end as the API takes them (UTC moments)."""
    return {
        "starts_at": iso(starts.astimezone(UTC)),
        "ends_at": iso((starts + timedelta(hours=hours)).astimezone(UTC)),
    }


def ask(setup: ShiftSetup, first: int, last: int) -> str:
    """ana asks for days first..last from today; the new request's ID."""
    response = setup.browser("ana").post(
        URL,
        json={
            "first_day": (datetime.now(CHICAGO).date() + timedelta(days=first)).isoformat(),
            "last_day": (datetime.now(CHICAGO).date() + timedelta(days=last)).isoformat(),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def approved_days_off(setup: ShiftSetup, first: int, last: int) -> str:
    """ana's days first..last, asked for and approved by chef."""
    request_id = ask(setup, first, last)
    response = setup.browser("chef").post(f"{URL}/{request_id}/approve")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "approved"
    return request_id


def refused(response: Any) -> None:
    """The answer is 409 with the time-off reason, the words the screens show."""
    assert response.status_code == 409, response.text
    assert response.json()["detail"] == ON_TIME_OFF


def anas_shifts(setup: ShiftSetup) -> int:
    with setup.db() as db:
        return len(db.scalars(select(Shift.id).where(Shift.employee_id == setup.ids["ana"])).all())


def chef(setup: ShiftSetup) -> TestClient:
    return setup.browser("chef")


# --- Every way of giving ana a shift is refused on her days off ------------------------


def test_creating_a_shift_for_someone_on_time_off_is_refused(people: ShiftSetup) -> None:
    approved_days_off(people, 3, 4)
    before = anas_shifts(people)
    body = {"department_id": str(people.ids["kitchen"]), "employee_id": str(people.ids["ana"])}
    refused(chef(people).post("/api/shifts", json=body | times(at(3, 9), 6)))
    # The last day counts until midnight, and so does an overnight shift ending in it.
    refused(chef(people).post("/api/shifts", json=body | times(at(4, 18), 5)))
    refused(chef(people).post("/api/shifts", json=body | times(at(2, 22), 4)))
    assert anas_shifts(people) == before


def test_assigning_an_open_shift_on_time_off_is_refused(people: ShiftSetup) -> None:
    open_shift = people.new_shift(**times(at(3, 9), 6))["id"]
    approved_days_off(people, 3, 3)
    refused(
        chef(people).post(
            f"/api/shifts/{open_shift}/assign", json={"employee_id": str(people.ids["ana"])}
        )
    )
    with people.db() as db:
        found = db.get(Shift, uuid.UUID(open_shift))
        assert found is not None and found.employee_id is None and found.status == "open"


def test_the_shift_the_approval_opened_cannot_be_given_back(people: ShiftSetup) -> None:
    # The case found in review: the approval opens her shift, then the manager reassigns it.
    hers = people.new_shift(employee_id=people.ids["ana"], **times(at(3, 9), 6))["id"]
    approved_days_off(people, 3, 3)
    back = {"employee_id": str(people.ids["ana"])}
    refused(chef(people).post(f"/api/shifts/{hers}/assign", json=back))
    with people.db() as db:
        found = db.get(Shift, uuid.UUID(hers))
        assert found is not None and found.employee_id is None


def test_moving_a_shift_into_time_off_is_refused(people: ShiftSetup) -> None:
    hers = people.new_shift(employee_id=people.ids["ana"], **times(at(6, 9), 6))
    approved_days_off(people, 3, 3)
    refused(chef(people).patch(f"/api/shifts/{hers['id']}", json=times(at(3, 9), 6)))
    with people.db() as db:
        found = db.get(Shift, uuid.UUID(hers["id"]))
        assert found is not None
        assert iso(found.starts_at.replace(tzinfo=UTC)) == hers["starts_at"]  # unchanged
    # Changing only the text of a shift outside her days off is still fine.
    changed = chef(people).patch(f"/api/shifts/{hers['id']}", json={"details": "Prep"})
    assert changed.status_code == 200, changed.text


def test_a_batch_with_one_shift_on_time_off_saves_nothing(people: ShiftSetup) -> None:
    approved_days_off(people, 4, 4)
    before = anas_shifts(people)
    created = chef(people).post(
        "/api/shifts/batch",
        json={
            "action": "create",
            "department_id": str(people.ids["kitchen"]),
            "employee_id": str(people.ids["ana"]),
            "times": [times(at(3, 9), 6), times(at(4, 9), 6), times(at(5, 9), 6)],
        },
    )
    refused(created)
    assert anas_shifts(people) == before

    open_ids = [people.new_shift(**times(at(day, 9), 6))["id"] for day in (3, 4)]
    assigned = chef(people).post(
        "/api/shifts/batch",
        json={"action": "assign", "shift_ids": open_ids, "employee_id": str(people.ids["ana"])},
    )
    refused(assigned)
    assert anas_shifts(people) == before


# --- What does not block ---------------------------------------------------------------


def test_only_approved_time_off_blocks(people: ShiftSetup) -> None:
    waiting = ask(people, 3, 3)
    denied = ask(people, 4, 4)
    assert chef(people).post(f"{URL}/{denied}/deny").status_code == 200
    cancelled = ask(people, 5, 5)
    assert people.browser("ana").post(f"{URL}/{cancelled}/cancel").status_code == 200
    assert waiting  # still waiting for chef

    body = {"department_id": str(people.ids["kitchen"]), "employee_id": str(people.ids["ana"])}
    for day in (3, 4, 5):
        response = chef(people).post("/api/shifts", json=body | times(at(day, 9), 6))
        assert response.status_code == 201, (day, response.text)


def test_the_days_around_time_off_and_coworkers_stay_free(people: ShiftSetup) -> None:
    approved_days_off(people, 3, 3)
    body = {"department_id": str(people.ids["kitchen"]), "employee_id": str(people.ids["ana"])}
    # Ends exactly when her day off begins, and starts exactly when it ends: both fine.
    assert chef(people).post("/api/shifts", json=body | times(at(2, 18), 6)).status_code == 201
    assert chef(people).post("/api/shifts", json=body | times(at(4, 0), 6)).status_code == 201
    # A coworker can still be given that day.
    cara = body | {"employee_id": str(people.ids["cara"])}
    assert chef(people).post("/api/shifts", json=cara | times(at(3, 9), 6)).status_code == 201
