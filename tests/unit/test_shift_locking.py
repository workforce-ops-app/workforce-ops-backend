"""The order in which shift changes take their locks (service._lock_for_change).

The locks themselves only work in MySQL (scripts/check_migrations.py tries real races
there). SQLite has no row locks, but the ORDER of the statements is the same on both, and
that order is what prevents deadlocks: a change must read (and so, in MySQL, lock) the
people it touches before it writes anything to the shift. These tests record every SQL
statement a change sends and check that order, and check the refusal when a shift was
reassigned by someone else while a change was on its way.
"""

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, event

from app.modules.org.models import User
from app.modules.schedules import repository, service
from app.modules.schedules.models import Shift
from app.modules.schedules.schemas import ShiftUpdate
from tests.shift_data import ShiftSetup, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it


@contextmanager
def recorded(engine: Engine, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """What happens while the block runs, in order: "lock <id>" each time a person's row is
    locked (repository.person with lock=True), and "write" for each statement that writes
    to the shifts table. In MySQL, the lock is a SELECT ... FOR UPDATE; SQLite leaves out
    the FOR UPDATE, so the lock calls are recorded where they are made instead."""
    happened: list[str] = []
    real_person = repository.person

    def person(db: Any, user_id: uuid.UUID, *, lock: bool = False) -> Any:
        found = real_person(db, user_id, lock=lock)
        # Recorded once the lock is taken: a change written just before (autoflush, as
        # the locking query starts) must show up as a write BEFORE the lock.
        if lock:
            happened.append(f"lock {user_id}")
        return found

    def keep(_conn: Any, _cursor: Any, sql: str, *_rest: Any) -> None:
        if sql.lstrip().upper().startswith(("UPDATE SHIFTS", "INSERT INTO SHIFTS")):
            happened.append("write")

    monkeypatch.setattr(repository, "person", person)
    event.listen(engine, "before_cursor_execute", keep)
    try:
        yield happened
    finally:
        event.remove(engine, "before_cursor_execute", keep)


@pytest.mark.parametrize("change", ["assign", "new times", "cancel"])
def test_a_change_reads_its_people_before_writing_the_shift(
    shifts: ShiftSetup, change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deadlock rule: the person is locked before the shift is written. In the old order,
    assigning wrote the shift first, and cancelling never locked the person at all."""
    ana, cara = shifts.ids["ana"], shifts.ids["cara"]
    created = shifts.new_shift(employee_id=ana)
    shift_id = uuid.UUID(created["id"])

    actions: dict[str, tuple[Callable[..., object], uuid.UUID]] = {
        # Reassigning from Ana to Cara: Cara is the new person.
        "assign": (lambda db, chef: service.assign_shift(db, chef, shift_id, cara), cara),
        # Moving Ana's shift by an hour: Ana is the person checked for overlaps.
        "new times": (
            lambda db, chef: service.update_shift(
                db,
                chef,
                shift_id,
                ShiftUpdate(starts_at=soon(hour=15), ends_at=soon(hour=15) + timedelta(hours=6)),
            ),
            ana,
        ),
        "cancel": (lambda db, chef: service.cancel_shift(db, chef, shift_id), ana),
    }
    run, person_id = actions[change]

    with shifts.db() as db:
        chef = db.get(User, shifts.ids["chef"])
        assert chef is not None
        with recorded(shifts.engine, monkeypatch) as happened:
            run(db, chef)

    # The person's lock comes before the first write to the shift.
    assert "write" in happened, happened
    assert f"lock {person_id}" in happened[: happened.index("write")], happened


def test_a_shift_reassigned_meanwhile_is_refused_not_changed(shifts: ShiftSetup) -> None:
    """A change whose first read of the shift is out of date (someone reassigned it
    meanwhile) must not change it without the new person's lock: it answers 409."""
    created = shifts.new_shift(employee_id=shifts.ids["ana"])
    shift_id = uuid.UUID(created["id"])

    with shifts.db() as db:
        chef = db.get(User, shifts.ids["chef"])
        assert chef is not None
        # This request reads the shift first: it belongs to Ana. The copy is kept in a
        # variable, as an endpoint keeps it: the session only remembers objects that are
        # still in use, and a forgotten copy would simply be read again, fresh.
        stale = repository.shift(db, shift_id)
        assert stale is not None and stale.employee_id == shifts.ids["ana"]
        # Meanwhile another request gives it to Cara.
        response = shifts.browser("chef").post(
            f"/api/shifts/{shift_id}/assign", json={"employee_id": str(shifts.ids["cara"])}
        )
        assert response.status_code == 200, response.text
        # Now this request tries to cancel it, still believing it is Ana's.
        with pytest.raises(service.Conflict):
            service.cancel_shift(db, chef, shift_id)

    # The attacker's view: nothing was changed by the refused request.
    with shifts.db() as db:
        saved = db.get(Shift, shift_id)
        assert saved is not None
        assert saved.status == "scheduled"
        assert saved.employee_id == shifts.ids["cara"]
