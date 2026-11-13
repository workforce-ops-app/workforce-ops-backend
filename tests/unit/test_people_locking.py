"""Account changes that meet another request on the way (app/modules/org/people.py).

Row locks only work in MySQL (scripts/check_migrations.py tries real races there). What
can be shown on SQLite is what each request does after its lock: it reads the person
fresh and checks again, so a change committed by someone else while it waited is seen.
Each test makes that other change happen at exactly that moment, by running it when the
request asks for the locked row.
"""

import uuid
from collections.abc import Callable

import pytest

from app.audit import Actor
from app.authz.check import Forbidden
from app.authz.models import Role, RolePermission
from app.authz.roles import assign_role
from app.db.base import utcnow
from app.modules.org import people as people_service
from app.modules.org import repository, service
from app.modules.org.models import User
from app.modules.org.schemas import UserUpdate
from tests.people_data import people, person
from tests.shift_data import ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them


def _meanwhile(monkeypatch: pytest.MonkeyPatch, change: Callable[[], None]) -> None:
    """Run `change` (another request, committed) just before the next locked read of a
    person, as if it had committed while this request waited for the lock."""
    real = repository.person
    done = False

    def person_then_change(db, user_id: uuid.UUID, *, lock: bool = False):  # type: ignore[no-untyped-def]
        nonlocal done
        if lock and not done:
            done = True
            change()
        return real(db, user_id, lock=lock)

    monkeypatch.setattr(repository, "person", person_then_change)


def test_a_person_moved_out_of_scope_meanwhile_is_not_changed(
    people: ShiftSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    # chef gets user.manage for Kitchen only, and is above ana (she reports to chef).
    with people.db() as db:
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

    def owner_moves_ana_to_front() -> None:
        with people.db() as other:
            ana = other.get(User, people.ids["ana"])
            assert ana is not None
            ana.department_id = people.ids["front"]
            other.commit()

    _meanwhile(monkeypatch, owner_moves_ana_to_front)
    with people.db() as db:
        chef = db.get(User, people.ids["chef"])
        assert chef is not None
        # The first check passes (she was in Kitchen); the one after the lock sees Front.
        with pytest.raises(Forbidden):
            people_service.change_person(
                db, chef, people.ids["ana"], UserUpdate(display_name="Renamed")
            )
    assert person(people, "ana").display_name == "Ana"


def test_a_person_deactivated_meanwhile_does_not_join_a_team(
    people: ShiftSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    def admin_deactivates_ana() -> None:
        with people.db() as other:
            ana = other.get(User, people.ids["ana"])
            assert ana is not None
            ana.deactivated_at = utcnow()
            other.commit()

    with people.db() as db:
        owner = db.get(User, people.ids["owner"])
        assert owner is not None
        db.get(User, people.ids["ana"])  # this request already holds an active copy of her
        _meanwhile(monkeypatch, admin_deactivates_ana)
        with pytest.raises(service.Conflict):
            service.add_member(db, owner, people.ids["crew"], people.ids["ana"])


def test_deactivating_twice_at_once_is_refused_the_second_time(
    people: ShiftSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two administrators press "deactivate" together: the one that waited sees the other's
    result (already deactivated, 409) instead of deactivating and auditing twice."""

    def other_admin_deactivates_cara() -> None:
        with people.db() as other:
            admin = other.get(User, people.ids["admin"])
            assert admin is not None
            people_service.deactivate(other, admin, people.ids["cara"])

    with people.db() as db:
        admin = db.get(User, people.ids["admin"])
        assert admin is not None
        _meanwhile(monkeypatch, other_admin_deactivates_cara)
        with pytest.raises(service.Conflict):
            people_service.deactivate(db, admin, people.ids["cara"])
