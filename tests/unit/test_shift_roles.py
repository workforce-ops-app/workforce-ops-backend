"""Each person's roles in the shifts API (workforce-ops-backend#159): which roles count,
their order, one lookup per answer, and every answer that shows a person.

The people menu of the department calendar (frontend #83) groups people by these roles.
Who may see them, and that nothing else about a role leaks, is in
tests/security/test_shifts.py.
"""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import Actor
from app.authz.models import Role
from app.authz.roles import assign_role
from app.db.base import utcnow
from app.modules.org.models import Team
from app.modules.schedules import repository
from tests.shift_data import ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


def give_role(
    setup: ShiftSetup, person: str, role_name: str, scope_type: str, scope: str | None
) -> None:
    """Give someone a role in company A, creating the role if the company does not have it
    yet (a role the company added, built_in null)."""
    with setup.db() as db:
        role = db.scalars(select(Role).where(Role.name == role_name)).first()
        if role is None:
            role = Role(name=role_name, built_in=None)
            db.add(role)
            db.flush()
        assign_role(
            db,
            Actor.system(),
            user_id=setup.ids[person],
            role=role,
            scope_type=scope_type,
            scope_id=setup.ids[scope] if scope else None,
        )
        db.commit()


def roles_shown(setup: ShiftSetup, person: str, who: str = "chef") -> list[dict]:
    """The roles a shift for this person shows, as the list answer has them."""
    setup.new_shift(employee_id=setup.ids[person])
    first = soon().date()
    response = setup.browser(who).get(
        "/api/shifts", params={"from": str(first), "to": str(first + timedelta(days=6))}
    )
    assert response.status_code == 200, response.text
    found = [s["employee"] for s in response.json()["items"] if s["employee"]]
    return next(e["roles"] for e in found if e["id"] == str(setup.ids[person]))


def test_roles_come_in_the_menus_order_each_once(shifts: ShiftSetup) -> None:
    # Ana is an Employee of Kitchen. She also becomes a Manager twice (of Kitchen and of the
    # Weekend Crew) and holds two roles the company added.
    give_role(shifts, "ana", "Manager", "department", "kitchen")
    give_role(shifts, "ana", "Manager", "team", "crew")
    give_role(shifts, "ana", "Shift lead", "department", "kitchen")
    give_role(shifts, "ana", "barista", "company", None)

    # Starting roles from the top down, added roles by name (case ignored), Employee last;
    # Manager once, however many scopes she holds it in.
    assert roles_shown(shifts, "ana") == [
        {"name": "Manager", "built_in": "manager"},
        {"name": "barista", "built_in": None},
        {"name": "Shift lead", "built_in": None},
        {"name": "Employee", "built_in": "employee"},
    ]


def test_archived_roles_and_archived_scopes_do_not_count(shifts: ShiftSetup) -> None:
    # Ana gets a role that is then archived, and Manager of the Weekend Crew, which is then
    # archived: neither grants anything any more (app/authz/check.py), so neither shows.
    give_role(shifts, "ana", "Trainer", "department", "kitchen")
    give_role(shifts, "ana", "Manager", "team", "crew")
    with shifts.db() as db:
        db.scalars(select(Role).where(Role.name == "Trainer")).one().archived_at = utcnow()
        db.get_one(Team, shifts.ids["crew"]).archived_at = utcnow()
        db.commit()

    assert roles_shown(shifts, "ana") == [{"name": "Employee", "built_in": "employee"}]


def test_deactivated_people_and_people_without_roles_have_none(shifts: ShiftSetup) -> None:
    with shifts.db() as db:
        found = repository.roles_of(db, [shifts.ids["gone"], shifts.ids["ana"]])
    assert found[shifts.ids["gone"]] == []
    assert found[shifts.ids["ana"]] == [("Employee", "employee")]
    # Nobody to look up: no query, an empty answer.
    with shifts.db() as db:
        assert repository.roles_of(db, []) == {}


def test_the_list_looks_roles_up_once_for_the_whole_page(
    shifts: ShiftSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    for person, day in (("ana", 1), ("cara", 2), ("ana", 3)):
        shifts.new_shift(
            employee_id=shifts.ids[person],
            starts_at=iso(soon(day)),
            ends_at=iso(soon(day) + timedelta(hours=4)),
        )
    shifts.new_shift(starts_at=iso(soon(4)), ends_at=iso(soon(4) + timedelta(hours=4)))

    # Count the lookups, and what each was asked for.
    calls: list[list[uuid.UUID]] = []
    original = repository.roles_of

    def counting(db: Session, user_ids: list[uuid.UUID]) -> repository.RolesByPerson:
        calls.append(sorted(user_ids))
        return original(db, user_ids)

    monkeypatch.setattr(repository, "roles_of", counting)
    first = soon().date()
    response = shifts.browser("chef").get(
        "/api/shifts", params={"from": str(first), "to": str(first + timedelta(days=6))}
    )
    assert response.status_code == 200
    # One lookup, each person once (the open shift has nobody to look up).
    assert calls == [sorted([shifts.ids["ana"], shifts.ids["cara"]])]
    assert all(s["employee"] is None or s["employee"]["roles"] for s in response.json()["items"])


def test_every_answer_with_a_person_shows_their_roles(shifts: ShiftSetup) -> None:
    employee_role = [{"name": "Employee", "built_in": "employee"}]
    created = shifts.new_shift(employee_id=shifts.ids["ana"])
    chef = shifts.browser("chef")

    # One shift, a change, and an assignment.
    one = chef.get(f"/api/shifts/{created['id']}").json()
    assert one["employee"]["roles"] == employee_role
    changed = chef.patch(f"/api/shifts/{created['id']}", json={"notes": "Bring keys"}).json()
    assert changed["employee"]["roles"] == employee_role
    open_one = shifts.new_shift(starts_at=iso(soon(2)), ends_at=iso(soon(2) + timedelta(hours=4)))
    assigned = chef.post(
        f"/api/shifts/{open_one['id']}/assign", json={"employee_id": str(shifts.ids["cara"])}
    ).json()
    assert assigned["employee"]["roles"] == employee_role

    # A batch answer, with everyone's roles from one lookup.
    batch = chef.post(
        "/api/shifts/batch",
        json={
            "action": "create",
            "department_id": str(shifts.ids["kitchen"]),
            "employee_id": str(shifts.ids["ana"]),
            "times": [
                {"starts_at": iso(soon(day)), "ends_at": iso(soon(day) + timedelta(hours=4))}
                for day in (5, 6)
            ],
        },
    )
    assert batch.status_code == 200, batch.text
    assert [s["employee"]["roles"] for s in batch.json()["items"]] == [employee_role] * 2
