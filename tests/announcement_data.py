"""Shared setup for the announcement tests: the shift tests' two companies, plus one more
team and two more managers in company A, so every kind of assignment has a counterpart in
the other department.

Company A ("Northwind"), as in tests/shift_data.py, plus:
    team Patio in Front (the Weekend Crew is in Kitchen)
    manny   Manager of Front        (home Front)
    pat     Manager of Patio        (home Front, on the Patio team)
    dana    (already there) is put on the Patio team

So the managers are: owner (company), chef (Kitchen), manny (Front), lead (Weekend Crew,
in Kitchen), and pat (Patio, in Front).
"""

from collections.abc import Iterator

import pytest
from sqlalchemy import select

from app.audit import Actor
from app.auth.passwords import hash_password
from app.authz.models import Role
from app.authz.roles import assign_role
from app.modules.org.models import Team, TeamMember, User
from tests.shift_data import PASSWORD, ShiftSetup, shifts

__all__ = ["announcements", "shifts"]


@pytest.fixture
def announcements(shifts: ShiftSetup) -> Iterator[ShiftSetup]:
    with shifts.db() as db:
        # The Patio team, in Front.
        patio = Team(name="Patio", department_id=shifts.ids["front"])
        db.add(patio)
        db.flush()
        shifts.ids["patio"] = patio.id
        manager = db.scalars(select(Role).where(Role.built_in == "manager")).one()
        hashed = hash_password(PASSWORD)
        # Two more managers: one for the Front department, one for the Patio team.
        for name, scope_type, scope in (("manny", "department", "front"), ("pat", "team", "patio")):
            person = User(
                email=f"{name}@northwind.example",
                display_name=name.title(),
                department_id=shifts.ids["front"],
                password_hash=hashed,
            )
            db.add(person)
            db.flush()
            shifts.ids[name] = person.id
            assign_role(
                db,
                Actor.system(),
                user_id=person.id,
                role=manager,
                scope_type=scope_type,
                scope_id=shifts.ids[scope],
            )
        db.add_all(
            [
                TeamMember(team_id=patio.id, user_id=shifts.ids["pat"]),
                TeamMember(team_id=patio.id, user_id=shifts.ids["dana"]),
            ]
        )
        db.commit()
    yield shifts


def post(setup: ShiftSetup, who: str, audience: str, **fields: object) -> dict:
    """Post an announcement through the API and return the answer (it must succeed).

    audience is "company", or the key of a department or team in setup.ids ("kitchen",
    "crew", "b_kitchen", ...).
    """
    body = audience_body(setup, audience) | {"title": "Heads up", "body": "Inventory on Friday."}
    response = setup.browser(who).post("/api/announcements", json=body | fields)
    assert response.status_code == 201, response.text
    return response.json()


def audience_body(setup: ShiftSetup, audience: str) -> dict:
    """The audience part of a POST body."""
    if audience == "company":
        return {"audience_type": "company"}
    key = audience.removeprefix("b_")
    if key in ("kitchen", "front"):
        return {"audience_type": "department", "department_id": str(setup.ids[audience])}
    return {"audience_type": "team", "team_id": str(setup.ids[audience])}
