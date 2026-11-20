"""Your departments, with what you may do in each (GET /api/departments/mine; found in
review: a Kitchen manager saw every department in the picker, and the manager buttons
followed her into departments she does not manage).

Each test checks what a person is offered: only the departments where they hold a role,
the permissions they hold there and no more, nothing from another company, and nothing
from an archived department.

People (tests/people_data.py): chef manages Kitchen; lead manages the Weekend Crew (a team
in Kitchen) and lives in Front; ana is an Employee of Kitchen; admin is an Administrator
(company); owner holds everything. Company B has b_chef (Manager of its Kitchen).
"""

from sqlalchemy import update

from app.modules.org.models import Department
from tests.people_data import people
from tests.shift_data import ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/departments/mine"


def mine(setup: ShiftSetup, who: str) -> dict[str, set[str]]:
    """The person's departments, by name, with their permissions there."""
    response = setup.browser(who).get(URL)
    assert response.status_code == 200, response.text
    return {item["name"]: set(item["permissions"]) for item in response.json()["items"]}


def test_a_department_manager_gets_only_their_department(people: ShiftSetup) -> None:
    found = mine(people, "chef")
    assert set(found) == {"Kitchen"}
    assert "schedule.edit" in found["Kitchen"]


def test_an_employee_gets_their_department_without_manager_permissions(
    people: ShiftSetup,
) -> None:
    found = mine(people, "ana")
    assert set(found) == {"Kitchen"}
    # Seeing the schedule, never changing it.
    assert "schedule.edit" not in found["Kitchen"]
    assert "time_off.review" not in found["Kitchen"]


def test_a_team_manager_gets_the_team_department_and_their_home(people: ShiftSetup) -> None:
    # lead manages the Weekend Crew, a team in Kitchen, and lives in Front.
    found = mine(people, "lead")
    assert "Kitchen" in found
    assert "schedule.edit" in found["Kitchen"]  # for the crew's shifts (the API checks each)
    # Wherever else they appear, the manager's tools come only from the team role.
    assert all("schedule.edit" not in codes for name, codes in found.items() if name != "Kitchen")


def test_company_wide_roles_get_every_department(people: ShiftSetup) -> None:
    assert set(mine(people, "admin")) == {"Kitchen", "Front"}
    owner = mine(people, "owner")
    assert set(owner) == {"Kitchen", "Front"}
    # The Owner holds every permission in each.
    assert "schedule.edit" in owner["Front"] and "org.manage" in owner["Front"]


def test_another_companys_departments_never_appear(people: ShiftSetup) -> None:
    # Both companies have a "Kitchen": company B's manager gets only theirs.
    response = people.browser("b_chef").get(URL)
    assert response.status_code == 200
    ids = {item["id"] for item in response.json()["items"]}
    assert str(people.ids["kitchen"]) not in ids
    assert len(ids) == 1
    # And company A's people never get company B's.
    for who in ("owner", "chef", "ana"):
        items = people.browser(who).get(URL).json()["items"]
        assert all(item["id"] != str(people.ids["b_kitchen"]) for item in items)


def test_an_archived_department_is_left_out(people: ShiftSetup) -> None:
    with people.db() as db:
        db.execute(
            update(Department)
            .where(Department.id == people.ids["kitchen"])
            .values(archived_at=Department.created_at)
        )
        db.commit()
    assert mine(people, "chef") == {}
    assert "Kitchen" not in mine(people, "owner")


def test_signed_out_gets_nothing(people: ShiftSetup) -> None:
    from fastapi.testclient import TestClient

    client = TestClient(people.app, base_url="https://testserver")  # type: ignore[arg-type]
    assert client.get(URL).status_code == 401
