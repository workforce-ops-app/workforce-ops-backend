"""Adding and ending reporting lines through the API (authorization.md; threats E1, E4;
rules AZ2, AZ6, AZ11, AZ12).

Lines decide whom a person permission may act on, so each test is someone trying to put
themselves or a friend above people they should not reach, and checks the lines as stored.

People and lines (tests/people_data.py):
    owner > admin > chef > {ana, cara, newbie, gone, lead > ben}; dana has no manager.
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.authz.models import ReportingLine
from tests.people_data import actions, people
from tests.shift_data import PASSWORD, ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/reporting-lines"


def reenter(client: TestClient) -> None:
    response = client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    assert response.status_code == 204, response.text


def current_lines(setup: ShiftSetup) -> set[tuple[uuid.UUID, uuid.UUID]]:
    """(manager, employee) for every current line of company A, as stored."""
    with setup.db() as db:
        rows = db.scalars(select(ReportingLine).where(ReportingLine.ended_at.is_(None)))
        return {(row.manager_id, row.employee_id) for row in rows}


def add(client: TestClient, setup: ShiftSetup, manager: str, employee: str) -> int:
    body = {"manager_id": str(setup.ids[manager]), "employee_id": str(setup.ids[employee])}
    return client.post(URL, json=body).status_code


def line_id(setup: ShiftSetup, manager: str, employee: str) -> str:
    listed = setup.browser("owner").get(URL, params={"user_id": str(setup.ids[employee])})
    [found] = [
        item for item in listed.json()["items"] if item["manager_id"] == str(setup.ids[manager])
    ]
    return found["id"]


# --- AZ2: nobody changes a line they are part of ---------------------------------------


def test_nobody_adds_or_ends_a_line_they_are_part_of(people: ShiftSetup) -> None:
    before = current_lines(people)
    admin = people.browser("admin")
    reenter(admin)
    assert add(admin, people, "admin", "ana") == 403  # placing yourself above someone
    assert add(admin, people, "ana", "admin") == 403
    assert admin.post(f"{URL}/{line_id(people, 'admin', 'chef')}/end").status_code == 403
    assert admin.post(f"{URL}/{line_id(people, 'owner', 'admin')}/end").status_code == 403
    assert current_lines(people) == before


# --- AZ6: only someone above both people -----------------------------------------------


def test_lines_need_a_place_above_both_people(people: ShiftSetup) -> None:
    before = current_lines(people)
    admin = people.browser("admin")
    reenter(admin)
    assert add(admin, people, "chef", "dana") == 403  # dana is not below admin
    assert add(admin, people, "dana", "ana") == 403
    chef = people.browser("chef")  # Manager: no reporting_line.manage
    reenter(chef)
    assert add(chef, people, "lead", "ana") == 403
    assert current_lines(people) == before
    # The owner is above everyone.
    owner = people.browser("owner")
    refused = owner.post(
        URL, json={"manager_id": str(people.ids["chef"]), "employee_id": str(people.ids["dana"])}
    )
    assert refused.status_code == 403 and refused.json()["type"] == "reauth-required"
    reenter(owner)
    assert add(owner, people, "chef", "dana") == 201
    assert (people.ids["chef"], people.ids["dana"]) in current_lines(people)
    assert actions(people, "reporting_line.added")[-1] == "reporting_line.added"


def test_loops_duplicates_and_self_reporting_are_refused(people: ShiftSetup) -> None:
    before = current_lines(people)
    owner = people.browser("owner")
    reenter(owner)
    assert add(owner, people, "ben", "chef") == 409  # chef is above ben: a loop
    assert add(owner, people, "chef", "ana") == 409  # already current
    assert add(owner, people, "ana", "ana") in {403, 409}
    assert add(owner, people, "chef", "gone") == 409  # deactivated
    assert current_lines(people) == before


def test_another_companys_people_are_unknown(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    reenter(owner)
    assert add(owner, people, "chef", "b_ana") == 422
    assert add(owner, people, "b_chef", "ana") == 422
    assert owner.get(URL, params={"user_id": str(people.ids["b_ana"])}).status_code == 404


# --- Ending ----------------------------------------------------------------------------


def test_ending_a_line_takes_away_the_place_above(people: ShiftSetup) -> None:
    admin = people.browser("admin")
    ended_id = line_id(people, "chef", "ana")
    refused = admin.post(f"{URL}/{ended_id}/end")
    assert refused.status_code == 403 and refused.json()["type"] == "reauth-required"
    reenter(admin)
    ended = admin.post(f"{URL}/{ended_id}/end")
    assert ended.status_code == 200 and ended.json()["ended_at"] is not None
    assert (people.ids["chef"], people.ids["ana"]) not in current_lines(people)
    # ana had no other manager: admin is no longer above her, so admin cannot even try
    # again; the owner, above everyone, is told it has already ended.
    assert admin.post(f"{URL}/{ended_id}/end").status_code == 403
    owner = people.browser("owner")
    reenter(owner)
    assert owner.post(f"{URL}/{ended_id}/end").status_code == 409
    assert actions(people, "reporting_line.ended") == ["reporting_line.ended"]
    # Kept as history.
    history = people.browser("owner").get(
        URL, params={"user_id": str(people.ids["ana"]), "include_ended": "true"}
    )
    assert ended_id in {item["id"] for item in history.json()["items"]}


# --- Seeing lines ----------------------------------------------------------------------


def test_people_see_their_own_lines_and_those_of_people_in_scope(people: ShiftSetup) -> None:
    ana, chef = people.browser("ana"), people.browser("chef")
    assert ana.get(URL, params={"user_id": str(people.ids["ana"])}).status_code == 200
    assert ana.get(URL, params={"user_id": str(people.ids["chef"])}).status_code == 403
    assert chef.get(URL, params={"user_id": str(people.ids["ana"])}).status_code == 200
