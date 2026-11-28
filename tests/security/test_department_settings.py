"""A department's own send-up minimum (docs/features/coverage.md, slice CV3; threats E3,
T2, I1/T3), through the real app.

Each test is someone changing the value who should not, a value weaker than the
company's, or managers confirming and refusing, and checks what is really stored, what
asking with offers then uses, and the audit log.

People (tests/people_data.py): chef manages Kitchen; lead manages the Weekend Crew (a team,
not the department); admin is an Administrator (company); ana is an Employee of Kitchen.
Company B has b_chef. For two managers, cara gets the Manager role for Kitchen too.
"""

import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import select

from app.audit import Actor
from app.authz.models import Role
from app.authz.roles import assign_role
from app.modules.time_off.models import TimeOffRequest
from app.settings.models import DepartmentSetting
from app.settings.service import change_setting, department_value
from app.tenancy.context import set_company
from tests.people_data import actions, people
from tests.shift_data import ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

CHICAGO = ZoneInfo("America/Chicago")
NAME = "time_off.offers_close_days"


def url(setup: ShiftSetup, dept: str = "kitchen") -> str:
    return f"/api/departments/{setup.ids[dept]}/settings"


def put(setup: ShiftSetup, who: str, value: object, dept: str = "kitchen"):
    return setup.browser(who).put(f"{url(setup, dept)}/offers_close_days", json={"value": value})


def in_force(setup: ShiftSetup, dept: str = "kitchen") -> int:
    with setup.db() as db:
        return department_value(db, NAME, setup.ids[dept])


def stored(setup: ShiftSetup) -> list[int]:
    with setup.db() as db:
        return [row.value for row in db.scalars(select(DepartmentSetting))]


def second_manager(setup: ShiftSetup) -> None:
    """cara also manages Kitchen (the Manager role for the department)."""
    with setup.db() as db:
        role = db.scalars(select(Role).where(Role.built_in == "manager")).one()
        assign_role(
            db,
            Actor.system(),
            user_id=setup.ids["cara"],
            role=role,
            scope_type="department",
            scope_id=setup.ids["kitchen"],
        )
        db.commit()


def decide(setup: ShiftSetup, who: str, approval_id: str, decision: str) -> int:
    response = setup.browser(who).post(f"/api/approval-requests/{approval_id}/{decision}")
    return response.status_code


# --- One manager: at once --------------------------------------------------------------


def test_the_only_manager_changes_it_at_once(people: ShiftSetup) -> None:
    response = put(people, "chef", 3)
    assert response.status_code == 200, response.json()
    assert response.json() == {"value": 3, "approval_request_id": None}
    assert in_force(people) == 3
    assert actions(people, "settings.department_changed") == ["settings.department_changed"]
    shown = people.browser("chef").get(url(people)).json()["items"]
    assert [
        (s["setting"], s["company_value"], s["department_value"], s["value"]) for s in shown
    ] == [(NAME, 1, 3, 3)]


def test_asking_with_offers_uses_the_department_value(people: ShiftSetup) -> None:
    assert put(people, "chef", 5).status_code == 200
    day = (datetime.now(CHICAGO).date() + timedelta(days=4)).isoformat()
    body = {"first_day": day, "last_day": day, "offer_coverage": True}
    # Four days ahead is too late with five days' notice in Kitchen (ana lives there).
    assert people.browser("ana").post("/api/time-off-requests", json=body).status_code == 409
    # dana lives in Front, which kept the company's one day.
    assert people.browser("dana").post("/api/time-off-requests", json=body).status_code == 201
    with people.db() as db:
        assert len(list(db.scalars(select(TimeOffRequest)))) == 1


# --- Who may change it (threat E3) ------------------------------------------------------


def test_people_who_do_not_manage_the_department_get_403(people: ShiftSetup) -> None:
    # An employee, and a team manager whose team is in Kitchen (not the department's).
    for who in ("ana", "lead"):
        assert put(people, who, 3).status_code == 403
        assert people.browser(who).get(url(people)).status_code == 403
    # chef manages Kitchen, not Front.
    assert put(people, "chef", 3, dept="front").status_code == 403
    assert stored(people) == []


def test_company_wide_reviewers_may_change_any_department(people: ShiftSetup) -> None:
    # admin holds time_off.review for the whole company; Front has no manager to ask.
    response = put(people, "admin", 4, dept="front")
    assert response.status_code == 200
    assert in_force(people, "front") == 4


def test_another_company_gets_404(people: ShiftSetup) -> None:
    assert put(people, "b_chef", 3).status_code == 404
    assert people.browser("b_chef").get(url(people)).status_code == 404
    assert stored(people) == []


def test_only_a_per_department_setting_can_be_set(people: ShiftSetup) -> None:
    response = people.browser("chef").put(f"{url(people)}/required_approvals", json={"value": 2})
    assert response.status_code == 404


# --- Never weaker than the company --------------------------------------------------------


def test_a_value_below_the_company_or_past_the_limit_is_refused(people: ShiftSetup) -> None:
    with people.db() as db:
        change_setting(db, NAME, 4, actor=Actor.system())
        db.commit()
    assert put(people, "chef", 3).status_code == 422  # below the company's 4
    assert put(people, "chef", 15).status_code == 422  # past the platform's 14
    assert put(people, "chef", "5").status_code == 422  # not a whole number
    assert stored(people) == []
    assert put(people, "chef", 4).status_code == 200


def test_the_company_raising_its_own_value_is_never_undercut(people: ShiftSetup) -> None:
    assert put(people, "chef", 3).status_code == 200
    with people.db() as db:
        change_setting(db, NAME, 6, actor=Actor.system())
        db.commit()
    assert in_force(people) == 6  # the stricter of the two


def test_a_body_cannot_name_another_department(people: ShiftSetup) -> None:
    # Threat T2: only the value; the department comes from the path and the rules.
    response = people.browser("chef").put(
        f"{url(people)}/offers_close_days",
        json={"value": 3, "department_id": str(people.ids["front"])},
    )
    assert response.status_code == 422


# --- Several managers: everyone else confirms ---------------------------------------------


def test_with_two_managers_one_alone_cannot_change_it(people: ShiftSetup) -> None:
    second_manager(people)
    response = put(people, "chef", 3)
    assert response.status_code == 202
    approval = response.json()["approval_request_id"]
    assert approval and response.json()["value"] is None
    assert in_force(people) == 1  # nothing yet
    shown = people.browser("chef").get(url(people)).json()["items"][0]
    assert shown["pending"]["value"] == 3
    assert len(shown["pending"]["waiting_for"]) == 1
    # chef cannot confirm his own change, and a second change waits its turn.
    assert decide(people, "chef", approval, "approve") == 403
    assert put(people, "cara", 4).status_code == 409
    # cara confirms: it takes effect.
    assert decide(people, "cara", approval, "approve") == 200
    assert in_force(people) == 3
    assert actions(people, "settings.department_changed") == ["settings.department_changed"]


def test_one_denial_stops_it(people: ShiftSetup) -> None:
    second_manager(people)
    approval = put(people, "chef", 3).json()["approval_request_id"]
    assert decide(people, "cara", approval, "deny") == 200
    assert in_force(people) == 1
    assert stored(people) == []
    # Someone who is not one of the managers may not confirm: the request is not theirs
    # to see (404, the approval endpoints' rule), nor another company's.
    approval = put(people, "chef", 3).json()["approval_request_id"]
    assert decide(people, "ana", approval, "approve") == 404
    assert decide(people, "b_chef", approval, "approve") == 404
    assert in_force(people) == 1


def test_the_department_managers_are_read_at_each_decision(people: ShiftSetup) -> None:
    # A manager added after the request was opened must confirm too.
    second_manager(people)
    approval = put(people, "chef", 3).json()["approval_request_id"]
    with people.db() as db:
        set_company(db, people.company_a)
        role = db.scalars(select(Role).where(Role.built_in == "manager")).one()
        assign_role(
            db,
            Actor.system(),
            user_id=people.ids["ana"],
            role=role,
            scope_type="department",
            scope_id=people.ids["kitchen"],
        )
        db.commit()
    assert decide(people, "cara", approval, "approve") == 200
    assert in_force(people) == 1  # still waiting for ana
    assert decide(people, "ana", approval, "approve") == 200
    assert in_force(people) == 3


def test_the_stored_department_is_the_paths(people: ShiftSetup) -> None:
    assert put(people, "chef", 3).status_code == 200
    with people.db() as db:
        rows = list(db.scalars(select(DepartmentSetting)))
        assert [row.department_id for row in rows] == [people.ids["kitchen"]]
        assert all(isinstance(row.department_id, uuid.UUID) for row in rows)
