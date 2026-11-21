"""Adding and removing owners (authorization.md; threat E6; rules AZ8, AZ9, AZ15).

Owners hold everything, so each test is someone trying to become one, or to push one out,
without every other owner agreeing, and checks who the owners are afterwards.

People and lines (tests/people_data.py):
    owner > admin > chef > {ana, cara, newbie, gone, lead > ben}; dana has no manager.
Only "owner" is an owner at the start.
"""

import uuid

from fastapi.testclient import TestClient

from tests.people_data import actions, people
from tests.shift_data import PASSWORD, ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/owners"


def reenter(client: TestClient) -> TestClient:
    response = client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    assert response.status_code == 204, response.text
    return client


def owners(setup: ShiftSetup) -> set[uuid.UUID]:
    listed = setup.browser("owner").get(URL)
    assert listed.status_code == 200, listed.text
    return {uuid.UUID(item["id"]) for item in listed.json()["items"]}


def ids(setup: ShiftSetup, *names: str) -> set[uuid.UUID]:
    return {setup.ids[name] for name in names}


def propose_add(client: TestClient, setup: ShiftSetup, name: str) -> int:
    return client.post(URL, json={"user_id": str(setup.ids[name])}).status_code


def three_owners(setup: ShiftSetup) -> None:
    """owner, then admin (at once: one owner), then chef (admin agrees)."""
    owner = reenter(setup.browser("owner"))
    assert propose_add(owner, setup, "admin") == 200
    asked = owner.post(URL, json={"user_id": str(setup.ids["chef"])})
    assert asked.status_code == 202, asked.text
    admin = reenter(setup.browser("admin"))
    assert admin.post(f"/api/approval-requests/{asked.json()['id']}/approve").status_code == 200
    assert owners(setup) == ids(setup, "owner", "admin", "chef")


# --- Who may propose -------------------------------------------------------------------


def test_only_owners_propose_owner_changes(people: ShiftSetup) -> None:
    for name in ("admin", "chef", "ana"):
        client = reenter(people.browser(name))
        assert propose_add(client, people, name) == 403
        assert propose_add(client, people, "ana") == 403
        removed = client.post(f"{URL}/{people.ids['owner']}/remove")
        assert removed.status_code == 403
    assert owners(people) == ids(people, "owner")
    assert actions(people, "ownership.") == []


def test_owner_changes_need_the_password_again(people: ShiftSetup) -> None:
    owner = people.browser("owner")
    refused = owner.post(URL, json={"user_id": str(people.ids["admin"])})
    assert refused.status_code == 403 and refused.json()["type"] == "reauth-required"
    assert owners(people) == ids(people, "owner")


# --- AZ15: every owner agrees ----------------------------------------------------------


def test_a_sole_owner_adds_an_owner_alone(people: ShiftSetup) -> None:
    owner = reenter(people.browser("owner"))
    assert propose_add(owner, people, "admin") == 200
    assert owners(people) == ids(people, "owner", "admin")
    assert actions(people, "ownership.") == ["ownership.owner_added"]
    assert propose_add(owner, people, "admin") == 409  # already one
    assert propose_add(owner, people, "gone") == 409  # deactivated
    assert propose_add(owner, people, "b_ana") == 422  # another company's


def test_with_several_owners_every_other_owner_must_agree(people: ShiftSetup) -> None:
    three_owners(people)
    owner = reenter(people.browser("owner"))
    asked = owner.post(URL, json={"user_id": str(people.ids["ana"])})
    assert asked.status_code == 202
    request = f"/api/approval-requests/{asked.json()['id']}"
    # The person being made an owner cannot approve it.
    assert reenter(people.browser("ana")).post(f"{request}/approve").status_code == 403
    # One of the two others agrees: not enough yet.
    assert reenter(people.browser("admin")).post(f"{request}/approve").status_code == 200
    assert owners(people) == ids(people, "owner", "admin", "chef")
    # The last one agrees: done.
    approved = reenter(people.browser("chef")).post(f"{request}/approve")
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert owners(people) == ids(people, "owner", "admin", "chef", "ana")


def test_an_owner_who_approved_no_longer_sees_it_as_waiting(people: ShiftSetup) -> None:
    # The Approvals page's "waiting for you" list (view=to_review) shows only requests
    # that still need this person's decision. With three owners, a new owner needs both
    # other owners: after one approves, the request is still pending, but it waits only
    # for the other one.
    three_owners(people)
    owner = reenter(people.browser("owner"))
    asked = owner.post(URL, json={"user_id": str(people.ids["ana"])})
    assert asked.status_code == 202
    request_id = asked.json()["id"]

    def to_review(name: str) -> list[str]:
        listed = people.browser(name).get("/api/approval-requests", params={"view": "to_review"})
        assert listed.status_code == 200, listed.text
        return [item["id"] for item in listed.json()["items"]]

    assert request_id in to_review("admin") and request_id in to_review("chef")
    admin = reenter(people.browser("admin"))
    assert admin.post(f"/api/approval-requests/{request_id}/approve").status_code == 200
    # Gone from admin's list (they decided), still on chef's (they have not).
    assert request_id not in to_review("admin")
    assert request_id in to_review("chef")
    # admin can still open it to follow it, and deciding again is still refused.
    assert people.browser("admin").get(f"/api/approval-requests/{request_id}").status_code == 200
    assert admin.post(f"/api/approval-requests/{request_id}/deny").status_code == 409


def test_one_denial_stops_an_owner_change(people: ShiftSetup) -> None:
    three_owners(people)
    owner = reenter(people.browser("owner"))
    asked = owner.post(URL, json={"user_id": str(people.ids["ana"])})
    request = f"/api/approval-requests/{asked.json()['id']}"
    assert reenter(people.browser("admin")).post(f"{request}/approve").status_code == 200
    assert reenter(people.browser("chef")).post(f"{request}/deny").status_code == 200
    assert owners(people) == ids(people, "owner", "admin", "chef")


def test_removing_an_owner_needs_every_owner_but_that_one(people: ShiftSetup) -> None:
    three_owners(people)
    owner = reenter(people.browser("owner"))
    asked = owner.post(f"{URL}/{people.ids['chef']}/remove")
    assert asked.status_code == 202
    request = f"/api/approval-requests/{asked.json()['id']}"
    # The owner being removed cannot block it, nor decide it.
    assert reenter(people.browser("chef")).post(f"{request}/deny").status_code == 403
    assert owners(people) == ids(people, "owner", "admin", "chef")
    assert reenter(people.browser("admin")).post(f"{request}/approve").status_code == 200
    assert owners(people) == ids(people, "owner", "admin")
    assert "ownership.owner_removed" in actions(people, "ownership.")


# --- AZ8: never the last owner ---------------------------------------------------------


def test_the_last_owner_can_never_be_removed(people: ShiftSetup) -> None:
    owner = reenter(people.browser("owner"))
    assert owner.post(f"{URL}/{people.ids['owner']}/remove").status_code == 409
    assert owners(people) == ids(people, "owner")
    # Nor deactivated, nor demoted through role assignments.
    assert owner.post(f"/api/users/{people.ids['owner']}/deactivate").status_code == 403
    assert owners(people) == ids(people, "owner")


def test_with_two_owners_either_removes_the_other(people: ShiftSetup) -> None:
    # "Every owner except the one being removed" is then only the one asking (0032).
    owner = reenter(people.browser("owner"))
    assert propose_add(owner, people, "admin") == 200
    removed = owner.post(f"{URL}/{people.ids['admin']}/remove")
    assert removed.status_code == 200
    assert owners(people) == ids(people, "owner")
    assert owner.post(f"{URL}/{people.ids['chef']}/remove").status_code == 404  # not one
