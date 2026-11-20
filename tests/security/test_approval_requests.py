"""Approval requests for roles at the giver's own level (authorization.md; threats E2, E5;
rules AZ7, AZ12, AZ14), through the real app.

Each test is someone trying to push a same-level role through without a real approval
from above: approving their own request, approving one that gives them the role, deciding
after losing their place, or approving after the deadline. Each checks what really
happened: the request's state and the roles people hold.

People and lines (tests/people_data.py):
    owner > admin > chef > {ana, cara, newbie, gone, lead > ben}; dana has no manager.
"""

import uuid
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.approvals.models import ApprovalRequest
from app.audit import Actor
from app.authz.models import ReportingLine, Role, RoleAssignment, RolePermission
from app.authz.roles import assign_role
from app.db.base import utcnow
from app.modules.org.models import User
from tests.people_data import actions, people
from tests.shift_data import PASSWORD, ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/approval-requests"


def reenter(client: TestClient) -> None:
    response = client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    assert response.status_code == 204, response.text


def role_id(setup: ShiftSetup, key: str) -> uuid.UUID:
    with setup.db() as db:
        return db.scalars(select(Role.id).where((Role.built_in == key) | (Role.name == key))).one()


def holds(setup: ShiftSetup, name: str, role: uuid.UUID) -> bool:
    with setup.db() as db:
        found = db.scalars(
            select(RoleAssignment.id).where(
                RoleAssignment.user_id == setup.ids[name], RoleAssignment.role_id == role
            )
        ).first()
        return found is not None


def ask(
    setup: ShiftSetup,
    giver: str,
    receiver: str,
    role: uuid.UUID,
    scope: str = "company",
    where: uuid.UUID | None = None,
) -> str:
    """The giver gives a role at their own level: a request opens (202). Its ID."""
    client = setup.browser(giver)
    reenter(client)
    body = {"user_id": str(setup.ids[receiver]), "role_id": str(role), "scope_type": scope}
    if where is not None:
        body["scope_id"] = str(where)
    response = client.post("/api/role-assignments", json=body)
    assert response.status_code == 202, response.text
    return response.json()["id"]


def state(setup: ShiftSetup, request_id: str) -> ApprovalRequest:
    with setup.db() as db:
        found = db.get(ApprovalRequest, uuid.UUID(request_id))
        assert found is not None
        db.expunge(found)
        return found


def admin_for_chef(setup: ShiftSetup) -> tuple[str, uuid.UUID]:
    """admin asks to make chef an Administrator (admin's own level): the request's ID."""
    administrator = role_id(setup, "administrator")
    return ask(setup, "admin", "chef", administrator), administrator


# --- AZ7, AZ14: the requester and the receiver never decide ----------------------------


def test_nobody_approves_their_own_request_or_their_own_promotion(people: ShiftSetup) -> None:
    request_id, administrator = admin_for_chef(people)
    for name in ("admin", "chef"):  # who asked, and who would receive it
        client = people.browser(name)
        reenter(client)
        assert client.post(f"{URL}/{request_id}/approve").status_code == 403, name
        assert client.get(f"{URL}/{request_id}").status_code == 200  # they may see it
    assert state(people, request_id).status == "pending"
    assert not holds(people, "chef", administrator)


def test_people_not_involved_cannot_see_or_decide_a_request(people: ShiftSetup) -> None:
    request_id, administrator = admin_for_chef(people)
    for name in ("ana", "lead", "dana", "b_chef"):
        client = people.browser(name)
        assert client.get(f"{URL}/{request_id}").status_code == 404, name
        assert client.post(f"{URL}/{request_id}/approve").status_code == 404, name
        assert client.post(f"{URL}/{request_id}/cancel").status_code == 404, name
        listed = client.get(URL, params={"view": "to_review"}).json()["items"]
        assert request_id not in {item["id"] for item in listed}
    assert state(people, request_id).status == "pending"
    assert not holds(people, "chef", administrator)


# --- The reviewer above decides --------------------------------------------------------


def test_the_manager_above_the_giver_approves_and_the_role_is_given(people: ShiftSetup) -> None:
    request_id, administrator = admin_for_chef(people)
    owner = people.browser("owner")  # admin's direct manager
    to_review = owner.get(URL, params={"view": "to_review"}).json()["items"]
    assert [item["id"] for item in to_review] == [request_id]
    # An admin-level role: the password first.
    refused = owner.post(f"{URL}/{request_id}/approve")
    assert refused.status_code == 403 and refused.json()["type"] == "reauth-required"
    reenter(owner)
    approved = owner.post(f"{URL}/{request_id}/approve")
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    assert holds(people, "chef", administrator)
    assert actions(people, "approval.") == ["approval.requested", "approval.approved"]
    assert actions(people, "role_assignment.added")[-1] == "role_assignment.added"
    # Decided once: a second approval is refused.
    assert owner.post(f"{URL}/{request_id}/approve").status_code == 409


def test_a_denied_request_gives_nothing(people: ShiftSetup) -> None:
    request_id, administrator = admin_for_chef(people)
    owner = people.browser("owner")
    reenter(owner)
    denied = owner.post(f"{URL}/{request_id}/deny")
    assert denied.status_code == 200 and denied.json()["status"] == "denied"
    assert not holds(people, "chef", administrator)
    assert owner.post(f"{URL}/{request_id}/approve").status_code == 409
    assert actions(people, "approval.denied") == ["approval.denied"]


def test_only_the_requester_cancels(people: ShiftSetup) -> None:
    request_id, administrator = admin_for_chef(people)
    assert people.browser("chef").post(f"{URL}/{request_id}/cancel").status_code == 403
    assert people.browser("owner").post(f"{URL}/{request_id}/cancel").status_code == 403
    cancelled = people.browser("admin").post(f"{URL}/{request_id}/cancel")
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    owner = people.browser("owner")
    reenter(owner)
    assert owner.post(f"{URL}/{request_id}/approve").status_code == 409
    assert not holds(people, "chef", administrator)


# --- After 7 days: declined as not reviewed --------------------------------------------


def test_a_request_nobody_reviewed_in_time_can_never_be_approved(people: ShiftSetup) -> None:
    request_id, administrator = admin_for_chef(people)
    with people.db() as db:
        db.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == uuid.UUID(request_id))
            .values(review_by=utcnow() - timedelta(seconds=1))
        )
        db.commit()
    owner = people.browser("owner")
    reenter(owner)
    late = owner.post(f"{URL}/{request_id}/approve")
    assert late.status_code == 409
    found = state(people, request_id)
    assert found.status == "denied" and found.not_reviewed is True
    assert found.decided_at == found.review_by  # declined at the deadline itself
    assert not holds(people, "chef", administrator)
    assert actions(people, "approval.not_reviewed") == ["approval.not_reviewed"]
    mine = people.browser("admin").get(URL).json()["items"]
    assert [(item["id"], item["not_reviewed"]) for item in mine] == [(request_id, True)]


# --- Reviewers are worked out again at every decision ----------------------------------


def _kitchen_admin_with_own_level_role(setup: ShiftSetup) -> uuid.UUID:
    """chef holds Manager and Kitchen Admin (role.assign) for Kitchen; "Kitchen Lead"
    grants everything chef holds for Kitchen, so giving it is at chef's own level."""
    with setup.db() as db:
        admin_role = Role(name="Kitchen Admin")
        lead_role = Role(name="Kitchen Lead")
        db.add_all([admin_role, lead_role])
        db.flush()
        extra = {"role.assign", "user.view", "schedule.edit", "schedule.view"}
        db.add_all(RolePermission(role_id=admin_role.id, permission_code=c) for c in extra)
        manager = db.scalars(select(Role).where(Role.built_in == "manager")).one()
        manager_codes = set(
            db.scalars(
                select(RolePermission.permission_code).where(RolePermission.role_id == manager.id)
            )
        )
        db.add_all(
            RolePermission(role_id=lead_role.id, permission_code=c) for c in extra | manager_codes
        )
        assign_role(
            db,
            Actor.system(),
            user_id=setup.ids["chef"],
            role=admin_role,
            scope_type="department",
            scope_id=setup.ids["kitchen"],
        )
        db.commit()
        return lead_role.id


def test_a_reviewer_who_lost_their_place_can_no_longer_decide(people: ShiftSetup) -> None:
    lead_role = _kitchen_admin_with_own_level_role(people)
    request_id = ask(people, "chef", "cara", lead_role, "department", people.ids["kitchen"])
    admin = people.browser("admin")  # chef's direct manager, who could give it
    assert [i["id"] for i in admin.get(URL, params={"view": "to_review"}).json()["items"]] == [
        request_id
    ]
    # The line admin > chef ends: admin is no longer above chef, so the request moves up.
    with people.db() as db:
        db.execute(
            update(ReportingLine)
            .where(
                ReportingLine.manager_id == people.ids["admin"],
                ReportingLine.employee_id == people.ids["chef"],
            )
            .values(ended_at=utcnow())
        )
        db.commit()
    assert admin.post(f"{URL}/{request_id}/approve").status_code == 404
    assert not holds(people, "cara", lead_role)
    # With nobody left above chef, the owner reviews it.
    owner = people.browser("owner")
    assert [i["id"] for i in owner.get(URL, params={"view": "to_review"}).json()["items"]] == [
        request_id
    ]
    reenter(owner)
    assert owner.post(f"{URL}/{request_id}/approve").status_code == 200
    assert holds(people, "cara", lead_role)


def test_approval_refuses_a_role_that_can_no_longer_be_given(people: ShiftSetup) -> None:
    request_id, administrator = admin_for_chef(people)
    with people.db() as db:
        chef = db.get(User, people.ids["chef"])
        assert chef is not None
        chef.deactivated_at = utcnow()
        db.commit()
    owner = people.browser("owner")
    reenter(owner)
    assert owner.post(f"{URL}/{request_id}/approve").status_code == 409
    assert state(people, request_id).status == "pending"
    assert not holds(people, "chef", administrator)
