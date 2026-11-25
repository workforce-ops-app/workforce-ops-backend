"""Reviewing time off (docs/features/time-off.md; decision 0029; threats E3, E5), through the
real app.

Each test is someone deciding a request they should not decide, or reviewers who disagree,
and checks what really happened: the answers, the request, its shifts, and the audit log.

People (tests/people_data.py): owner > admin > chef > ana, cara, lead; lead > ben. chef
manages Kitchen (ana, cara); lead manages the Weekend Crew (ben). Northwind runs on
America/Chicago.
"""

import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.approvals.models import ApprovalRequest
from app.audit import Actor
from app.audit.models import AuditEvent
from app.authz.chain import add_reporting_line
from app.authz.models import ReportingLine
from app.db.base import utcnow
from app.modules.org.models import TeamMember
from app.modules.schedules.models import Shift
from app.modules.time_off.models import TimeOffRequest
from app.settings.service import change_setting
from tests.people_data import actions, people
from tests.shift_data import ShiftSetup, iso, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/time-off-requests"
CHICAGO = ZoneInfo("America/Chicago")
UTC = ZoneInfo("UTC")


def day(offset: int) -> datetime:
    """Nine in the morning, `offset` days from today in Northwind's zone."""
    today = datetime.now(CHICAGO).date() + timedelta(days=offset)
    return datetime.combine(today, datetime.min.time(), CHICAGO).replace(hour=9)


def ask(client: TestClient, first: int, last: int) -> str:
    """Ask for days first..last from today; the new request's ID."""
    response = client.post(
        URL,
        json={
            "first_day": day(first).date().isoformat(),
            "last_day": day(last).date().isoformat(),
        },
    )
    assert response.status_code == 201, response.json()
    return response.json()["id"]


def decide(setup: ShiftSetup, who: str, request_id: str, decision: str, comment: str = "") -> int:
    body = {"comment": comment} if comment else None
    return setup.browser(who).post(f"{URL}/{request_id}/{decision}", json=body).status_code


def status(setup: ShiftSetup, request_id: str) -> str:
    with setup.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        return found.status


def waiting_for(setup: ShiftSetup, who: str) -> list[str]:
    response = setup.browser(who).get(f"{URL}/waiting")
    assert response.status_code == 200
    return [item["id"] for item in response.json()["items"]]


def shift_for(setup: ShiftSetup, who: str, offset: int) -> str:
    starts = day(offset)
    return setup.new_shift(
        employee_id=setup.ids[who],
        starts_at=iso(starts.astimezone(UTC)),
        ends_at=iso((starts + timedelta(hours=6)).astimezone(UTC)),
    )["id"]


def needs_two(setup: ShiftSetup) -> None:
    """Two approvals per request, so two reviewers can disagree."""
    with setup.db() as db:
        change_setting(db, "time_off.required_approvals", 2, actor=Actor.system())
        db.commit()


def also_reports_to(setup: ShiftSetup, employee: str, manager: str) -> None:
    with setup.db() as db:
        add_reporting_line(
            db, Actor.system(), manager_id=setup.ids[manager], employee_id=setup.ids[employee]
        )
        db.commit()


# --- Approving opens exactly the overlapping shifts ------------------------------------


def test_the_direct_manager_approves_and_only_those_days_open(people: ShiftSetup) -> None:
    on_the_day = shift_for(people, "ana", 2)
    later = shift_for(people, "ana", 6)
    coworker = shift_for(people, "cara", 2)
    request_id = ask(people.browser("ana"), 2, 3)

    assert waiting_for(people, "chef") == [request_id]
    assert waiting_for(people, "cara") == [] and waiting_for(people, "lead") == []
    assert decide(people, "chef", request_id, "approve") == 200
    assert status(people, request_id) == "approved"

    with people.db() as db:
        rows = {
            str(s.id): (s.status, s.employee_id)
            for s in db.scalars(
                select(Shift).where(
                    Shift.id.in_([uuid.UUID(x) for x in (on_the_day, later, coworker)])
                )
            )
        }
        opened = db.scalars(select(AuditEvent).where(AuditEvent.action == "shift.opened")).all()
    assert rows[on_the_day] == ("open", None)
    assert rows[later] == ("scheduled", people.ids["ana"])
    assert rows[coworker] == ("scheduled", people.ids["cara"])
    assert [(str(e.target_id), e.details["time_off_request_id"]) for e in opened] == [
        (on_the_day, request_id)
    ]
    assert actions(people, "time_off.approved") == ["time_off.approved"]
    # Decided: nobody can decide it again.
    assert decide(people, "chef", request_id, "deny") == 409


def test_fewer_reviewers_than_the_setting_asks_for_means_all_of_them(people: ShiftSetup) -> None:
    needs_two(people)  # but ana has one direct manager who can review: chef
    request_id = ask(people.browser("ana"), 2, 2)
    assert decide(people, "chef", request_id, "approve") == 200
    assert status(people, request_id) == "approved"


# --- E5, AZ7: nobody reviews their own request -----------------------------------------


def test_nobody_reviews_their_own_request(people: ShiftSetup) -> None:
    request_id = ask(people.browser("chef"), 2, 2)  # chef holds time_off.review
    assert request_id not in waiting_for(people, "chef")
    assert decide(people, "chef", request_id, "approve") == 403
    assert status(people, request_id) == "pending"
    # It goes to chef's own manager instead.
    assert waiting_for(people, "admin") == [request_id]
    assert decide(people, "admin", request_id, "approve") == 200


# --- E3: reviewing someone you are not above -------------------------------------------


def test_a_manager_not_above_the_employee_cannot_review(people: ShiftSetup) -> None:
    request_id = ask(people.browser("ana"), 2, 2)
    assert decide(people, "lead", request_id, "approve") == 403  # has the permission
    assert decide(people, "cara", request_id, "approve") == 403  # a coworker
    assert decide(people, "b_chef", request_id, "approve") == 404  # another company
    # Higher up, but not the reviewer while chef can review: chef decides first.
    assert decide(people, "admin", request_id, "approve") == 403
    assert status(people, request_id) == "pending"


def test_a_reviewer_who_lost_their_place_cannot_decide(people: ShiftSetup) -> None:
    request_id = ask(people.browser("ana"), 2, 2)
    with people.db() as db:
        db.execute(
            update(ReportingLine)
            .where(
                ReportingLine.manager_id == people.ids["chef"],
                ReportingLine.employee_id == people.ids["ana"],
            )
            .values(ended_at=utcnow())
        )
        db.commit()
    assert decide(people, "chef", request_id, "approve") == 403
    assert status(people, request_id) == "pending"


def test_time_off_is_not_decided_through_the_general_approvals_page(people: ShiftSetup) -> None:
    request_id = ask(people.browser("ana"), 2, 2)
    with people.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        approval_id = found.approval_request_id
    chef = people.browser("chef")
    assert chef.post(f"/api/approval-requests/{approval_id}/approve").status_code == 409
    assert status(people, request_id) == "pending"


def test_time_off_is_not_cancelled_through_the_general_approvals_page(people: ShiftSetup) -> None:
    # Review of #167: cancelling there would stop the approval record waiting while the
    # time-off request stays pending. Refused (409); the time-off page cancels both.
    request_id = ask(people.browser("ana"), 2, 2)
    with people.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        approval_id = found.approval_request_id
    ana = people.browser("ana")
    refused = ana.post(f"/api/approval-requests/{approval_id}/cancel")
    assert refused.status_code == 409, refused.text
    assert status(people, request_id) == "pending"
    with people.db() as db:
        approval = db.get(ApprovalRequest, approval_id)
        assert approval is not None and approval.status == "pending"
    assert actions(people, "approval.cancelled") == []
    # The time-off page cancels both.
    assert ana.post(f"{URL}/{request_id}/cancel").status_code == 200
    assert status(people, request_id) == "cancelled"


# --- Denying ---------------------------------------------------------------------------


def test_a_denial_with_a_comment(people: ShiftSetup) -> None:
    on_the_day = shift_for(people, "ana", 2)
    request_id = ask(people.browser("ana"), 2, 2)
    assert decide(people, "chef", request_id, "deny", "<b>short-staffed</b>") == 200
    assert status(people, request_id) == "denied"
    seen = people.browser("ana").get(f"{URL}/{request_id}").json()
    assert [(d["decision"], d["comment"]) for d in seen["decisions"]] == [
        ("deny", "<b>short-staffed</b>")  # kept as typed, shown as plain text
    ]
    # Who asked and who decided, by name, for the review screen (#172).
    assert seen["employee_name"] == "Ana"
    assert [d["approver_name"] for d in seen["decisions"]] == ["Chef"]
    waiting = people.browser("chef").get(f"{URL}?status=denied").json()["items"]
    assert {item["employee_name"] for item in waiting} <= {"Ana"}
    assert actions(people, "time_off.denied") == ["time_off.denied"]
    with people.db() as db:
        shift = db.get(Shift, uuid.UUID(on_the_day))
        assert shift is not None and shift.status == "scheduled"
        comments = db.scalars(select(AuditEvent.details)).all()
    assert all("short-staffed" not in str(d) for d in comments)  # never in the log


def test_no_decision_after_the_first_day_begins(people: ShiftSetup) -> None:
    request_id = ask(people.browser("ana"), 2, 2)
    with people.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        db.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == found.approval_request_id)
            .values(review_by=utcnow() - timedelta(seconds=1))
        )
        db.commit()
    assert decide(people, "chef", request_id, "approve") == 409
    assert status(people, request_id) == "denied"


# --- Disagreement moves up -------------------------------------------------------------


def test_disagreement_goes_to_the_nearest_shared_manager(people: ShiftSetup) -> None:
    # ana also reports to lead, who now covers her through the Weekend Crew.
    with people.db() as db:
        db.add(TeamMember(team_id=people.ids["crew"], user_id=people.ids["ana"]))
        db.commit()
    also_reports_to(people, "ana", "lead")
    needs_two(people)
    request_id = ask(people.browser("ana"), 2, 2)
    assert set(waiting_for(people, "chef")) == {request_id} == set(waiting_for(people, "lead"))

    assert decide(people, "chef", request_id, "approve") == 200
    assert status(people, request_id) == "pending"  # one of two approvals
    assert decide(people, "lead", request_id, "deny") == 200
    assert status(people, request_id) == "escalated"

    # chef and lead are both below admin (lead through chef): admin is the nearest.
    with people.db() as db:
        escalated = db.scalars(
            select(AuditEvent.details).where(AuditEvent.action == "time_off.escalated")
        ).all()
    assert escalated == [{"to": [str(people.ids["admin"])]}]
    assert waiting_for(people, "admin") == [request_id]
    assert decide(people, "owner", request_id, "deny") == 403  # higher, but not nearest
    assert decide(people, "chef", request_id, "deny") == 403  # already disagreed
    assert decide(people, "admin", request_id, "approve") == 200
    assert status(people, request_id) == "approved"


def test_a_reviewer_who_decided_no_longer_sees_it_as_waiting(people: ShiftSetup) -> None:
    # Reported in review: after denying, the request stayed at the top under "Waiting for
    # you". With two reviewers (chef and lead), one decision leaves the request pending for
    # the other; it must leave the list of the one who decided, for a denial and for an
    # approval alike.
    with people.db() as db:
        db.add(TeamMember(team_id=people.ids["crew"], user_id=people.ids["ana"]))
        db.commit()
    also_reports_to(people, "ana", "lead")
    needs_two(people)
    denied_first = ask(people.browser("ana"), 2, 2)
    approved_first = ask(people.browser("ana"), 4, 4)
    both = {denied_first, approved_first}
    assert set(waiting_for(people, "chef")) == both == set(waiting_for(people, "lead"))

    assert decide(people, "chef", denied_first, "deny") == 200
    assert decide(people, "chef", approved_first, "approve") == 200
    # Both still wait for lead, so neither is settled yet.
    assert status(people, denied_first) == "pending"
    assert status(people, approved_first) == "pending"
    assert waiting_for(people, "chef") == []
    assert set(waiting_for(people, "lead")) == both

    # chef can still open both to follow them, and cannot decide them again.
    client = people.browser("chef")
    assert client.get(f"{URL}/{denied_first}").status_code == 200
    assert decide(people, "chef", denied_first, "approve") == 409


def test_with_no_shared_manager_the_owner_settles_it(people: ShiftSetup) -> None:
    # ana reports to chef and to admin, and admin no longer reports to anyone: nobody is
    # above both of them through lines, so the owner decides.
    also_reports_to(people, "ana", "admin")
    with people.db() as db:
        db.execute(
            update(ReportingLine)
            .where(ReportingLine.manager_id == people.ids["owner"])
            .values(ended_at=utcnow())
        )
        db.commit()
    needs_two(people)
    request_id = ask(people.browser("ana"), 2, 2)
    assert decide(people, "admin", request_id, "deny") == 200
    assert status(people, request_id) == "pending"  # chef has not decided yet
    assert decide(people, "chef", request_id, "approve") == 200
    assert status(people, request_id) == "escalated"
    assert waiting_for(people, "owner") == [request_id]
    assert decide(people, "owner", request_id, "deny") == 200
    assert status(people, request_id) == "denied"


def test_every_decision_is_audited_even_while_the_request_waits(people: ShiftSetup) -> None:
    # Review of #167 (AZ12): a decision that leaves the request waiting, or sends it up the
    # chain, has its own entry (final: false); the settling one is final.
    with people.db() as db:
        db.add(TeamMember(team_id=people.ids["crew"], user_id=people.ids["ana"]))
        db.commit()
    also_reports_to(people, "ana", "lead")
    needs_two(people)
    request_id = ask(people.browser("ana"), 2, 2)
    assert decide(people, "chef", request_id, "approve") == 200  # one of two
    assert decide(people, "lead", request_id, "deny") == 200  # escalated
    assert decide(people, "admin", request_id, "approve") == 200  # settles it
    with people.db() as db:
        entries = db.execute(
            select(AuditEvent.action, AuditEvent.actor_id, AuditEvent.details)
            .where(AuditEvent.action.in_(("approval.approved", "approval.denied")))
            .order_by(AuditEvent.seq)
        ).all()
    assert [(action, actor, details["final"]) for action, actor, details in entries] == [
        ("approval.approved", people.ids["chef"], False),
        ("approval.denied", people.ids["lead"], False),
        ("approval.approved", people.ids["admin"], True),
    ]
