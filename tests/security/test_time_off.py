"""Asking for time off and following requests (docs/features/time-off.md; threats I1, I2,
T2, T5), through the real app.

Each test is someone reaching for requests that are not theirs, bending the rules on days,
or setting a status directly, and checks what really happened: the answer and the rows.

People (tests/shift_data.py, tests/people_data.py): Northwind runs on America/Chicago;
Front on America/New_York. chef manages Kitchen (ana, cara); lead manages the Weekend Crew
(ben); dana is in Front with no manager.
"""

import uuid
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.approvals.models import ApprovalRequest
from app.approvals.service import lapse
from app.audit import Actor
from app.audit.models import AuditEvent
from app.db.base import utcnow
from app.modules.time_off.models import TimeOffRequest
from app.settings.service import change_setting
from tests.people_data import actions, people
from tests.shift_data import ShiftSetup, iso, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/time-off-requests"
CHICAGO = ZoneInfo("America/Chicago")


def day(offset: int) -> date:
    """A day in Northwind's zone, counted from today there."""
    return datetime.now(CHICAGO).date() + timedelta(days=offset)


def ask(client: TestClient, first: int, last: int, reason: str | None = None) -> dict:
    """Ask for days first..last from today; the answer, with its HTTP status as code."""
    body: dict = {"first_day": day(first).isoformat(), "last_day": day(last).isoformat()}
    if reason is not None:
        body["reason"] = reason
    response = client.post(URL, json=body)
    return {**(response.json() if response.content else {}), "code": response.status_code}


def stored(setup: ShiftSetup, request_id: str) -> TimeOffRequest:
    with setup.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        db.expunge(found)
        return found


def approval_of(setup: ShiftSetup, request_id: str) -> ApprovalRequest:
    with setup.db() as db:
        found = db.get(ApprovalRequest, stored(setup, request_id).approval_request_id)
        assert found is not None
        db.expunge(found)
        return found


# --- Asking ----------------------------------------------------------------------------


def test_a_request_shows_the_shifts_it_affects(people: ShiftSetup) -> None:
    starts = datetime.combine(day(2), datetime.min.time(), CHICAGO).replace(hour=9)
    shift = people.new_shift(
        employee_id=people.ids["ana"],
        starts_at=iso(starts.astimezone(ZoneInfo("UTC"))),
        ends_at=iso((starts + timedelta(hours=6)).astimezone(ZoneInfo("UTC"))),
    )
    made = ask(people.browser("ana"), 2, 3, "family visit")
    assert made["code"] == 201, made
    assert made["reason"] == "family visit"
    assert [s["id"] for s in made["affected_shifts"]] == [shift["id"]]
    assert actions(people, "time_off.requested") == ["time_off.requested"]
    # Its approval record: deadline at the start of the first day in the workplace zone.
    approval = approval_of(people, made["id"])
    first_midnight = datetime.combine(day(2), datetime.min.time(), CHICAGO)
    assert approval.kind == "time_off" and approval.required_approvals == 1
    assert approval.review_by == first_midnight.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)


def test_the_days_must_follow_the_rules(people: ShiftSetup) -> None:
    ana = people.browser("ana")
    assert ask(ana, 0, 1)["code"] == 422  # today: too late to review
    assert ask(ana, -3, -1)["code"] == 422
    assert ask(ana, 5, 4)["code"] == 422  # last before first
    assert ask(ana, 1, 31)["code"] == 422  # 31 days
    assert ask(ana, 1, 30)["code"] == 201  # 30 days is fine
    assert ask(ana, 40, 40, "x" * 501)["code"] == 422


def test_a_body_cannot_set_the_status_or_someone_else(people: ShiftSetup) -> None:
    ana = people.browser("ana")
    body = {"first_day": day(3).isoformat(), "last_day": day(3).isoformat()}
    assert ana.post(URL, json=body | {"status": "approved"}).status_code == 422
    assert ana.post(URL, json=body | {"employee_id": str(people.ids["cara"])}).status_code == 422
    with people.db() as db:
        assert db.scalars(select(TimeOffRequest)).all() == []


def test_overlapping_requests_are_refused(people: ShiftSetup) -> None:
    ana = people.browser("ana")
    assert ask(ana, 3, 5)["code"] == 201
    assert ask(ana, 5, 7)["code"] == 409
    assert ask(ana, 1, 3)["code"] == 409
    assert ask(ana, 6, 7)["code"] == 201  # next to it is fine
    assert ask(people.browser("cara"), 3, 5)["code"] == 201  # someone else's days


def test_required_approvals_come_from_the_company_setting(people: ShiftSetup) -> None:
    with people.db() as db:
        change_setting(db, "time_off.required_approvals", 2, actor=Actor.system())
        db.commit()
    made = ask(people.browser("ana"), 2, 2)
    assert approval_of(people, made["id"]).required_approvals == 2


def test_the_reason_is_kept_as_plain_text(people: ShiftSetup) -> None:
    made = ask(people.browser("ana"), 2, 2, "<img src=x onerror=alert(1)>")
    assert made["reason"] == "<img src=x onerror=alert(1)>"  # data, never markup
    # The reason never goes into the audit log, which is kept for good.
    with people.db() as db:
        details = db.scalars(
            select(AuditEvent.details).where(AuditEvent.action == "time_off.requested")
        ).all()
    assert all("reason" not in d and "onerror" not in str(d) for d in details)


# --- I1, I2: other people's requests ---------------------------------------------------


def test_people_see_only_requests_they_may_see(people: ShiftSetup) -> None:
    made = ask(people.browser("ana"), 2, 2)
    ask(people.browser("dana"), 2, 2)
    url = f"{URL}/{made['id']}"
    assert people.browser("ana").get(url).status_code == 200  # own
    assert people.browser("chef").get(url).status_code == 200  # Kitchen's manager
    assert people.browser("cara").get(url).status_code == 403  # a coworker
    assert people.browser("lead").get(url).status_code == 403  # another team's manager
    assert people.browser("b_chef").get(url).status_code == 404  # another company
    # Lists: chef sees Kitchen's people only; employees cannot list others at all.
    listed = people.browser("chef").get(URL).json()["items"]
    assert {item["employee_id"] for item in listed} == {str(people.ids["ana"])}
    assert people.browser("cara").get(URL).status_code == 403
    mine = people.browser("cara").get(URL, params={"mine": "true"}).json()["items"]
    assert mine == []
    assert people.browser("b_chef").get(URL).json()["items"] == []


# --- Cancelling ------------------------------------------------------------------------


def test_only_the_employee_cancels_their_request(people: ShiftSetup) -> None:
    made = ask(people.browser("ana"), 2, 2)
    url = f"{URL}/{made['id']}/cancel"
    for name in ("cara", "chef", "owner", "b_chef"):
        assert people.browser(name).post(url).status_code == 404, name
    assert stored(people, made["id"]).status == "pending"
    cancelled = people.browser("ana").post(url)
    assert cancelled.status_code == 200 and cancelled.json()["status"] == "cancelled"
    assert approval_of(people, made["id"]).status == "cancelled"
    assert people.browser("ana").post(url).status_code == 409
    assert actions(people, "time_off.cancelled") == ["time_off.cancelled"]
    # The days are free again.
    assert ask(people.browser("ana"), 2, 2)["code"] == 201


def test_an_approved_request_is_cancelled_only_before_its_first_day(people: ShiftSetup) -> None:
    later = ask(people.browser("ana"), 4, 4)
    begun = ask(people.browser("ana"), 6, 6)
    with people.db() as db:
        db.execute(
            update(TimeOffRequest)
            .where(TimeOffRequest.id.in_([uuid.UUID(later["id"]), uuid.UUID(begun["id"])]))
            .values(status="approved", decided_at=utcnow())
        )
        # The second one's days have begun (as if time had passed).
        db.execute(
            update(TimeOffRequest)
            .where(TimeOffRequest.id == uuid.UUID(begun["id"]))
            .values(first_day=day(0))
        )
        db.commit()
    ana = people.browser("ana")
    assert ana.post(f"{URL}/{later['id']}/cancel").status_code == 200
    assert ana.post(f"{URL}/{begun['id']}/cancel").status_code == 409


# --- Not reviewed in time --------------------------------------------------------------


def overdue(setup: ShiftSetup, request_id: str) -> None:
    """Move the request's review deadline into the past, as if its first day had begun."""
    with setup.db() as db:
        db.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == stored(setup, request_id).approval_request_id)
            .values(review_by=utcnow() - timedelta(seconds=1))
        )
        db.commit()


def test_a_status_filter_finds_requests_older_than_the_limit(people: ShiftSetup) -> None:
    """Review of #166: the status filter ran after the limit, so asking for one status
    could answer nothing while older requests with it existed."""
    ana, chef = people.browser("ana"), people.browser("chef")
    cancelled = ask(ana, 3, 3)
    lapsed = ask(ana, 5, 5)
    ask(ana, 7, 7)
    ask(ana, 9, 9)  # the two newest stay pending
    assert ana.post(f"{URL}/{cancelled['id']}/cancel").status_code == 200
    overdue(people, lapsed["id"])  # not stored as denied until someone reads it

    def ids(**params: str) -> list[str]:
        return [item["id"] for item in chef.get(URL, params=params).json()["items"]]

    assert ids(status="cancelled", limit="1") == [cancelled["id"]]
    # The overdue one counts as declined although it was still stored as pending.
    assert ids(status="denied", limit="1") == [lapsed["id"]]
    assert len(ids(status="pending", limit="1")) == 1
    assert actions(people, "time_off.not_reviewed") == ["time_off.not_reviewed"]


def test_a_request_lapses_only_once_when_noticed_twice(people: ShiftSetup) -> None:
    """Review of #166: two requests reading the same overdue request at once both lapsed
    it, writing the audit entry twice. Here the second holds a copy read before the first
    lapsed it (what a request without a lock sees); it must leave the request alone."""
    made = ask(people.browser("ana"), 3, 3)
    overdue(people, made["id"])
    approval_id = stored(people, made["id"]).approval_request_id
    with people.db() as second:
        old_copy = second.get(ApprovalRequest, approval_id)
        assert old_copy is not None and old_copy.status == "pending"
        with people.db() as first:
            fresh = first.get(ApprovalRequest, approval_id)
            assert fresh is not None and lapse(first, fresh)
            first.commit()
        assert not lapse(second, old_copy)  # already lapsed: nothing to do
        assert old_copy.status == "denied"  # and its copy now says so
        second.commit()
    assert actions(people, "approval.not_reviewed") == ["approval.not_reviewed"]
    assert actions(people, "time_off.not_reviewed") == ["time_off.not_reviewed"]


def test_a_request_nobody_reviewed_by_its_first_day_is_declined(people: ShiftSetup) -> None:
    made = ask(people.browser("ana"), 3, 3)
    with people.db() as db:
        db.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == stored(people, made["id"]).approval_request_id)
            .values(review_by=utcnow() - timedelta(seconds=1))
        )
        db.commit()
    mine = people.browser("ana").get(URL, params={"mine": "true"}).json()["items"]
    assert [(i["status"], i["not_reviewed"]) for i in mine] == [("denied", True)]
    assert actions(people, "time_off.not_reviewed") == ["time_off.not_reviewed"]
    assert people.browser("ana").post(f"{URL}/{made['id']}/cancel").status_code == 409
    # Declined requests no longer hold the days.
    assert ask(people.browser("ana"), 3, 3)["code"] == 201
