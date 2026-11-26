"""Asking coworkers for cover or a swap on a time-off request (docs/features/coverage.md,
slice CV1; threats T8, I10, I1/T3, T2), through the real app.

Each test is someone trying what the rules refuse (offering a shift they could not take,
offering with a shift that is not theirs, reading other coworkers' answers, reaching into
another company), or the request moving between its states, and checks what really
happened: the answers, the rows, and the audit log.

People (tests/people_data.py): chef manages Kitchen (ana, cara); ben lives in Front and is
on the Weekend Crew, a team in Kitchen, so he may work Kitchen shifts; dana lives in Front
and may not. Company B has b_chef and b_ana. Northwind runs on America/Chicago.

In most tests ana asks for days 5 and 6 with offers, with one Kitchen shift on day 5.
"""

import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.audit import Actor
from app.audit.models import AuditEvent
from app.db.base import utcnow
from app.modules.schedules.models import Shift
from app.modules.time_off.models import CoverageOffer, TimeOffRequest
from app.settings.service import change_setting
from tests.people_data import actions, people
from tests.shift_data import ShiftSetup, iso, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here

URL = "/api/time-off-requests"
CHICAGO = ZoneInfo("America/Chicago")
UTC = ZoneInfo("UTC")
TOO_LATE = "It is too late to ask coworkers for these days; send the request without offers."


def day(offset: int, hour: int = 9) -> datetime:
    """`hour` o'clock, `offset` days from today in Northwind's zone."""
    today = datetime.now(CHICAGO).date() + timedelta(days=offset)
    return datetime.combine(today, datetime.min.time(), CHICAGO).replace(hour=hour)


def ask_body(first: int, last: int, offers: bool = True) -> dict:
    return {
        "first_day": day(first).date().isoformat(),
        "last_day": day(last).date().isoformat(),
        "offer_coverage": offers,
    }


def ask(client: TestClient, first: int = 5, last: int = 6) -> str:
    """Ask with offers for days first..last from today; the new request's ID."""
    response = client.post(URL, json=ask_body(first, last))
    assert response.status_code == 201, response.json()
    return response.json()["id"]


def shift_for(setup: ShiftSetup, who: str, offset: int, dept: str = "kitchen", hour: int = 9):
    """A six-hour shift for `who` on day `offset`, made by the owner (who may schedule
    anywhere); its ID."""
    starts = day(offset, hour)
    return setup.new_shift(
        "owner",
        employee_id=setup.ids[who],
        department_id=str(setup.ids[dept]),
        starts_at=iso(starts.astimezone(UTC)),
        ends_at=iso((starts + timedelta(hours=6)).astimezone(UTC)),
    )["id"]


def offer(setup: ShiftSetup, who: str, request_id: str, shift_id: str, answer: str, swap=None):
    body = {"answer": answer} | ({"swap_shift_id": swap} if swap else {})
    return setup.browser(who).put(f"{URL}/{request_id}/offers/{shift_id}", json=body)


def offers_seen(setup: ShiftSetup, who: str, request_id: str) -> list[tuple[str, str]]:
    """(coworker ID, answer) for every offer the person sees on the request page."""
    response = setup.browser(who).get(f"{URL}/{request_id}")
    assert response.status_code == 200, response.json()
    return sorted((o["offered_by"], o["answer"]) for o in response.json()["offers"])


def stored_status(setup: ShiftSetup, request_id: str) -> str:
    with setup.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        return found.status


def waiting_for(setup: ShiftSetup, who: str) -> list[str]:
    response = setup.browser(who).get(f"{URL}/waiting")
    assert response.status_code == 200
    return [item["id"] for item in response.json()["items"]]


def setup_request(people: ShiftSetup) -> tuple[str, str]:
    """ana's day-5 Kitchen shift, and her request for days 5 and 6 with offers."""
    shift = shift_for(people, "ana", 5)
    return ask(people.browser("ana")), shift


# --- Asking with offers and the collecting state ----------------------------------------


def test_asking_with_offers_collects_and_nobody_can_decide_it(people: ShiftSetup) -> None:
    request_id, _ = setup_request(people)
    answer = people.browser("ana").get(f"{URL}/{request_id}").json()
    assert answer["status"] == "collecting"
    assert answer["offers_close_at"] is not None and answer["sent_up_at"] is None
    # Nobody reviews it yet: not on the manager's list, and deciding is refused.
    assert request_id not in waiting_for(people, "chef")
    assert request_id not in waiting_for(people, "owner")
    approve = people.browser("chef").post(f"{URL}/{request_id}/approve")
    assert approve.status_code == 403
    assert stored_status(people, request_id) == "collecting"


def test_asking_without_offers_is_unchanged(people: ShiftSetup) -> None:
    response = people.browser("ana").post(URL, json=ask_body(5, 6, offers=False))
    assert response.status_code == 201
    assert response.json()["status"] == "pending"
    assert response.json()["offers_close_at"] is None


def test_too_late_to_ask_with_offers(people: ShiftSetup) -> None:
    # Tomorrow: the deadline (the day before) has already begun.
    response = people.browser("ana").post(URL, json=ask_body(1, 1))
    assert response.status_code == 409
    assert response.json()["detail"] == TOO_LATE
    # A company that gives reviewers five days: day 4 is too late, day 6 is not.
    with people.db() as db:
        change_setting(db, "time_off.offers_close_days", 5, actor=Actor.system())
        db.commit()
    assert people.browser("ana").post(URL, json=ask_body(4, 4)).status_code == 409
    assert people.browser("ana").post(URL, json=ask_body(6, 6)).status_code == 201
    # Nothing was stored for the refused ones.
    with people.db() as db:
        assert len(list(db.scalars(select(TimeOffRequest)))) == 1


def test_a_body_cannot_set_the_status_or_deadline(people: ShiftSetup) -> None:
    # Threat T2: only the rules change these.
    for extra in ({"status": "approved"}, {"offers_close_at": iso(utcnow())}):
        response = people.browser("ana").post(URL, json=ask_body(5, 6) | extra)
        assert response.status_code == 422


# --- Sending up ------------------------------------------------------------------------


def test_the_employee_sends_it_up(people: ShiftSetup) -> None:
    request_id, _ = setup_request(people)
    # Only the employee: a coworker or a manager gets 404, another company 404.
    for who in ("cara", "chef", "b_ana"):
        assert people.browser(who).post(f"{URL}/{request_id}/send-up").status_code == 404
    response = people.browser("ana").post(f"{URL}/{request_id}/send-up")
    assert response.status_code == 200
    assert response.json()["status"] == "pending" and response.json()["sent_up_at"]
    assert request_id in waiting_for(people, "chef")
    # Once only.
    assert people.browser("ana").post(f"{URL}/{request_id}/send-up").status_code == 409
    with people.db() as db:
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == "time_off.sent_up")).one()
        assert event.actor_type == "user" and event.details == {"by": "employee"}


def test_the_deadline_sends_it_up_on_the_next_read(people: ShiftSetup) -> None:
    request_id, _ = setup_request(people)
    passed = utcnow() - timedelta(minutes=1)
    with people.db() as db:
        db.execute(
            update(TimeOffRequest)
            .where(TimeOffRequest.id == uuid.UUID(request_id))
            .values(offers_close_at=passed)
        )
        db.commit()
    # The manager's own list is the first read: it goes up, as the system, at the deadline.
    assert request_id in waiting_for(people, "chef")
    with people.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None and found.status == "pending"
        assert found.sent_up_at == passed
        event = db.scalars(select(AuditEvent).where(AuditEvent.action == "time_off.sent_up")).one()
        assert event.actor_type == "system" and event.details == {"by": "deadline"}
    # Offers are closed now, and sending it up again is refused.
    assert people.browser("ana").post(f"{URL}/{request_id}/send-up").status_code == 409


def test_the_employees_own_list_sends_it_up_before_filtering(people: ShiftSetup) -> None:
    # Review of #193: the employee's own list, filtered on "collecting", is the first read
    # after the deadline. It must not list the request as collecting: it goes up first,
    # so the filter sees "pending" (and the list filtered on "pending" has it).
    request_id, _ = setup_request(people)
    with people.db() as db:
        db.execute(
            update(TimeOffRequest)
            .where(TimeOffRequest.id == uuid.UUID(request_id))
            .values(offers_close_at=utcnow() - timedelta(minutes=1))
        )
        db.commit()
    ana = people.browser("ana")
    collecting = ana.get(URL, params={"mine": "true", "status": "collecting"})
    assert collecting.status_code == 200, collecting.text
    assert request_id not in [item["id"] for item in collecting.json()["items"]]
    assert stored_status(people, request_id) == "pending"
    pending = ana.get(URL, params={"mine": "true", "status": "pending"})
    assert request_id in [item["id"] for item in pending.json()["items"]]


def test_a_collecting_request_can_be_cancelled(people: ShiftSetup) -> None:
    request_id, _ = setup_request(people)
    response = people.browser("ana").post(f"{URL}/{request_id}/cancel")
    assert response.status_code == 200 and response.json()["status"] == "cancelled"


def test_a_collecting_request_never_sent_up_is_declined_as_not_reviewed(
    people: ShiftSetup,
) -> None:
    from app.approvals.models import ApprovalRequest

    request_id, _ = setup_request(people)
    passed = utcnow() - timedelta(minutes=1)
    with people.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        found.offers_close_at = passed
        approval = db.get(ApprovalRequest, found.approval_request_id)
        assert approval is not None
        approval.review_by = passed
        db.commit()
    answer = people.browser("ana").get(f"{URL}/{request_id}").json()
    assert answer["status"] == "denied" and answer["not_reviewed"] is True


# --- Who may offer (threat T8) ---------------------------------------------------------


def test_a_coworker_offers_to_cover_and_nothing_on_the_schedule_moves(
    people: ShiftSetup,
) -> None:
    request_id, shift = setup_request(people)
    response = offer(people, "cara", request_id, shift, "cover")
    assert response.status_code == 200, response.json()
    assert response.json()["answer"] == "cover" and response.json()["status"] == "offered"
    # Still ana's shift, and the request is still collecting.
    with people.db() as db:
        stored = db.get(Shift, uuid.UUID(shift))
        assert stored is not None and stored.employee_id == people.ids["ana"]
    assert stored_status(people, request_id) == "collecting"
    assert actions(people, "coverage.") == ["coverage.offered"]


def test_a_new_answer_replaces_the_old_one(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    assert offer(people, "cara", request_id, shift, "cover").status_code == 200
    assert offer(people, "cara", request_id, shift, "decline").status_code == 200
    with people.db() as db:
        stored = list(db.scalars(select(CoverageOffer)))
        assert [o.answer for o in stored] == ["decline"]
    assert actions(people, "coverage.") == ["coverage.offered", "coverage.offered"]


def test_someone_who_could_not_work_the_shift_cannot_offer(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    # dana lives in Front and is on no Kitchen team: the request is not hers to know about.
    assert offer(people, "dana", request_id, shift, "cover").status_code == 404
    assert offer(people, "dana", request_id, shift, "decline").status_code == 404
    assert people.browser("dana").get(f"{URL}/{request_id}").status_code == 403
    # ben lives in Front but is on the Weekend Crew in Kitchen: he may.
    assert offer(people, "ben", request_id, shift, "cover").status_code == 200


def test_the_employee_cannot_offer_on_their_own_request(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    response = offer(people, "ana", request_id, shift, "cover")
    assert response.status_code == 409
    assert people.browser("ana").get(f"{URL}/offerable").json()["items"] == []


def test_cover_is_refused_with_an_overlapping_shift(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    shift_for(people, "cara", 5, hour=11)  # overlaps ana's 9 to 3
    response = offer(people, "cara", request_id, shift, "cover")
    assert response.status_code == 409
    assert response.json()["detail"] == "You already have a shift at that time."
    with people.db() as db:
        assert list(db.scalars(select(CoverageOffer))) == []


def test_cover_is_refused_during_the_coworkers_own_time_off(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    # cara has day 5 off, approved by chef.
    response = people.browser("cara").post(URL, json=ask_body(5, 5, offers=False))
    assert response.status_code == 201
    own = response.json()["id"]
    assert people.browser("chef").post(f"{URL}/{own}/approve").status_code == 200
    response = offer(people, "cara", request_id, shift, "cover")
    assert response.status_code == 409
    assert response.json()["detail"] == "You have approved time off at that time."


def test_a_shift_not_on_the_request_cannot_be_answered(people: ShiftSetup) -> None:
    request_id, _ = setup_request(people)
    elsewhere = shift_for(people, "ana", 9)  # ana's, but not on the requested days
    assert offer(people, "cara", request_id, elsewhere, "cover").status_code == 404


# --- Swaps -----------------------------------------------------------------------------


def test_a_swap_with_the_coworkers_own_later_shift(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    given = shift_for(people, "cara", 8)
    response = offer(people, "cara", request_id, shift, "swap", given)
    assert response.status_code == 200, response.json()
    assert response.json()["swap_shift"]["id"] == given


def test_a_swap_needs_a_shift_given_and_only_a_swap_names_one(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    given = shift_for(people, "cara", 8)
    assert offer(people, "cara", request_id, shift, "swap").status_code == 422
    assert offer(people, "cara", request_id, shift, "cover", given).status_code == 422


def test_a_swap_with_someone_elses_shift_is_refused(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    chefs = shift_for(people, "chef", 8)
    response = offer(people, "cara", request_id, shift, "swap", chefs)
    assert response.status_code == 409
    assert "your own scheduled shifts" in response.json()["detail"]


def test_a_swap_with_a_shift_in_another_department_is_refused(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    fronts = shift_for(people, "ben", 8, dept="front")
    response = offer(people, "ben", request_id, shift, "swap", fronts)
    assert response.status_code == 409
    assert response.json()["detail"] == "The shift you give must be in the same department."


def test_a_swap_with_a_shift_during_the_time_off_is_refused(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    during = shift_for(people, "cara", 6)  # day 6 is one of ana's days off
    response = offer(people, "cara", request_id, shift, "swap", during)
    assert response.status_code == 409
    assert response.json()["detail"] == "The shift you give is during the time off."


def test_a_swap_the_employee_could_not_work_is_refused(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    given = shift_for(people, "cara", 8)
    shift_for(people, "ana", 8, hour=12)  # ana already works then
    response = offer(people, "cara", request_id, shift, "swap", given)
    assert response.status_code == 409
    assert response.json()["detail"] == "The person asking could not work the shift you give."


def test_a_swap_naming_another_companys_shift_is_invalid(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    theirs = people.new_shift(
        "b_chef", employee_id=people.ids["b_ana"], department_id=people.ids["b_kitchen"]
    )["id"]
    response = offer(people, "cara", request_id, shift, "swap", theirs)
    assert response.status_code == 422
    with people.db() as db:
        assert list(db.scalars(select(CoverageOffer))) == []


# --- Who sees what (threat I10) --------------------------------------------------------


def test_a_coworker_sees_only_their_own_answers(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    assert offer(people, "cara", request_id, shift, "cover").status_code == 200
    assert offer(people, "ben", request_id, shift, "decline").status_code == 200
    cara, ben = str(people.ids["cara"]), str(people.ids["ben"])
    assert offers_seen(people, "cara", request_id) == [(cara, "cover")]
    assert offers_seen(people, "ben", request_id) == [(ben, "decline")]
    # The employee and the manager see every offer.
    both = sorted([(cara, "cover"), (ben, "decline")])
    assert offers_seen(people, "ana", request_id) == both
    assert offers_seen(people, "chef", request_id) == both
    # The coworkers' cards list only their own answers too.
    card = people.browser("cara").get(f"{URL}/offerable").json()["items"]
    assert [item["request"]["id"] for item in card] == [request_id]
    assert [a["offered_by"] for a in card[0]["answers"]] == [cara]


def test_a_coworker_never_sees_the_reason(people: ShiftSetup) -> None:
    """Threat I10, review of #188: the reason for time off may be medical or otherwise
    personal, and a coworker needs only the days and the shifts to decide whether they can
    help. Every coworker answer leaves the field out entirely (not sent empty), on the card
    and on the request page, before and after they answer. The employee and the manager
    still see it."""
    shift = shift_for(people, "ana", 5)
    body = ask_body(5, 6) | {"reason": "hospital appointment"}
    made = people.browser("ana").post(URL, json=body)
    assert made.status_code == 201, made.json()
    request_id = made.json()["id"]
    cara = people.browser("cara")

    def coworker_answers() -> list[dict]:
        card = cara.get(f"{URL}/offerable").json()["items"]
        page = cara.get(f"{URL}/{request_id}")
        assert page.status_code == 200
        return [item["request"] for item in card] + [page.json()]

    seen = coworker_answers()
    assert offer(people, "cara", request_id, shift, "cover").status_code == 200
    seen += coworker_answers()[1:]  # after answering: the request page (the card too)
    for answer in seen:
        assert answer["id"] == request_id
        assert "reason" not in answer
        assert answer.get("decisions", []) == [] and answer.get("progress") is None
        assert "hospital" not in str(answer)
    # The employee and their manager still see why.
    for who in ("ana", "chef"):
        assert people.browser(who).get(f"{URL}/{request_id}").json()["reason"] == (
            "hospital appointment"
        )


def test_the_offerable_list_has_only_requests_you_could_answer(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    assert people.browser("dana").get(f"{URL}/offerable").json()["items"] == []
    items = people.browser("ben").get(f"{URL}/offerable").json()["items"]
    assert [item["request"]["id"] for item in items] == [request_id]
    assert [s["id"] for s in items[0]["shifts"]] == [shift]
    # Once it went up, it is no longer anyone's card.
    assert people.browser("ana").post(f"{URL}/{request_id}/send-up").status_code == 200
    assert people.browser("ben").get(f"{URL}/offerable").json()["items"] == []


# --- After it went up, and taking an answer back ---------------------------------------


def test_offers_close_when_it_goes_up(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    assert offer(people, "cara", request_id, shift, "cover").status_code == 200
    assert people.browser("ana").post(f"{URL}/{request_id}/send-up").status_code == 200
    assert offer(people, "cara", request_id, shift, "decline").status_code == 409
    assert offer(people, "ben", request_id, shift, "cover").status_code == 409
    url = f"{URL}/{request_id}/offers/{shift}"
    assert people.browser("cara").delete(url).status_code == 409
    # cara still sees her answer on the request, but not the reviewers' progress.
    page = people.browser("cara").get(f"{URL}/{request_id}").json()
    assert [o["answer"] for o in page["offers"]] == ["cover"]
    assert page["progress"] is None and page["decisions"] == []


def test_taking_an_answer_back(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    assert offer(people, "cara", request_id, shift, "cover").status_code == 200
    url = f"{URL}/{request_id}/offers/{shift}"
    assert people.browser("ben").delete(url).status_code == 404  # not his answer
    assert people.browser("cara").delete(url).status_code == 204
    assert people.browser("cara").delete(url).status_code == 404
    assert offers_seen(people, "ana", request_id) == []
    assert actions(people, "coverage.") == ["coverage.offered", "coverage.withdrawn"]


# --- Other companies (threats I1 and T3) -----------------------------------------------


def test_another_company_gets_404_everywhere(people: ShiftSetup) -> None:
    request_id, shift = setup_request(people)
    assert offer(people, "cara", request_id, shift, "cover").status_code == 200
    for who in ("b_ana", "b_chef"):
        client = people.browser(who)
        assert client.get(f"{URL}/{request_id}").status_code == 404
        assert client.post(f"{URL}/{request_id}/send-up").status_code == 404
        assert offer(people, who, request_id, shift, "cover").status_code == 404
        assert client.delete(f"{URL}/{request_id}/offers/{shift}").status_code == 404
        assert client.get(f"{URL}/offerable").json()["items"] == []
    with people.db() as db:
        assert len(list(db.scalars(select(CoverageOffer)))) == 1


def test_every_starting_role_may_offer(people: ShiftSetup) -> None:
    from app.authz.roles import _grants_for

    for built_in in ("owner", "administrator", "manager", "employee"):
        assert "coverage.respond_self" in _grants_for(built_in)
