"""Choosing coworkers' offers when approving time off (docs/features/coverage.md, slice
CV2; threats E12, E3, E5, T2), through the real app.

Each test is a reviewer choosing what the rules refuse (their own offer, a shift they may
not edit, an offer that no longer works), or approving and declining, and checks what
really happened to the shifts, the offers, and the audit log.

People (tests/people_data.py): chef manages Kitchen (ana, cara) and reviews ana's time
off; ben is on the Weekend Crew in Kitchen; lead manages the crew. In most tests ana asks
for days 5 and 6 with offers, with Kitchen shifts on both days; the coworkers answer, and
ana sends it up.
"""

import uuid
from typing import Any

from sqlalchemy import delete, select, update

from app.audit.models import AuditEvent
from app.authz.models import Role, RolePermission
from app.db.base import utcnow
from app.modules.org.models import TeamMember, User
from app.modules.schedules.models import Shift
from app.modules.time_off.models import CoverageOffer, TimeOffRequest
from tests.people_data import actions, people
from tests.security.test_coverage_offers import URL, ask, offer, shift_for, stored_status
from tests.security.test_time_off_review import also_reports_to, needs_two
from tests.shift_data import ShiftSetup, shifts

__all__ = ["people", "shifts"]  # the fixtures, imported so pytest finds them here


class Case:
    """ana's request with two shifts, offers from cara (cover, day 5) and ben (swap with
    his day-8 Kitchen shift, day 6), sent up and waiting for chef."""

    def __init__(self, setup: ShiftSetup) -> None:
        self.setup = setup
        self.day5 = shift_for(setup, "ana", 5)
        self.day6 = shift_for(setup, "ana", 6)
        self.ben8 = shift_for(setup, "ben", 8)
        self.request = ask(setup.browser("ana"))
        self.cover = self._offer("cara", self.day5, "cover")
        self.swap = self._offer("ben", self.day6, "swap", self.ben8)

    def _offer(self, who: str, shift: str, answer: str, swap: str | None = None) -> str:
        response = offer(self.setup, who, self.request, shift, answer, swap)
        assert response.status_code == 200, response.json()
        return response.json()["id"]

    def send_up(self) -> None:
        url = f"{URL}/{self.request}/send-up"
        assert self.setup.browser("ana").post(url).status_code == 200

    def approve(self, who: str = "chef", **choices: str) -> Any:
        """Approve with {shift ID: offer ID} choices; the response."""
        body = {"choices": [{"shift_id": s, "offer_id": o} for s, o in choices.items()]}
        return self.setup.browser(who).post(f"{URL}/{self.request}/approve", json=body)


def holder(setup: ShiftSetup, shift_id: str) -> tuple[uuid.UUID | None, str]:
    """Who has the shift now, and its status."""
    with setup.db() as db:
        found = db.get(Shift, uuid.UUID(shift_id))
        assert found is not None
        return found.employee_id, found.status


def offer_statuses(setup: ShiftSetup) -> dict[str, str]:
    with setup.db() as db:
        return {str(o.id): o.status for o in db.scalars(select(CoverageOffer))}


def make_case(people: ShiftSetup, send_up: bool = True) -> Case:
    case = Case(people)
    if send_up:
        case.send_up()
    return case


# --- Applying the chosen offers ---------------------------------------------------------


def test_a_chosen_cover_moves_the_shift_and_the_rest_open(people: ShiftSetup) -> None:
    case = make_case(people)
    response = case.approve(**{case.day5: case.cover})
    assert response.status_code == 200, response.json()
    assert holder(people, case.day5) == (people.ids["cara"], "scheduled")
    assert holder(people, case.day6) == (None, "open")  # not chosen: opened as before
    assert holder(people, case.ben8) == (people.ids["ben"], "scheduled")
    assert offer_statuses(people) == {case.cover: "chosen", case.swap: "not_chosen"}
    with people.db() as db:
        assigned = db.scalars(select(AuditEvent).where(AuditEvent.action == "shift.assigned")).all()
        # One from making the shifts per shift, then the move.
        moved = [e for e in assigned if e.details.get("offer_id")]
        assert [(str(e.target_id), e.details["offer_id"]) for e in moved] == [
            (case.day5, case.cover)
        ]
        approved = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "time_off.approved")
        ).one()
        assert approved.details == {"chosen_offers": [case.cover]}


def test_a_chosen_swap_trades_the_two_shifts(people: ShiftSetup) -> None:
    case = make_case(people)
    response = case.approve(**{case.day6: case.swap})
    assert response.status_code == 200, response.json()
    assert holder(people, case.day6) == (people.ids["ben"], "scheduled")
    assert holder(people, case.ben8) == (people.ids["ana"], "scheduled")
    assert holder(people, case.day5) == (None, "open")


def test_approving_without_choices_opens_every_shift(people: ShiftSetup) -> None:
    case = make_case(people)
    response = people.browser("chef").post(f"{URL}/{case.request}/approve")
    assert response.status_code == 200
    assert holder(people, case.day5) == (None, "open")
    assert holder(people, case.day6) == (None, "open")
    assert offer_statuses(people) == {case.cover: "not_chosen", case.swap: "not_chosen"}


def test_nothing_moves_before_approval(people: ShiftSetup) -> None:
    case = make_case(people)
    assert holder(people, case.day5) == (people.ids["ana"], "scheduled")
    assert holder(people, case.ben8) == (people.ids["ben"], "scheduled")


# --- Endings ------------------------------------------------------------------------------


def test_declining_drops_the_offers(people: ShiftSetup) -> None:
    case = make_case(people)
    assert people.browser("chef").post(f"{URL}/{case.request}/deny").status_code == 200
    assert offer_statuses(people) == {case.cover: "dropped", case.swap: "dropped"}
    assert holder(people, case.day5) == (people.ids["ana"], "scheduled")


def test_cancelling_drops_the_offers(people: ShiftSetup) -> None:
    case = make_case(people, send_up=False)
    assert people.browser("ana").post(f"{URL}/{case.request}/cancel").status_code == 200
    assert offer_statuses(people) == {case.cover: "dropped", case.swap: "dropped"}


def test_not_reviewed_in_time_drops_the_offers(people: ShiftSetup) -> None:
    from app.approvals.models import ApprovalRequest

    case = make_case(people)
    with people.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(case.request))
        assert found is not None
        approval = db.get(ApprovalRequest, found.approval_request_id)
        assert approval is not None
        approval.review_by = utcnow()
        db.commit()
    assert stored_status(people, case.request) == "pending"
    people.browser("ana").get(f"{URL}/{case.request}")  # the read that notices
    assert offer_statuses(people) == {case.cover: "dropped", case.swap: "dropped"}


# --- Who may choose what (threat E12) ------------------------------------------------------


def test_a_reviewer_cannot_choose_their_own_offer(people: ShiftSetup) -> None:
    case = make_case(people, send_up=False)
    # chef lives in Kitchen and may offer too: he offers to cover day 5 himself.
    own = case._offer("chef", case.day5, "cover")
    case.send_up()
    response = case.approve(**{case.day5: own})
    assert response.status_code == 403
    assert stored_status(people, case.request) == "pending"
    assert holder(people, case.day5) == (people.ids["ana"], "scheduled")


def test_choosing_needs_schedule_edit_over_the_moved_shifts(people: ShiftSetup) -> None:
    case = make_case(people)
    # The Manager role keeps time_off.review but loses schedule.edit.
    with people.db() as db:
        manager = db.scalars(select(Role).where(Role.built_in == "manager")).one()
        db.execute(
            delete(RolePermission).where(
                RolePermission.role_id == manager.id,
                RolePermission.permission_code == "schedule.edit",
            )
        )
        db.commit()
    response = case.approve(**{case.day5: case.cover})
    assert response.status_code == 403
    assert stored_status(people, case.request) == "pending"
    assert holder(people, case.day5) == (people.ids["ana"], "scheduled")
    assert offer_statuses(people) == {case.cover: "offered", case.swap: "offered"}
    # Approving without choices needs only what time off needs.
    assert people.browser("chef").post(f"{URL}/{case.request}/approve").status_code == 200


def test_choices_sent_with_an_approval_that_does_not_settle_never_apply(
    people: ShiftSetup,
) -> None:
    # Two approvals needed: ana also reports to lead and joins his Weekend Crew, so chef
    # and lead both review her.
    with people.db() as db:
        db.add(TeamMember(team_id=people.ids["crew"], user_id=people.ids["ana"]))
        db.commit()
    needs_two(people)
    also_reports_to(people, "ana", "lead")
    case = make_case(people)
    assert case.approve(**{case.day5: case.cover}).status_code == 200
    assert holder(people, case.day5) == (people.ids["ana"], "scheduled")  # not yet
    # lead settles it without choices: chef's choice does not apply.
    assert people.browser("lead").post(f"{URL}/{case.request}/approve").status_code == 200
    assert stored_status(people, case.request) == "approved"
    assert holder(people, case.day5) == (None, "open")
    assert offer_statuses(people)[case.cover] == "not_chosen"


def test_choices_must_be_offers_for_that_shift(people: ShiftSetup) -> None:
    case = make_case(people)
    # The cover offer was for day 5, not day 6.
    assert case.approve(**{case.day6: case.cover}).status_code == 422
    # An unknown offer, and a shift that is not the request's.
    assert case.approve(**{case.day5: str(uuid.uuid4())}).status_code == 422
    assert case.approve(**{case.ben8: case.swap}).status_code == 422
    assert stored_status(people, case.request) == "pending"


def test_a_declined_answer_cannot_be_chosen(people: ShiftSetup) -> None:
    case = make_case(people, send_up=False)
    no = case._offer("cara", case.day6, "decline")
    case.send_up()
    assert case.approve(**{case.day6: no}).status_code == 422


def test_a_body_cannot_set_offer_statuses(people: ShiftSetup) -> None:
    case = make_case(people)
    body = {"choices": [{"shift_id": case.day5, "offer_id": case.cover, "status": "chosen"}]}
    response = people.browser("chef").post(f"{URL}/{case.request}/approve", json=body)
    assert response.status_code == 422


def test_another_companys_reviewer_cannot_choose(people: ShiftSetup) -> None:
    case = make_case(people)
    assert case.approve("b_chef", **{case.day5: case.cover}).status_code == 404
    assert holder(people, case.day5) == (people.ids["ana"], "scheduled")


# --- The re-check at approval ---------------------------------------------------------------


def refused(case: Case, choices: dict[str, str]) -> str:
    """Approving with these choices is 409; nothing changed; the message."""
    setup = case.setup
    before = actions(setup, "time_off.approved")
    response = case.approve(**choices)
    assert response.status_code == 409, response.json()
    assert stored_status(setup, case.request) == "pending"
    assert holder(setup, case.day5) == (setup.ids["ana"], "scheduled")
    assert holder(setup, case.day6) == (setup.ids["ana"], "scheduled")
    assert actions(setup, "time_off.approved") == before
    return response.json()["detail"]


def test_the_recheck_refuses_a_deactivated_coworker(people: ShiftSetup) -> None:
    case = make_case(people)
    with people.db() as db:
        db.execute(
            update(User).where(User.id == people.ids["cara"]).values(deactivated_at=utcnow())
        )
        db.commit()
    message = refused(case, {case.day5: case.cover})
    assert "can no longer be assigned" in message and "Choose another offer" in message


def test_the_recheck_refuses_a_coworker_now_busy(people: ShiftSetup) -> None:
    case = make_case(people)
    shift_for(people, "cara", 5, hour=10)
    assert "another shift at that time" in refused(case, {case.day5: case.cover})


def test_the_recheck_refuses_a_coworker_now_away(people: ShiftSetup) -> None:
    case = make_case(people)
    response = people.browser("cara").post(
        URL,
        json={
            "first_day": stored_first_day(people, case.request),
            "last_day": stored_first_day(people, case.request),
        },
    )
    assert response.status_code == 201
    own = response.json()["id"]
    assert people.browser("chef").post(f"{URL}/{own}/approve").status_code == 200
    assert "approved time off" in refused(case, {case.day5: case.cover})


def test_the_recheck_refuses_a_swap_shift_moved_meanwhile(people: ShiftSetup) -> None:
    case = make_case(people)
    # The owner gives ben's day-8 shift to cara.
    moved = people.browser("owner").post(
        f"/api/shifts/{case.ben8}/assign", json={"employee_id": str(people.ids["cara"])}
    )
    assert moved.status_code == 200, moved.json()
    assert "no longer theirs to give" in refused(case, {case.day6: case.swap})


def stored_first_day(setup: ShiftSetup, request_id: str) -> str:
    with setup.db() as db:
        found = db.get(TimeOffRequest, uuid.UUID(request_id))
        assert found is not None
        return found.first_day.isoformat()


# --- The new assignments are checked too (#209) -----------------------------------------


def test_choosing_cannot_hand_a_shift_to_someone_outside_the_reviewers_scope(
    people: ShiftSetup,
) -> None:
    # lead manages the Weekend Crew (team scope) and is ben's manager, so lead reviews
    # ben's time off and may edit ben's Kitchen shift. cara works in Kitchen but is not on
    # the crew: lead may not give her a shift. Choosing her cover would do just that, so
    # it is refused (403), the same rule as assigning (#183), and nothing changes.
    day5 = shift_for(people, "ben", 5)
    request = ask(people.browser("ben"))
    answered = offer(people, "cara", request, day5, "cover")
    assert answered.status_code == 200, answered.json()
    cover = answered.json()["id"]
    sent = people.browser("ben").post(f"{URL}/{request}/send-up")
    assert sent.status_code == 200, sent.json()
    body = {"choices": [{"shift_id": day5, "offer_id": cover}]}
    response = people.browser("lead").post(f"{URL}/{request}/approve", json=body)
    assert response.status_code == 403, response.json()
    assert stored_status(people, request) == "pending"
    assert holder(people, day5) == (people.ids["ben"], "scheduled")
    assert offer_statuses(people) == {cover: "offered"}
    # Approving without choosing her offer is still lead's to do.
    assert people.browser("lead").post(f"{URL}/{request}/approve").status_code == 200
