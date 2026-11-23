"""Request and response shapes for time off (docs/features/time-off.md).

Requests forbid unknown fields, so a body cannot set a status, an employee, or an
approval record (threat T2): those only change through the rules in service.py.
"""

import uuid
from datetime import date, datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, Field, StringConstraints, model_validator

from app.modules.org.schemas import Strict

# An optional reason: surrounding spaces removed, at most 500 characters (the column).
# Shown as plain text only (threat T5): the interface never renders it as HTML.
Reason = Annotated[str, StringConstraints(strip_whitespace=True, max_length=500)]


class TimeOffCreate(Strict):
    """Whole days off, both included, in your workplace's time zone."""

    first_day: date
    last_day: date
    reason: Reason | None = None
    # "Offer Shift Swap / Coverage" (coverage.md): coworkers may answer before it goes up.
    offer_coverage: bool = False


class Step(BaseModel):
    """One reviewer's decision so far (names only; comments stay on the request page)."""

    approver_id: uuid.UUID
    approver_name: str
    decision: str  # approve or deny


class Person(BaseModel):
    id: uuid.UUID
    display_name: str


class Progress(BaseModel):
    """Where an open request stands."""

    decided: list[Step]  # oldest first
    waiting_for: list[Person]  # reviewers who have not decided yet, by name


class TimeOffSummary(BaseModel):
    """A request as a coworker asked to cover or swap sees it (coverage.md, threat I10):
    everything they need to decide whether they can take a shift, and no reason. The
    reason may be medical or otherwise personal, so it is not part of this shape at all
    (review of #188): a coworker's answer has no reason field, not an empty one."""

    id: uuid.UUID
    employee_id: uuid.UUID
    # Who asked, so the review screen names them without a lookup the reviewer may
    # not be allowed to make (#172). Anyone who may see the request may see this.
    employee_name: str
    first_day: date
    last_day: date
    status: str  # collecting, pending, escalated, approved, denied, cancelled
    not_reviewed: bool  # denied because nobody reviewed it before its first day
    created_at: datetime
    decided_at: datetime | None
    # Asked with offers (coverage.md): when it goes up by itself (null: asked without),
    # and when it went up (null while collecting).
    offers_close_at: datetime | None = None
    sent_up_at: datetime | None = None
    # While the request is open (pending or escalated): who has decided so far and who
    # still has to, so a request one manager already denied does not read as untouched.
    # None once it is settled. The employee already sees these decisions on the request.
    progress: Progress | None = None


class TimeOffOut(TimeOffSummary):
    """A request as its employee and its reviewers see it: with the reason."""

    reason: str | None


class AffectedShift(BaseModel):
    """One of the employee's shifts on the requested days."""

    id: uuid.UUID
    department_id: uuid.UUID
    starts_at: datetime
    ends_at: datetime


class Decision(BaseModel):
    """One reviewer's decision so far."""

    approver_id: uuid.UUID
    approver_name: str  # shown with the request only (#172)
    decision: str  # approve or deny
    decided_at: datetime
    comment: str | None  # plain text, as the reviewer wrote it


class OfferOut(BaseModel):
    """A coworker's answer about one shift (coverage.md). A coworker only ever gets their
    own; the employee and the managers get everyone's (threat I10)."""

    id: uuid.UUID
    shift_id: uuid.UUID  # the employee's shift it is about
    offered_by: uuid.UUID
    offered_by_name: str
    answer: str  # cover, swap, or decline
    swap_shift: AffectedShift | None  # for a swap: the coworker's shift given in exchange
    status: str  # offered, chosen, not_chosen, dropped
    updated_at: datetime


class TimeOffDetail(TimeOffOut):
    """One request, with the shifts it affects, the decisions so far, and the offers."""

    affected_shifts: list[AffectedShift]
    decisions: list[Decision]
    offers: list[OfferOut] = []


class CoworkerDetail(TimeOffSummary):
    """One request as a coworker asked to cover or swap sees it: the shifts it affects and
    only their own answers. No reason, and no progress (threat I10). decisions is always
    empty: it is kept so the shape matches TimeOffDetail apart from the reason."""

    affected_shifts: list[AffectedShift]
    decisions: list[Decision] = []
    offers: list[OfferOut] = []


class OfferBody(Strict):
    """A coworker's answer for one shift. A swap names the shift given; nothing else does."""

    answer: Literal["cover", "swap", "decline"]
    swap_shift_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _swap_shift_only_for_swaps(self) -> Self:
        if (self.answer == "swap") != (self.swap_shift_id is not None):
            raise ValueError("A swap names the shift you give, and only a swap does.")
        return self


class Offerable(BaseModel):
    """A coworker's card: a collecting request, the shifts they could take, their answers."""

    request: TimeOffSummary  # no reason: coworkers never see it
    shifts: list[AffectedShift]
    answers: list[OfferOut]


class OfferableList(BaseModel):
    items: list[Offerable]


class DecisionBody(Strict):
    """An optional comment with an approval or denial."""

    comment: Reason | None = None


class Choice(Strict):
    """One coworker's offer chosen for one of the request's shifts (coverage.md)."""

    shift_id: uuid.UUID
    offer_id: uuid.UUID


class ApproveBody(DecisionBody):
    """An approval: an optional comment, and the offers chosen (none, or one per shift).
    A request covers at most 30 days, so 100 choices is far more than any can need."""

    choices: list[Choice] = Field(default_factory=list, max_length=100)


class TimeOffList(BaseModel):
    items: list[TimeOffOut]
