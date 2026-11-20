"""The rules for seeing and deciding approval requests (authorization.md, delegation
limits; decisions 0029 and 0032).

Who sees a request: the person who asked, the person it is about, whoever decided it, and
whoever reviews it now. For anyone else it does not exist (404), so a request's ID tells an outsider
nothing.

Who decides: the reviewers its kind's handler names at that moment (app/approvals/), never
the requester or the person it is about (AZ7, AZ14). Deciding an admin-level request
needs the password entered again (decision 0025). Only the requester cancels.

A request past its deadline is declined as not reviewed the first time anyone reads or
acts on it (app/approvals/service.py, lapse), so it can never be approved late.

Decisions take turns with role, assignment, and reporting-line changes through the
company's lock (chain.lock_reporting_lines); after it, the request is read fresh and
locked, and the reviewers are worked out on fresh reads.
"""

import uuid
from typing import Literal

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalDecision, ApprovalRequest
from app.approvals.service import (
    DecisionError,
    cancel,
    decide,
    handler_for,
    lapse,
    may_decide,
    waits_for,
)
from app.auth.models import UserSession
from app.auth.reauth import require_reauth
from app.authz.chain import lock_reporting_lines
from app.authz.check import Forbidden
from app.modules.org.models import User
from app.modules.org.service import Conflict, NotFound

NOT_REVIEWED = "Nobody reviewed this request in time, so it was declined. Ask again."


def _involved(db: Session, user: User, request: ApprovalRequest) -> bool:
    """Whether the user may see the request: they asked, it is about them, they decided
    it, or they are among its reviewers now (whether or not it is still pending, so a
    reviewer gets "no longer pending" rather than "not found" once it is decided)."""
    if user.id in (request.requested_by, request.subject_user_id):
        return True
    if db.get(ApprovalDecision, (request.id, user.id)) is not None:
        return True
    return user.id in handler_for(request).reviewers(db, request)


def _lapse_all(db: Session, requests: list[ApprovalRequest]) -> None:
    """Decline the overdue ones as not reviewed, and save that at once."""
    if any([lapse(db, request) for request in requests]):
        db.commit()


# --- Seeing requests -------------------------------------------------------------------


def list_requests(
    db: Session, user: User, *, view: Literal["mine", "to_review"], limit: int
) -> list[ApprovalRequest]:
    """The newest requests the user asked for or that are about them ("mine"), or the
    pending ones still waiting for the user's decision ("to_review")."""
    if view == "mine":
        rows = list(
            db.scalars(
                select(ApprovalRequest)
                .where(
                    or_(
                        ApprovalRequest.requested_by == user.id,
                        ApprovalRequest.subject_user_id == user.id,
                    )
                )
                .order_by(ApprovalRequest.created_at.desc(), ApprovalRequest.id.desc())
                .limit(limit)
            )
        )
        _lapse_all(db, rows)
        return rows
    pending = list(
        db.scalars(
            select(ApprovalRequest)
            .where(ApprovalRequest.status == "pending")
            .order_by(ApprovalRequest.created_at, ApprovalRequest.id)
        )
    )
    _lapse_all(db, pending)
    # Only the ones still waiting for this person: a request they already decided, still
    # pending for the other reviewers, is not listed again.
    return [request for request in pending if waits_for(db, user, request)][:limit]


def view_request(db: Session, user: User, request_id: uuid.UUID) -> ApprovalRequest:
    request = db.get(ApprovalRequest, request_id)
    if request is None or not _involved(db, user, request):
        raise NotFound()
    _lapse_all(db, [request])
    return request


# --- Deciding --------------------------------------------------------------------------


def _locked(db: Session, user: User, request_id: uuid.UUID) -> ApprovalRequest:
    """The request, after the company's lock, read fresh and locked; 404 for anyone not
    involved; 409 (after saving the lapse) if it ran out of time meanwhile."""
    found = db.get(ApprovalRequest, request_id)
    if found is None or not _involved(db, user, found):
        raise NotFound()
    lock_reporting_lines(db)
    request = db.get(ApprovalRequest, request_id, populate_existing=True, with_for_update=True)
    if request is None:  # requests are never deleted
        raise NotFound()
    if lapse(db, request):
        db.commit()
        raise Conflict(NOT_REVIEWED)
    if request.status != "pending":
        raise Conflict("This request is no longer pending.")
    return request


def _decide(
    db: Session, user: User, request_id: uuid.UUID, decision: str, session: UserSession
) -> ApprovalRequest:
    request = _locked(db, user, request_id)
    if request.kind == "time_off":
        # Decided on its own endpoints, which lock the employee and their shifts first
        # (app/modules/time_off/service.py): deciding here would take them in another order.
        raise Conflict("Time-off requests are reviewed on the time-off page.")
    if not may_decide(db, user, request):
        raise Forbidden()  # involved (they asked, or it is about them), but not a reviewer
    if handler_for(request).sensitive(db, request):
        require_reauth(session)
    try:
        decide(db, user, request, decision)
    except DecisionError as error:
        db.rollback()
        raise Conflict(str(error)) from error
    db.commit()
    return request


def approve(
    db: Session, user: User, request_id: uuid.UUID, *, session: UserSession
) -> ApprovalRequest:
    return _decide(db, user, request_id, "approve", session)


def deny(
    db: Session, user: User, request_id: uuid.UUID, *, session: UserSession
) -> ApprovalRequest:
    return _decide(db, user, request_id, "deny", session)


def cancel_request(db: Session, user: User, request_id: uuid.UUID) -> ApprovalRequest:
    request = _locked(db, user, request_id)
    if request.requested_by != user.id:
        raise Forbidden()  # only the requester takes a request back
    try:
        cancel(db, user, request)
    except DecisionError as error:
        raise Conflict(str(error)) from error
    db.commit()
    return request
