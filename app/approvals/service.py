"""Opening and deciding approval requests (authorization.md, delegation limits; 0029).

A feature that needs approval from above calls open_request() instead of making the
change. The request grants nothing while it is pending. Then:

- approve():  a reviewer agrees. Once it has `required_approvals` approvals, the request
              is approved and its kind's handler makes the change, in the same transaction.
- deny():     a reviewer refuses; one denial is enough (data-model.md, approval_decisions).
- cancel():   the requester takes it back.
- lapse():    nobody decided by review_by: it is declined as "not reviewed", and the audit
              log says so (decision 0032). This happens the next time anyone reads or
              acts on the request, so no background job is needed: nothing can approve a
              lapsed request, because every decision lapses it first. Its decided_at is
              the deadline itself; the audit entry is written when it is noticed.

What a kind of request does, and who may review it, is up to the feature that owns the
kind: it registers a Handler (register_handler), as roles do for "role_assignment"
(app/modules/roles/approval.py). Who may decide is worked out again at the moment of each
decision, never stored, so a reviewer who lost their role or their place above the
requester since the request was opened can no longer decide it.

Rules for everyone (AZ7, AZ14): nobody decides a request they made, or one about
themselves; each person decides a request once (the decisions table's key).
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import KINDS, ApprovalDecision, ApprovalRequest
from app.audit import Actor, record
from app.db.base import utcnow
from app.modules.org.models import User

# A role grant, owner change, or account change nobody decides within this long is
# declined as not reviewed (decision 0032). Other kinds set their own deadline.
REVIEW_WITHIN = timedelta(days=7)


class DecisionError(ValueError):
    """A decision that the request's state does not allow (the caller answers 409)."""


@dataclass(frozen=True)
class Handler:
    """What one kind of request needs from the feature that owns it.

    reviewers(db, request): the IDs of everyone who may decide it now (fresh reads).
    sensitive(db, request): whether deciding it needs the password entered again.
    apply(db, request, approver): make the change once approved; raise DecisionError if
        it can no longer be made (say, the role was archived meanwhile).
    describe(db, request): what the audit entries show about it (no personal data).
    lapsed(db, request): called when the request is declined as not reviewed, so the
        feature can update its own record too (time off marks its request denied).
    """

    reviewers: Callable[[Session, ApprovalRequest], set[uuid.UUID]]
    sensitive: Callable[[Session, ApprovalRequest], bool]
    apply: Callable[[Session, ApprovalRequest, User], None]
    describe: Callable[[Session, ApprovalRequest], dict[str, Any]]
    lapsed: Callable[[Session, ApprovalRequest], None] | None = None


_handlers: dict[str, Handler] = {}


def register_handler(kind: str, handler: Handler) -> None:
    """Called once by the feature that owns the kind, when its module is imported."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind of approval request {kind!r}")
    _handlers[kind] = handler


def handler_for(request: ApprovalRequest) -> Handler:
    """The handler of the request's kind. A kind without one is a bug, so it raises."""
    try:
        return _handlers[request.kind]
    except KeyError:
        raise LookupError(f"no handler for approval requests of kind {request.kind!r}") from None


# --- Opening ---------------------------------------------------------------------------


def pending_like(
    db: Session, kind: str, subject_user_id: uuid.UUID, payload: dict[str, Any]
) -> ApprovalRequest | None:
    """A pending request of this kind, about this person, asking for the same thing; read
    fresh (FOR SHARE), for callers holding the company's lock. Used to refuse asking twice."""
    rows = db.scalars(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.kind == kind,
            ApprovalRequest.subject_user_id == subject_user_id,
            ApprovalRequest.status == "pending",
        )
        .with_for_update(read=True)
    )
    return next((row for row in rows if row.payload == payload and not _overdue(row)), None)


def open_request(
    db: Session,
    *,
    kind: str,
    requested_by: uuid.UUID,
    subject_user_id: uuid.UUID,
    payload: dict[str, Any],
    details: dict[str, Any],
    required_approvals: int = 1,
    review_by: datetime | None = None,
) -> ApprovalRequest:
    """Record a request waiting for approval, with its audit entry; the caller commits.

    `payload` is what happens on approval (kept with the request); `details` is what the
    audit entry shows about it (for a role: its name and scope). `review_by` is the
    deadline, 7 days from now unless the kind sets its own (time off: its first day).
    """
    if kind not in KINDS:
        raise ValueError(f"unknown kind of approval request {kind!r}")
    request = ApprovalRequest(
        kind=kind,
        requested_by=requested_by,
        subject_user_id=subject_user_id,
        payload=payload,
        status="pending",
        required_approvals=required_approvals,
        review_by=review_by if review_by is not None else utcnow() + REVIEW_WITHIN,
        not_reviewed=False,
    )
    db.add(request)
    db.flush()  # gives the request its ID for the audit entry
    record(
        db,
        actor=Actor.user(requested_by),
        action="approval.requested",
        target_type="approval_request",
        target_id=request.id,
        details={"kind": kind, "subject_user_id": str(subject_user_id), **details},
    )
    return request


# --- Lapsing ---------------------------------------------------------------------------


def _overdue(request: ApprovalRequest) -> bool:
    return request.status == "pending" and request.review_by <= utcnow()


def lapse(db: Session, request: ApprovalRequest) -> bool:
    """Decline the request as not reviewed if its deadline has passed; audited, as the
    system. Returns whether it lapsed now. The caller commits."""
    if not _overdue(request):
        return False
    request.status = "denied"
    request.not_reviewed = True
    # Declined at the deadline, not at the moment someone happened to look: the history
    # then shows exactly when the request ran out of time.
    request.decided_at = request.review_by
    record(
        db,
        actor=Actor.system(),
        action="approval.not_reviewed",
        target_type="approval_request",
        target_id=request.id,
        details={"kind": request.kind, **handler_for(request).describe(db, request)},
    )
    hook = handler_for(request).lapsed
    if hook is not None:
        hook(db, request)
    return True


# --- Deciding --------------------------------------------------------------------------


def may_decide(db: Session, user: User, request: ApprovalRequest) -> bool:
    """Whether the user may approve or deny the request right now (fresh reads)."""
    if request.status != "pending" or _overdue(request):
        return False
    if user.id in (request.requested_by, request.subject_user_id):
        return False  # nobody decides their own request, or one about themselves
    if user.deactivated_at is not None:
        return False
    return user.id in handler_for(request).reviewers(db, request)


def decide(db: Session, user: User, request: ApprovalRequest, decision: str) -> None:
    """Record the user's approval or denial (the caller has checked may_decide and taken
    the company's lock). One denial denies; enough approvals approve and apply it."""
    already = db.get(ApprovalDecision, (request.id, user.id))
    if already is not None:
        raise DecisionError("You have already decided this request.")
    now = utcnow()
    db.add(
        ApprovalDecision(
            request_id=request.id,
            approver_type="user",
            approver_id=user.id,
            decision=decision,
            decided_at=now,
        )
    )
    details = {"kind": request.kind, **handler_for(request).describe(db, request)}
    if decision == "deny":
        request.status, request.decided_at = "denied", now
        record(
            db,
            actor=Actor.user(user.id),
            action="approval.denied",
            target_type="approval_request",
            target_id=request.id,
            details=details,
        )
        return

    db.flush()  # the decision is counted below
    approvals = db.scalars(
        select(ApprovalDecision.approver_id).where(
            ApprovalDecision.request_id == request.id, ApprovalDecision.decision == "approve"
        )
    ).all()
    if len(approvals) < request.required_approvals:
        return  # more approvals needed; it stays pending
    # Approved: the change is made in this same transaction, so either both happen or
    # neither does.
    handler_for(request).apply(db, request, user)
    request.status, request.decided_at = "approved", now
    record(
        db,
        actor=Actor.user(user.id),
        action="approval.approved",
        target_type="approval_request",
        target_id=request.id,
        details=details,
    )


def cancel(db: Session, user: User, request: ApprovalRequest) -> None:
    """The requester takes back a pending request; audited. The caller commits."""
    if request.requested_by != user.id:
        raise PermissionError("only the requester cancels a request")
    if request.status != "pending":
        raise DecisionError("This request is no longer pending.")
    request.status, request.decided_at = "cancelled", utcnow()
    record(
        db,
        actor=Actor.user(user.id),
        action="approval.cancelled",
        target_type="approval_request",
        target_id=request.id,
        details={"kind": request.kind, **handler_for(request).describe(db, request)},
    )
