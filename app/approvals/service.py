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
              the deadline itself; the audit entry is written when it is noticed. Two
              requests noticing it at once lapse it only once.

What a kind of request does, and who may review it, is up to the feature that owns the
kind: it registers a Handler (register_handler), as roles do for "role_assignment"
(app/modules/roles/approval.py). Who may decide is worked out again at the moment of each
decision, never stored, so a reviewer who lost their role or their place above the
requester since the request was opened can no longer decide it.

Rules for everyone (AZ7, AZ14): nobody decides a request they made, or one about
themselves; each person decides a request once (the decisions table's key).

Fresh reads (review of #163): a decision waits for the company's lock, and under MySQL's
REPEATABLE READ an ordinary read after that wait still answers from the transaction's old
snapshot. So after the lock, may_decide(fresh=True) reads the decider and asks the handler
for its reviewers with fresh=True (locking reads), and decide() reads the decisions made so
far with locking reads too, so one committed meanwhile by another reviewer is counted.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import select, update
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


class Reviewers(Protocol):
    """A handler's reviewers(): who may decide the request now. fresh=True is asked after
    the company's lock, and then every read must be a locking read (the top of this file);
    without it, ordinary reads (lists and pages, which must not wait on row locks)."""

    # db and the request are positional-only (the "/"), so each handler may name them as
    # it likes (time off calls the request "approval").
    def __call__(
        self, db: Session, request: ApprovalRequest, /, *, fresh: bool = False
    ) -> set[uuid.UUID]: ...


@dataclass(frozen=True)
class Handler:
    """What one kind of request needs from the feature that owns it.

    reviewers(db, request, fresh=...): the IDs of everyone who may decide it now.
    sensitive(db, request): whether deciding it needs the password entered again (asked
        only after the company's lock, so it reads fresh).
    apply(db, request, approver): make the change once approved; raise DecisionError if
        it can no longer be made (say, the role was archived meanwhile). Runs after the
        company's lock, so it reads fresh.
    describe(db, request): what the audit entries show about it (no personal data).
    lapsed(db, request): called when the request is declined as not reviewed, so the
        feature can update its own record too (time off marks its request denied).
    outcome(db, request): for kinds with their own rule instead of "one denial denies,
        enough approvals approve": called after each decision is recorded, it answers
        "approved", "denied", or None (still waiting). Time off uses it to send a
        disagreement up the chain instead of deciding it.
    ready(db, request, approvers): whether the approvals so far are enough. Without it,
        `required_approvals` approvals are enough; owner changes instead need every
        current reviewer, worked out again now, so an owner added meanwhile must agree too.
    """

    reviewers: Reviewers
    sensitive: Callable[[Session, ApprovalRequest], bool]
    apply: Callable[[Session, ApprovalRequest, User], None]
    describe: Callable[[Session, ApprovalRequest], dict[str, Any]]
    lapsed: Callable[[Session, ApprovalRequest], None] | None = None
    outcome: Callable[[Session, ApprovalRequest], str | None] | None = None
    ready: Callable[[Session, ApprovalRequest, set[uuid.UUID]], bool] | None = None


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
    system. Returns whether it lapsed now. The caller commits.

    Safe when two requests notice the same overdue request at the same moment (two
    people opening their lists, say): only one of them lapses it, so there is one audit
    entry and the hook runs once. The caller's copy may be old (read without a lock), so
    the change is made by one UPDATE that only matches while the request is still
    pending and overdue. The database runs that against the newest committed row and
    makes a second UPDATE wait for the first to finish; the second then matches nothing
    and answers "not now". Either way the copy is then read again with a locking read,
    so it shows what was committed, not this transaction's old snapshot (reviews of
    #163 and #166).
    """
    # 1. The quick answer from the copy we have: not overdue means nothing to do.
    if not _overdue(request):
        return False
    # 2. Claim it: one conditional UPDATE. Declined at the deadline, not at the moment
    #    someone happened to look, so the history shows exactly when it ran out of time.
    claimed = db.execute(
        update(ApprovalRequest)
        .where(
            ApprovalRequest.id == request.id,
            ApprovalRequest.status == "pending",
            ApprovalRequest.review_by <= utcnow(),
        )
        .values(status="denied", not_reviewed=True, decided_at=ApprovalRequest.review_by)
        .execution_options(synchronize_session=False)
    )
    # 3. The copy is read again, so it shows the database's state either way. A locking
    #    read (FOR SHARE): under MySQL's REPEATABLE READ an ordinary read answers from this
    #    transaction's old snapshot, so the request that lost the race would still see
    #    "pending" after the winner committed the denial. A locking read sees the newest
    #    committed row (review of #166).
    db.refresh(request, with_for_update={"read": True})
    if claimed.rowcount != 1:  # type: ignore[attr-defined]
        return False  # someone else lapsed or decided it first: nothing more to do
    # 4. Only the request that claimed it writes the audit entry and runs the hook.
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


def may_decide(db: Session, user: User, request: ApprovalRequest, *, fresh: bool = False) -> bool:
    """Whether the user may approve or deny the request right now. fresh=True after the
    company's lock: the user and the reviewers are read with locking reads, so a reviewer
    deactivated or stripped of their role while the decision waited cannot decide."""
    if request.status != "pending" or _overdue(request):
        return False
    if user.id in (request.requested_by, request.subject_user_id):
        return False  # nobody decides their own request, or one about themselves
    if fresh:
        db.refresh(user, with_for_update={"read": True})
    if user.deactivated_at is not None:
        return False
    return user.id in handler_for(request).reviewers(db, request, fresh=fresh)


def has_decided(db: Session, user: User, request: ApprovalRequest) -> bool:
    """Whether the user has already approved or denied this request."""
    # The decisions table is keyed by (request, person), so this is one primary-key read.
    return db.get(ApprovalDecision, (request.id, user.id)) is not None


def waits_for(db: Session, user: User, request: ApprovalRequest) -> bool:
    """Whether the request still needs the user's decision: what the "waiting for you"
    lists and counts show.

    A request that needs several reviewers stays pending after one of them decides, while
    it waits for the others. That reviewer is still one of its reviewers (may_decide), but
    a second decision would be refused (decide(): "You have already decided this
    request."), so it must not be listed as waiting for them. may_decide() itself stays as
    it is: the decision endpoints use it to answer 403 for someone who is not a reviewer
    at all, and leave the clearer "already decided" (409) to decide().
    """
    # Step 1: everything may_decide() checks (pending, in time, not their own, active, a
    # reviewer). Step 2: and they have not decided it yet.
    return may_decide(db, user, request) and not has_decided(db, user, request)


def decide(db: Session, user: User, request: ApprovalRequest, decision: str) -> None:
    """Record the user's approval or denial (the caller has checked may_decide and taken
    the company's lock). One denial denies; enough approvals approve and apply it. A kind
    with its own outcome rule (Handler.outcome) decides that instead."""
    # Locking reads (FOR SHARE) for the decisions so far: one another reviewer committed
    # while this request waited for the lock must be seen, or a second decision by the
    # same person would hit the table's key (a 500) and a count would come up short.
    already = db.get(
        ApprovalDecision,
        (request.id, user.id),
        with_for_update={"read": True},
        populate_existing=True,
    )
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
    rule = handler_for(request).outcome
    if rule is not None:
        db.flush()  # the kind's rule reads this decision with the others
        result = rule(db, request)
        if result is None:
            return  # still waiting (or sent up the chain)
        decision = "deny" if result == "denied" else "approve"
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

    handler = handler_for(request)
    if rule is None:
        # The usual rule: enough approvals approve. A kind with its own rule (time off)
        # has already decided above, so it skips this count.
        db.flush()  # the decision is counted below
        # A locking read (FOR SHARE), so approvals another reviewer committed while this
        # request waited for the lock are counted (review of #163).
        approvals = set(
            db.scalars(
                select(ApprovalDecision.approver_id)
                .where(
                    ApprovalDecision.request_id == request.id,
                    ApprovalDecision.decision == "approve",
                )
                .with_for_update(read=True)
            )
        )
        enough = (
            handler.ready(db, request, approvals)
            if handler.ready is not None
            else len(approvals) >= request.required_approvals
        )
        if not enough:
            record(
                db,
                actor=Actor.user(user.id),
                action="approval.approved",
                target_type="approval_request",
                target_id=request.id,
                details={**details, "final": False},
            )
            return  # more approvals needed; it stays pending
    # Approved: the change is made in this same transaction, so either both happen or
    # neither does.
    handler.apply(db, request, user)
    request.status, request.decided_at = "approved", now
    record(
        db,
        actor=Actor.user(user.id),
        action="approval.approved",
        target_type="approval_request",
        target_id=request.id,
        details={**details, "final": True},
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
