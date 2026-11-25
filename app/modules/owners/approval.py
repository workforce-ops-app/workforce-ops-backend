"""What "owner_add" and "owner_remove" approval requests do, and who reviews them
(authorization.md, delegation limits; decision 0032).

- Reviewers: every current owner except the one who asked and the one the request is
  about. Worked out again at each decision, on fresh reads.
- Enough: every one of those reviewers has approved, counted again at the last approval,
  so an owner added meanwhile must agree too (not a fixed number).
- Always sensitive: deciding needs the password entered again.
- Approval makes the change (app/modules/owners/service.py), which re-checks that it is
  still possible on fresh reads: never the last owner, never a deactivated person (the
  person is locked first, so a deactivation cannot slip in alongside).
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import DecisionError, Handler, register_handler
from app.audit import Actor
from app.authz.delegation import active_owners
from app.modules.org.models import User
from app.modules.owners.service import locked_person, make_owner, unmake_owner


def reviewers(db: Session, request: ApprovalRequest, *, fresh: bool = False) -> set[uuid.UUID]:
    """Every current owner but the asker and the subject. fresh=True after the company's
    lock (locking reads); fresh=False before it, for lists (ordinary reads)."""
    return active_owners(db, fresh=fresh) - {request.requested_by, request.subject_user_id}


def ready(db: Session, request: ApprovalRequest, approvers: set[uuid.UUID]) -> bool:
    # Runs in decide(), after the company's lock: the owners as they are now.
    return reviewers(db, request, fresh=True) <= approvers


def sensitive(db: Session, request: ApprovalRequest) -> bool:
    return True


def describe(db: Session, request: ApprovalRequest) -> dict[str, Any]:
    return {}  # the kind and the subject are already in every entry


def _subject(db: Session, request: ApprovalRequest) -> User:
    # Locked and read fresh (locked_person), so a deactivation committed while the
    # request waited is seen, and one still to come waits until this one commits.
    person = locked_person(db, request.subject_user_id)
    if person is None:  # people are never deleted
        raise DecisionError("This person no longer exists.")
    return person


def apply_add(db: Session, request: ApprovalRequest, approver: User) -> None:
    make_owner(db, Actor.user(approver.id), _subject(db, request))


def apply_remove(db: Session, request: ApprovalRequest, approver: User) -> None:
    unmake_owner(db, Actor.user(approver.id), _subject(db, request))


register_handler(
    "owner_add",
    Handler(
        reviewers=reviewers, sensitive=sensitive, apply=apply_add, describe=describe, ready=ready
    ),
)
register_handler(
    "owner_remove",
    Handler(
        reviewers=reviewers, sensitive=sensitive, apply=apply_remove, describe=describe, ready=ready
    ),
)
