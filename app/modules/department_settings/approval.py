"""What a "department_setting" approval request does, and who reviews it
(docs/features/coverage.md, the send-up minimum).

- Reviewers: every current manager of the department except the one who asked (the
  managers as service.py works them out), read again at each decision.
- Enough: every one of them has approved, counted again at the last approval, so a
  manager added meanwhile must agree too. One denial stops it (the shared rule).
- Not sensitive: no password re-entry (a stricter deadline only gives reviewers longer).
- Approval writes the value, checked again: never weaker than the company's value as it
  is now, and only for a department that still exists and is not archived.
- Locks (the order at the top of service.py, review of #195): the department before the
  company's lock (lock_first), then the people sorted by ID (lock), so a confirmation
  never waits on someone a schedule change holds while holding someone it waits for.
  The department is read with a locking read, so an archive committed while this
  decision waited is seen (archiving takes the department's lock, not the company's).
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import DecisionError, Handler, register_handler
from app.audit import Actor
from app.modules.department_settings import service
from app.modules.org.models import User
from app.modules.org.service import Invalid
from app.settings.registry import get_setting_def
from app.settings.service import change_department_setting


def _department_id(request: ApprovalRequest) -> uuid.UUID:
    return uuid.UUID(request.payload["department_id"])


def reviewers(db: Session, request: ApprovalRequest, *, fresh: bool = False) -> set[uuid.UUID]:
    # fresh after the company's lock: the managers are read with locking reads.
    managers = service.managers(db, _department_id(request), fresh=fresh)
    return managers - {request.requested_by}


def lock_first(db: Session, request: ApprovalRequest) -> None:
    # Before the company's lock: the department (its ID in the payload never changes, so
    # an ordinary read of the request is enough to find it).
    service.lock_department(db, _department_id(request))


def lock_people(db: Session, request: ApprovalRequest, decider: User) -> None:
    # After the company's lock, before anyone is read: the decider and the possible
    # managers, together and sorted by ID.
    service.lock_people(db, _department_id(request), {decider.id})


def ready(db: Session, request: ApprovalRequest, approvers: set[uuid.UUID]) -> bool:
    # Only called by decide(), after the company's lock, so the managers are read fresh.
    return reviewers(db, request, fresh=True) <= approvers


def sensitive(db: Session, request: ApprovalRequest) -> bool:
    return False


def describe(db: Session, request: ApprovalRequest) -> dict[str, Any]:
    # The department, the setting, and the value: nothing personal.
    return {key: request.payload[key] for key in ("department_id", "setting", "value")}


def apply(db: Session, request: ApprovalRequest, approver: User) -> None:
    # A locking read, fresh (review of #195): an ordinary one would answer from this
    # transaction's first snapshot, so a department archived meanwhile would still look
    # active. lock_first already holds this lock, so it takes no new one.
    department = service.lock_department(db, _department_id(request))
    if department is None or department.archived_at is not None:
        raise DecisionError("This department no longer exists.")
    setting = get_setting_def(request.payload["setting"])
    try:
        value = service.check_value(db, setting, request.payload["value"])
    except Invalid as error:
        # The company raised its own value meanwhile, past this one.
        raise DecisionError(str(error)) from error
    change_department_setting(
        db,
        setting.name,
        department.id,
        value,
        actor=Actor.user(approver.id),
        requested_by=request.requested_by,
    )


register_handler(
    service.KIND,
    Handler(
        reviewers=reviewers,
        sensitive=sensitive,
        apply=apply,
        describe=describe,
        ready=ready,
        lock_first=lock_first,
        lock_people=lock_people,
    ),
)
