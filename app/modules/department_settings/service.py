"""A department's own value for a setting (docs/features/coverage.md, the send-up minimum).

A setting declared per_department (app/settings/registry.py) may be made stricter for one
department than for the whole company, never weaker: the value in force there is the
stricter of the two (department_value in app/settings/service.py).

Who may change it (threat E3): one of the department's managers, the active people who
hold time_off.review through an assignment for that department, or someone who holds
time_off.review for the whole company (an owner or administrator). Anyone else gets 403.

With several managers, a change is an approval request (kind "department_setting",
approval.py) that every other manager of the department must approve; one denial stops
it, and it lapses after 7 days. With one manager (or nobody else to ask), it takes effect
at once. Only one change per department and setting waits at a time (409).

Changes take turns through the company's lock (the same one role changes take), so two
managers asking at once cannot both open a request, and the managers are read fresh.
Every change is audited (settings.department_changed, and the approval events).

Locks, in the order every other request takes them (review of #195), so two requests
never wait for each other forever:
1. the department (a shared lock, FOR SHARE), before the company's lock, as creating,
   moving, and reactivating a person and archiving a department do (org/people.py);
2. the company's lock;
3. the people, all together and sorted by ID: the changer and every possible manager
   (lock_people), the order of every schedule change (schedules/service.py,
   _lock_for_change). Locking the changer first and the other managers later did not:
   with a shift reassigned between two of them at that moment, each request held one
   person and waited for the other (#209 was the same deadlock for time off).
A confirmation takes the same locks in the same order (approval.py).
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalDecision, ApprovalRequest
from app.approvals.service import open_request
from app.audit import Actor
from app.authz.chain import lock_reporting_lines
from app.authz.check import Forbidden, grants
from app.authz.models import Role, RoleAssignment, RolePermission
from app.modules.org.models import Department, User
from app.modules.org.service import Conflict, Invalid, NotFound
from app.settings.registry import (
    SettingDef,
    SettingRejected,
    Stricter,
    all_settings,
    get_setting_def,
)
from app.settings.service import (
    change_department_setting,
    department_value,
    own_department_value,
    setting_value,
)

KIND = "department_setting"
MANAGES = "time_off.review"  # what makes someone one of a department's managers


# --- Who manages a department ----------------------------------------------------------


def managers(db: Session, department_id: uuid.UUID, *, fresh: bool = False) -> set[uuid.UUID]:
    """The department's managers: active people holding time_off.review through an
    active assignment for this department (company-wide holders are not counted).

    fresh: locking reads (FOR SHARE), for checks after the company's lock. Under MySQL's
    REPEATABLE READ an ordinary read would answer from before the wait, so a manager who
    lost the role meanwhile would still count (review of #163)."""
    found = set()
    # Sorted by ID, so the people are locked (fresh) in the one order every request
    # takes them (the top of this file).
    for person_id in sorted(_holders(db, department_id, fresh=fresh)):
        person = _person(db, person_id, fresh=fresh)
        if person is not None and person.deactivated_at is None:
            found.add(person_id)
    return found


def _holders(db: Session, department_id: uuid.UUID, *, fresh: bool) -> set[uuid.UUID]:
    """Everyone holding time_off.review through an active role's assignment for this
    department, active or not (a set: a person may hold it through more than one role).
    fresh: a locking read (FOR SHARE) of the assignments."""
    # Every joined model has a column in the select list, so the company filter limits
    # each one to the session's company too (tenancy.md: joins).
    query = (
        select(RoleAssignment.user_id, Role.id, RolePermission.role_id)
        .join(Role, Role.id == RoleAssignment.role_id)
        .join(RolePermission, RolePermission.role_id == Role.id)
        .where(
            RoleAssignment.scope_type == "department",
            RoleAssignment.department_id == department_id,
            RolePermission.permission_code == MANAGES,
            Role.archived_at.is_(None),
        )
    )
    rows = db.execute(query.with_for_update(read=True) if fresh else query).all()
    return {person_id for person_id, _, _ in rows}


def _person(db: Session, person_id: uuid.UUID, *, fresh: bool) -> User | None:
    """A person, read with a shared lock (FOR SHARE) and fresh when `fresh`."""
    if fresh:
        return db.get(User, person_id, with_for_update={"read": True}, populate_existing=True)
    return db.get(User, person_id)


def lock_department(db: Session, department_id: uuid.UUID) -> Department | None:
    """The department, read fresh with a shared lock (FOR SHARE) that it keeps until the
    transaction ends: taken before the company's lock (the top of this file), so it
    cannot be archived while a change to it is decided. None if there is no such
    department in the company."""
    return db.get(Department, department_id, with_for_update={"read": True}, populate_existing=True)


def lock_people(db: Session, department_id: uuid.UUID, also: set[uuid.UUID]) -> None:
    """After the company's lock: lock the people a change or a confirmation reads, all at
    once and sorted by ID (the top of this file). They are the people `also` names (the
    changer, the confirmer) and everyone who holds the managers' permission for the
    department: the same people managers() reads, deactivated or not, so its own locking
    reads find every lock already held and take no new one out of order.

    The candidates come from a locking read (FOR SHARE) of their assignments, so it sees
    assignments committed while this request waited for the company's lock; no new one
    can appear after it, since role changes take the company's lock too."""
    for person_id in sorted(_holders(db, department_id, fresh=True) | also):
        _person(db, person_id, fresh=True)


def company_wide(db: Session, user: User, *, fresh: bool = False) -> bool:
    """Whether the user holds time_off.review for the whole company (fresh: locking reads,
    as in managers())."""
    return any(grant.scope_type == "company" for grant in grants(db, user, MANAGES, fresh=fresh))


def _department(
    db: Session, user: User, department_id: uuid.UUID, *, fresh: bool = False
) -> Department:
    """The department, if the user may manage its settings (403); another company's or an
    unknown or archived one is 404. fresh: after the company's lock, every read is a
    locking read (managers())."""
    department = lock_department(db, department_id) if fresh else db.get(Department, department_id)
    if department is None or department.archived_at is not None:
        raise NotFound()
    if user.id not in managers(db, department_id, fresh=fresh) and not company_wide(
        db, user, fresh=fresh
    ):
        raise Forbidden()
    return department


def _per_department(name: str) -> SettingDef:
    """A setting a department may set for itself (404 for any other name)."""
    try:
        setting = get_setting_def(name)
    except LookupError:
        raise NotFound() from None
    if not setting.per_department:
        raise NotFound()
    return setting


# --- Reading ---------------------------------------------------------------------------


@dataclass
class Pending:
    approval: ApprovalRequest
    value: int
    waiting_for: list[uuid.UUID]


@dataclass
class Shown:
    setting: SettingDef
    company_value: int  # the company's value (or the platform default)
    department_value: int | None  # the department's own, if it set one
    value: int  # in force: the stricter of the two
    pending: Pending | None  # a change waiting for the other managers


def pending_change(
    db: Session, department_id: uuid.UUID, name: str, *, fresh: bool = False
) -> ApprovalRequest | None:
    """The change of this setting still waiting for this department's managers, if any.
    Requests past their deadline are left out (they lapse when next read or decided).
    fresh: a locking read, after the company's lock (as in managers())."""
    query = select(ApprovalRequest).where(
        ApprovalRequest.kind == KIND, ApprovalRequest.status == "pending"
    )
    if fresh:
        query = query.with_for_update(read=True).execution_options(populate_existing=True)
    rows = db.scalars(query)
    now = datetime.now(UTC).replace(tzinfo=None)
    for row in rows:
        if (
            row.payload.get("department_id") == str(department_id)
            and row.payload.get("setting") == name
            and row.review_by > now
        ):
            return row
    return None


def _waiting_for(db: Session, approval: ApprovalRequest) -> list[uuid.UUID]:
    from app.modules.department_settings.approval import reviewers

    decided = set(
        db.scalars(
            select(ApprovalDecision.approver_id).where(ApprovalDecision.request_id == approval.id)
        )
    )
    return sorted(reviewers(db, approval) - decided)


def show(db: Session, user: User, department_id: uuid.UUID) -> list[Shown]:
    """Every per-department setting for one department, as its managers see it."""
    _department(db, user, department_id)
    found = []
    for setting in sorted(all_settings().values(), key=lambda s: s.name):
        if not setting.per_department:
            continue
        waiting = pending_change(db, department_id, setting.name)
        found.append(
            Shown(
                setting=setting,
                company_value=setting_value(db, setting.name),
                department_value=own_department_value(db, setting.name, department_id),
                value=department_value(db, setting.name, department_id),
                pending=Pending(waiting, int(waiting.payload["value"]), _waiting_for(db, waiting))
                if waiting is not None
                else None,
            )
        )
    return found


# --- Changing --------------------------------------------------------------------------


@dataclass
class Changed:
    value: int | None  # the new value, when it took effect at once
    pending: ApprovalRequest | None  # the request, when other managers must confirm


def check_value(db: Session, setting: SettingDef, value: object) -> int:
    """Within the platform's bounds and never weaker than the company's value (422)."""
    try:
        checked = setting.check(value)
    except SettingRejected as error:
        raise Invalid(str(error)) from error
    company = setting_value(db, setting.name)
    weaker = checked < company if setting.stricter is Stricter.HIGHER else checked > company
    if weaker:
        raise Invalid(f"A department may not go below the company's value ({company}).")
    return checked


def change(db: Session, user: User, department_id: uuid.UUID, name: str, value: object) -> Changed:
    """Change a department's value: at once with no other manager to ask, otherwise as an
    approval request every other manager must approve."""
    setting = _per_department(name)
    # 1. Allowed at all, with ordinary reads, before anything is locked: someone who may
    #    not change this department's settings never waits for, or holds, its locks.
    _department(db, user, department_id)
    # 2. The locks, in the order at the top of this file: the department, the company's
    #    lock (taking turns with every other role, line, and setting change in the
    #    company), then the changer and the possible managers, together and sorted.
    lock_department(db, department_id)
    lock_reporting_lines(db)
    lock_people(db, department_id, {user.id})
    # 3. Everything checked again, fresh. Every read after the lock is a locking read
    #    (review of #193, the same stale read): an ordinary one answers from this
    #    transaction's first snapshot, taken before the wait, so a manager who lost the
    #    role meanwhile could still change the setting, the managers to ask could be out
    #    of date, and two changes at once would both open a request. The locks above are
    #    already held, so these reads take no new ones.
    me = _person(db, user.id, fresh=True)
    if me is None or me.deactivated_at is not None:
        raise Forbidden()
    _department(db, me, department_id, fresh=True)
    checked = check_value(db, setting, value)
    if pending_change(db, department_id, setting.name, fresh=True) is not None:
        raise Conflict("A change of this setting is already waiting for the other managers.")
    others = managers(db, department_id, fresh=True) - {me.id}
    if not others:
        change_department_setting(db, setting.name, department_id, checked, actor=Actor.user(me.id))
        db.commit()
        return Changed(checked, None)
    payload = {"department_id": str(department_id), "setting": setting.name, "value": checked}
    approval = open_request(
        db,
        kind=KIND,
        requested_by=me.id,
        subject_user_id=me.id,
        payload=payload,
        details=payload,
        required_approvals=len(others),
    )
    db.commit()
    return Changed(None, approval)
