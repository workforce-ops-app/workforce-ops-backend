"""What a "role_assignment" approval request does, and who reviews it (authorization.md,
"Who approves a same-level grant"; decision 0032).

A role at the giver's own level opens a request instead of being given
(app/modules/roles/assignments.py). This module tells the shared approval layer
(app/approvals/service.py) three things about such a request:

- Who reviews it: the giver's direct managers who could give that role to that person
  themselves (role.assign over the person, and every permission of the role for the
  whole place). If none of them can, the next level up, one level at a time; if nobody
  in the chain can, the company's owners. Worked out again at every decision, on fresh
  reads, so somebody who lost their role or their place since cannot decide.
- Whether deciding is sensitive: an admin-level role needs the password entered again.
- What approval does: gives the role, in the same transaction, after checking that it
  still can be given (the role, the place, and the person are all still usable).

Nobody reviews a request they made or one that gives them a role (AZ14); the shared layer
checks that for every kind.

Fresh reads (review of #163): a decision takes the company's lock first
(app/modules/approval_requests/service.py), and under MySQL's REPEATABLE READ an ordinary
read after that wait still answers from the transaction's old snapshot. So everything a
decision depends on is read again after the lock with locking reads (FOR SHARE), as giving
a role does (assignments.py): reviewers(fresh=True) for who may decide, and sensitive()
and apply(), which only run after the lock, always. Before the lock (lists, one request)
the ordinary reads stay, so a page view never waits on, or holds, row locks.
"""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.approvals.models import ApprovalRequest
from app.approvals.service import DecisionError, Handler, register_handler
from app.audit import Actor
from app.authz.chain import direct_managers_fresh, is_above_in_chain_fresh
from app.authz.check import ADMIN_LEVEL, Forbidden, NotFound, authorize, is_owner
from app.authz.delegation import held_for, place_problem, scope_of, what_role_grants
from app.authz.models import Role, RoleAssignment
from app.authz.roles import assign_role
from app.modules.org.models import User


def _wanted(request: ApprovalRequest) -> tuple[uuid.UUID, str, uuid.UUID | None]:
    """The role, scope type, and scope ID the request asks for (from its payload)."""
    payload = request.payload
    scope_id = payload.get("scope_id")
    return (
        uuid.UUID(payload["role_id"]),
        payload["scope_type"],
        uuid.UUID(scope_id) if scope_id else None,
    )


def _row[M](db: Session, model: type[M], row_id: uuid.UUID, fresh: bool) -> M | None:
    """One row by ID. fresh=True makes it a locking read (FOR SHARE) that replaces the copy
    this session holds, so it shows the newest committed version (the top of this file)."""
    if fresh:
        return db.get(model, row_id, with_for_update={"read": True}, populate_existing=True)
    return db.get(model, row_id)


def _could_give(db: Session, reviewer: User, request: ApprovalRequest, *, fresh: bool) -> bool:
    """Whether the reviewer could give this role to this person themselves, and is above
    the person who asked. With fresh=True every read is a locking read, so a reviewer who
    lost role.assign, a role edited to grant more, or a person moved away while the
    decision waited for the lock is seen as it is now."""
    # 1. The reviewer as they are now: active, and not the asker or the person it is about.
    if fresh:
        db.refresh(reviewer, with_for_update={"read": True})
    if reviewer.deactivated_at is not None:
        return False
    if reviewer.id in (request.requested_by, request.subject_user_id):
        return False
    # 2. An owner could give any role.
    if is_owner(db, reviewer, fresh=fresh):
        return True
    # 3. The role and the person as they are now.
    role_id, scope_type, scope_id = _wanted(request)
    role = _row(db, Role, role_id, fresh)
    subject = _row(db, User, request.subject_user_id, fresh)
    if role is None or subject is None:
        return False
    # 4. Above the person who asked (the chain is always read fresh).
    if not is_above_in_chain_fresh(db, reviewer.id, request.requested_by):
        return False
    # 5. role.assign over the person (AZ5), and every permission the role grants now for
    #    the whole place (AZ3, AZ4).
    try:
        authorize(db, reviewer, "role.assign", subject, fresh=fresh)
    except (Forbidden, NotFound):
        return False
    codes = what_role_grants(db, role, fresh=fresh)
    place = scope_of(db, scope_type, scope_id, fresh=fresh)
    return held_for(db, reviewer, codes, place, fresh=fresh) == codes


def _owners(db: Session, *, fresh: bool) -> set[uuid.UUID]:
    """The company's active owners (Owner role, company-wide); locking reads if fresh."""
    query = (
        select(RoleAssignment.user_id, Role.id)
        .join(Role, Role.id == RoleAssignment.role_id)
        .where(Role.built_in == "owner", RoleAssignment.scope_type == "company")
    )
    ids = db.scalars(query.with_for_update(read=True) if fresh else query)
    return {
        person
        for person in ids
        if (found := _row(db, User, person, fresh)) and found.deactivated_at is None
    }


def reviewers(db: Session, request: ApprovalRequest, *, fresh: bool = False) -> set[uuid.UUID]:
    """Who may decide the request now: the nearest level above the giver where somebody
    could give the role themselves, or else the owners. fresh=True after the company's
    lock (the top of this file)."""
    seen: set[uuid.UUID] = {request.requested_by}
    level = direct_managers_fresh(db, {request.requested_by})
    while level:
        able = {
            person_id
            for person_id in level
            if (person := _row(db, User, person_id, fresh)) is not None
            and _could_give(db, person, request, fresh=fresh)
        }
        if able:
            return able
        seen |= level
        level = direct_managers_fresh(db, level) - seen
    return _owners(db, fresh=fresh) - {request.requested_by, request.subject_user_id}


def sensitive(db: Session, request: ApprovalRequest) -> bool:
    """Approving or denying an admin-level role needs the password entered again. Only
    asked after the company's lock, so it reads what the role grants now (fresh)."""
    role = _row(db, Role, _wanted(request)[0], True)
    if role is None:
        return False
    return not ADMIN_LEVEL.isdisjoint(what_role_grants(db, role, fresh=True))


def describe(db: Session, request: ApprovalRequest) -> dict[str, Any]:
    """What the audit entries show: the role and where (IDs and the role's name)."""
    role_id, scope_type, scope_id = _wanted(request)
    role = db.get(Role, role_id)
    return {
        "role": (role.built_in or role.name) if role is not None else str(role_id),
        "scope_type": scope_type,
        "scope_id": str(scope_id) if scope_id else None,
    }


def apply(db: Session, request: ApprovalRequest, approver: User) -> None:
    """Give the role, if it still can be given; DecisionError (409) if not. Runs after the
    company's lock, so the role, the person, and the place are read fresh: one archived or
    deactivated while the decision waited is seen."""
    role_id, scope_type, scope_id = _wanted(request)
    role = _row(db, Role, role_id, True)
    subject = _row(db, User, request.subject_user_id, True)
    if role is None or role.archived_at is not None or role.built_in == "owner":
        raise DecisionError("This role can no longer be given.")
    if subject is None or subject.deactivated_at is not None:
        raise DecisionError("This person is deactivated.")
    problem = place_problem(db, scope_type, scope_id, fresh=True)
    if problem is not None:
        raise DecisionError(problem[1])
    held = db.scalars(
        select(RoleAssignment)
        .where(
            RoleAssignment.user_id == subject.id,
            RoleAssignment.role_id == role.id,
            RoleAssignment.scope_type == scope_type,
        )
        .with_for_update(read=True)
    )
    if any((row.department_id or row.team_id or row.employee_id) == scope_id for row in held):
        raise DecisionError("This person already holds this role there.")
    assign_role(
        db,
        Actor.user(approver.id),
        user_id=subject.id,
        role=role,
        scope_type=scope_type,
        scope_id=scope_id,
    )


register_handler(
    "role_assignment",
    Handler(reviewers=reviewers, sensitive=sensitive, apply=apply, describe=describe),
)
