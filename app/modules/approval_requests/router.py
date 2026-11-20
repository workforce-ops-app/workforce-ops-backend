"""Approval requests over HTTP (authorization.md, delegation limits). HTTP only: the rules
are in service.py and app/approvals/.

    GET  /api/approval-requests?view=mine|to_review&limit=   200  your requests / to decide
    GET  /api/approval-requests/{id}                         200  one request
    POST /api/approval-requests/{id}/approve                 200  approve (maybe applies it)
    POST /api/approval-requests/{id}/deny                    200  deny
    POST /api/approval-requests/{id}/cancel                  200  take your own back

Errors: 401 not signed in, 403 not allowed (or "reauth-required"), 404 not found (or not
yours to see), 409 no longer pending, not reviewed in time, or no longer possible.
Every change also needs the CSRF token.
"""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Query

# Registers what each kind of request does on approval, before any request is decided.
import app.modules.owners.approval  # noqa: F401
import app.modules.roles.approval  # noqa: F401
import app.modules.time_off.approval  # noqa: F401
from app.auth.dependencies import Database, SignedInPerson
from app.modules.approval_requests import service
from app.modules.approval_requests.schemas import ApprovalRequestList, ApprovalRequestOut, shown

router = APIRouter(prefix="/api/approval-requests", tags=["approval requests"])


@router.get("")
def list_requests(
    current: SignedInPerson,
    db: Database,
    view: Literal["mine", "to_review"] = "mine",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> ApprovalRequestList:
    rows = service.list_requests(db, current.user, view=view, limit=limit)
    return ApprovalRequestList(items=[shown(db, row) for row in rows])


@router.get("/{request_id}")
def view_request(
    request_id: uuid.UUID, current: SignedInPerson, db: Database
) -> ApprovalRequestOut:
    return shown(db, service.view_request(db, current.user, request_id))


@router.post("/{request_id}/approve")
def approve(request_id: uuid.UUID, current: SignedInPerson, db: Database) -> ApprovalRequestOut:
    return shown(db, service.approve(db, current.user, request_id, session=current.session))


@router.post("/{request_id}/deny")
def deny(request_id: uuid.UUID, current: SignedInPerson, db: Database) -> ApprovalRequestOut:
    return shown(db, service.deny(db, current.user, request_id, session=current.session))


@router.post("/{request_id}/cancel")
def cancel(request_id: uuid.UUID, current: SignedInPerson, db: Database) -> ApprovalRequestOut:
    return shown(db, service.cancel_request(db, current.user, request_id))
