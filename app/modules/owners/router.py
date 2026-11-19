"""Owners over HTTP (authorization.md, delegation limits). HTTP only: the rules are in
service.py.

    GET  /api/owners                        200  the company's owners
    POST /api/owners  {user_id}             200  added at once (one owner), with the owners
                                            202  waiting for the other owners (the request)
    POST /api/owners/{user_id}/remove       200  removed at once, with the owners
                                            202  waiting for the other owners (the request)

Errors: 401 not signed in, 403 not an owner (or "reauth-required"), 404 not an owner (on
remove), 409 the last owner, already an owner, deactivated, or already requested, 422
unknown person. Every change also needs the CSRF token.
"""

import uuid
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

# Registers what owner requests do on approval, before any request is decided.
import app.modules.owners.approval  # noqa: F401
from app.auth.dependencies import Database, SignedInPerson
from app.modules.approval_requests.schemas import ApprovalRequestOut, shown
from app.modules.org.models import User
from app.modules.owners import service
from app.modules.owners.schemas import OwnerAdd, OwnerList, OwnerOut

router = APIRouter(prefix="/api/owners", tags=["owners"])

WAITING: dict[int | str, dict[str, Any]] = {
    202: {"model": ApprovalRequestOut, "description": "Waiting for the other owners"}
}


def _owners(db: Database, user: User) -> OwnerList:
    return OwnerList(
        items=[
            OwnerOut(id=p.id, display_name=p.display_name) for p in service.list_owners(db, user)
        ]
    )


def _answer(db: Database, user: User, proposed: service.Proposed) -> OwnerList | JSONResponse:
    if proposed.request is not None:
        return JSONResponse(
            status_code=202, content=shown(proposed.request).model_dump(mode="json")
        )
    return _owners(db, user)


@router.get("")
def list_owners(current: SignedInPerson, db: Database) -> OwnerList:
    return _owners(db, current.user)


@router.post("", response_model=OwnerList, responses=WAITING)
def add_owner(body: OwnerAdd, current: SignedInPerson, db: Database) -> OwnerList | JSONResponse:
    proposed = service.add_owner(db, current.user, body.user_id, session=current.session)
    return _answer(db, current.user, proposed)


@router.post("/{user_id}/remove", response_model=OwnerList, responses=WAITING)
def remove_owner(
    user_id: uuid.UUID, current: SignedInPerson, db: Database
) -> OwnerList | JSONResponse:
    proposed = service.remove_owner(db, current.user, user_id, session=current.session)
    return _answer(db, current.user, proposed)
