"""Setup and reset links: the HTTP side (authentication.md, endpoints).

    POST /api/users/{id}/setup-link     201  a link for a new account (user.manage, above them)
    POST /api/users/{id}/reset-link     201  a link for a forgotten password (the same rule)
    POST /api/password-links/redeem     204  set a password with a link (anyone holding one)

The rules live in app/auth/links.py; this file only turns HTTP into calls and back.

Errors: 400 the link does not work (one answer for every reason), 401 not signed in,
403 not allowed, 404 no such person (or another company's), 409 the kind of link does not
fit the account, 422 invalid input or a password that breaks a rule.
"""

import uuid
from datetime import UTC

from fastapi import APIRouter, Request

from app.auth import links
from app.auth.dependencies import Database, SignedInPerson
from app.modules.password_links.schemas import LinkCreated, RedeemRequest

people = APIRouter(prefix="/api/users", tags=["password links"])
redeeming = APIRouter(prefix="/api/password-links", tags=["password links"])


def _origin(request: Request) -> str:
    """The application's own address as browsers see it: the configured APP_ORIGIN, or
    else the address this request was sent to (the same rule as the CSRF check)."""
    configured = getattr(request.app.state, "app_origin", None)
    return configured or f"{request.url.scheme}://{request.url.netloc}"


def _created(request: Request, new: links.NewLink) -> LinkCreated:
    """The answer for a new link: its address, shown this once."""
    return LinkCreated(
        purpose=new.link.purpose,  # "setup" or "reset" (the CHECK in the table)
        link=links.link_address(_origin(request), new.token),
        expires_at=new.link.expires_at.replace(tzinfo=UTC),
    )


@people.post("/{user_id}/setup-link", status_code=201)
def create_setup_link(
    user_id: uuid.UUID, request: Request, current: SignedInPerson, db: Database
) -> LinkCreated:
    """A link for a new account to choose its first password."""
    return _created(request, links.create_link(db, current.user, user_id, "setup"))


@people.post("/{user_id}/reset-link", status_code=201)
def create_reset_link(
    user_id: uuid.UUID, request: Request, current: SignedInPerson, db: Database
) -> LinkCreated:
    """A link for someone who forgot their password (or is locked out) to choose a new one."""
    return _created(request, links.create_link(db, current.user, user_id, "reset"))


@redeeming.post("/redeem", status_code=204)
def redeem_link(body: RedeemRequest, db: Database) -> None:
    """Set a password with a link. Nobody is signed in: the link is the proof."""
    links.redeem(db, body.token.get_secret_value(), body.new_password.get_secret_value())


# The one router app/main.py discovers in this module; both groups of endpoints are copied
# into it. This comes last: include_router copies the routes defined above at this moment.
router = APIRouter()
router.include_router(people)
router.include_router(redeeming)
