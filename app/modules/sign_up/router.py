"""Company sign-up: the HTTP side (docs/features/organization.md, company sign-up).

    POST /api/sign-up  {company_name, timezone, display_name, email, password}
        201  the company and its owner exist, and the owner is signed in: the same body
             as POST /api/sessions, and the __Host-session cookie

Errors: 403 the request did not come from the application's own pages (the Origin
check; no CSRF token is needed, as at sign-in), 409 already signed in (sign out first) or
the email can't be used, 422 invalid input or a password that breaks a rule, 429 too
many sign-ups (5 an hour per address, also counted toward sign-in's 20 a minute; 200
new companies an hour on the platform), with Retry-After.

The rules live in service.py; this file only turns HTTP into calls and back.
"""

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import Engine

from app.auth.dependencies import Database
from app.auth.limits import client_address
from app.auth.models import UserSession
from app.auth.passwords import PasswordRejected
from app.auth.sessions import COOKIE_NAME, load_session
from app.modules.org.models import User
from app.modules.security.layer import detection_skip
from app.modules.sessions.router import _info, _set_cookie
from app.modules.sessions.schemas import SessionInfo
from app.modules.sign_up import service
from app.modules.sign_up.schemas import SignUpRequest
from app.tenancy.context import set_company

router = APIRouter(prefix="/api/sign-up", tags=["sign-up"])

SIGN_OUT_FIRST = "You are signed in. Sign out first to sign up a new company."


@router.post("", status_code=201)
@detection_skip  # a credential route: detection copies nothing of it (rule DE3)
def sign_up(body: SignUpRequest, request: Request, response: Response, db: Database) -> SessionInfo:
    """Create a company and its owner, and sign the owner in."""
    # 1. The limits per address, before any work: every request counts, successful or
    #    not, and also toward sign-in's limit, so switching forms gains nothing.
    address = client_address(request)
    request.app.state.limits.sign_up_per_address.hit(address)
    request.app.state.limits.sign_in_per_address.hit(address)

    # 2. Signed out only: a signed-in person does not start a second company by accident.
    if load_session(db, request.cookies.get(COOKIE_NAME)) is not None:
        raise HTTPException(status_code=409, detail=SIGN_OUT_FIRST)
    # The request's own session is done with for now: the sign-up opens its own
    # transaction on its own connection (service.py), and must not wait behind this one.
    db.rollback()

    # 3. The sign-up itself, in one transaction.
    engine = db.get_bind()
    if not isinstance(engine, Engine):  # the app's sessions are bound to its engine
        raise RuntimeError("the request's database session has no engine")
    try:
        made = service.sign_up(engine, body)
    except PasswordRejected as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    except service.EmailTaken:
        raise HTTPException(status_code=409, detail=service.EmailTaken.message) from None

    # 4. Saved: now the cookie, and the same answer as signing in.
    set_company(db, made.company_id)
    user = db.get(User, made.user_id)
    session = db.get(UserSession, made.session_id)
    if user is None or session is None:  # just committed, so always found
        raise RuntimeError("the new owner or their session is missing")
    _set_cookie(response, made.token, session)
    return _info(request, db, user, session)
