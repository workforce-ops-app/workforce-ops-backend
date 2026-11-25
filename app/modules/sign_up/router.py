"""Company sign-up: the HTTP side (docs/features/organization.md, company sign-up).

    POST /api/sign-up  {company_name, timezone, display_name, email, password}
        201  the company and its owner exist, and the owner is signed in: the same body
             as POST /api/sessions, and the __Host-session cookie

Errors: 403 the request did not come from the application's own pages (the Origin
check; no CSRF token is needed, as at sign-in), 409 already signed in (sign out first) or
the email can't be used, 422 invalid input or a password that breaks a rule, 429 too
many sign-ups (5 an hour per address, also counted toward sign-in's 20 a minute; 200
new companies an hour on the platform), with Retry-After.

Counted: every request that passes the Origin check and is JSON, whether its fields are
valid or not, toward both limits per address (count_sign_up). A body that is not JSON at
all is refused (422) before it is counted; it reaches nothing.

The rules live in service.py; this file only turns HTTP into calls and back.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import Engine

from app.auth.dependencies import Database
from app.auth.limits import TooManyRequests, client_address
from app.auth.models import UserSession
from app.auth.passwords import PasswordRejected
from app.auth.sessions import COOKIE_NAME, has_working_session
from app.modules.org.models import User
from app.modules.security.layer import detection_skip
from app.modules.sessions.router import _info, _set_cookie
from app.modules.sessions.schemas import SessionInfo
from app.modules.sign_up import service
from app.modules.sign_up.schemas import SignUpRequest
from app.tenancy.context import set_company

router = APIRouter(prefix="/api/sign-up", tags=["sign-up"])

SIGN_OUT_FIRST = "You are signed in. Sign out first to sign up a new company."


def count_sign_up(request: Request) -> None:
    """Count the request toward both limits per address, then refuse it if either is over.

    A dependency of the route, so FastAPI runs it before it checks the body's fields: a
    request with invalid fields counts too. Both counters always move, so a request past
    the sign-up limit still counts toward sign-in's, and switching forms gains nothing.
    """
    address = client_address(request)
    limits = request.app.state.limits
    refusals = []
    for limit in (limits.sign_up_per_address, limits.sign_in_per_address):
        try:
            limit.hit(address)
        except TooManyRequests as refused:
            refusals.append(refused)
    if refusals:
        # Over both: the answer says to wait for the later of the two.
        raise max(refusals, key=lambda refused: refused.retry_after)


@router.post("", status_code=201, dependencies=[Depends(count_sign_up)])
@detection_skip  # a credential route: detection copies nothing of it (rule DE3)
def sign_up(body: SignUpRequest, request: Request, response: Response, db: Database) -> SessionInfo:
    """Create a company and its owner, and sign the owner in."""
    # 1. The limits per address were counted already (count_sign_up).

    # 2. Signed out only: a signed-in person does not start a second company by accident.
    #    Checked in a database session of its own, so an ended session's company does not
    #    stay bound to this request's session, which works for the new company below.
    if has_working_session(db, request.cookies.get(COOKIE_NAME)):
        raise HTTPException(status_code=409, detail=SIGN_OUT_FIRST)

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
