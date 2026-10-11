"""Signing in and out: the HTTP side (authentication.md, endpoints).

    POST   /api/sessions          sign in; sets the __Host-session cookie
    GET    /api/sessions/current  who is signed in, for which company
    DELETE /api/sessions/current  sign out
    DELETE /api/sessions          sign out everywhere (all of your own sessions)

The rules live in app/auth/sessions.py; this file only turns HTTP into calls and back.
"""

from datetime import UTC

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.auth.csrf import csrf_token
from app.auth.dependencies import Database, SignedInPerson
from app.auth.models import UserSession
from app.auth.sessions import (
    COOKIE_NAME,
    SIGN_IN_FAILED,
    end_previous_session,
    seconds_left,
    sign_in,
    sign_out,
    sign_out_everywhere,
)
from app.authz.check import effective_permissions
from app.modules.org.models import Company, User
from app.modules.sessions.schemas import (
    SessionCompany,
    SessionInfo,
    SessionUser,
    SignInRequest,
)

router = APIRouter(prefix="/api/sessions", tags=["sessions"])


def _set_cookie(response: Response, token: str, session: UserSession) -> None:
    """Give the browser its token, in a cookie locked down as far as browsers allow."""
    response.set_cookie(
        COOKIE_NAME,
        token,
        # Gone from the browser when the session's maximum length is reached.
        max_age=seconds_left(session.expires_at),
        path="/",  # required by the __Host- prefix; no Domain, so this host only
        secure=True,  # only sent over HTTPS (browsers also allow http://localhost)
        httponly=True,  # JavaScript cannot read it, so an XSS bug cannot steal it
        samesite="strict",  # not sent with requests started by other sites (CSRF)
    )


def _clear_cookie(response: Response) -> None:
    """Tell the browser to forget the token."""
    response.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")


def _info(request: Request, db: Session, user: User, session: UserSession) -> SessionInfo:
    """The session's answer: the person, their company, their permissions, and the limit."""
    company = db.get(Company, user.company_id)
    if company is None:  # the session's own company is always visible to it
        raise RuntimeError("the signed-in person's company is missing")
    return SessionInfo(
        user=SessionUser(
            id=user.id,
            display_name=user.display_name,
            email=user.email,
            department_id=user.department_id,
        ),
        company=SessionCompany(id=company.id, name=company.name, timezone=company.timezone),
        # Every permission the person holds somewhere, read fresh on every request, so a
        # role change shows at once. Only for the menu: the API checks every request.
        permissions=effective_permissions(db, user),
        expires_at=session.expires_at.replace(tzinfo=UTC),
        # The key create_app keeps on the app, the same one the CSRF check uses.
        csrf_token=csrf_token(request.app.state.csrf_key, session.token_hash),
    )


@router.post("", status_code=201)
def create_session(
    body: SignInRequest, request: Request, response: Response, db: Database
) -> SessionInfo:
    """Sign in. Every failure gets the same 401 answer (threat I3)."""
    result = sign_in(db, body.email, body.password)
    if result is None:
        raise HTTPException(status_code=401, detail=SIGN_IN_FAILED)
    # The browser's previous session, if any, ends now: it gets only the new token.
    end_previous_session(db, request.cookies.get(COOKIE_NAME))
    _set_cookie(response, result.token, result.session)
    return _info(request, db, result.user, result.session)


@router.get("/current")
def current_session(request: Request, current: SignedInPerson, db: Database) -> SessionInfo:
    """Who is signed in on this browser, and for which company."""
    return _info(request, db, current.user, current.session)


@router.delete("/current", status_code=204)
def delete_current_session(response: Response, current: SignedInPerson, db: Database) -> None:
    """Sign out on this browser."""
    sign_out(db, current)
    _clear_cookie(response)


@router.delete("", status_code=204)
def delete_all_sessions(response: Response, current: SignedInPerson, db: Database) -> None:
    """Sign out on every browser."""
    sign_out_everywhere(db, current)
    _clear_cookie(response)
