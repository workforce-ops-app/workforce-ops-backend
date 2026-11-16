"""Entering the password again: before sensitive actions, and to change your own password
(authentication.md, "Password re-entry for sensitive actions"; decision 0025).

Why: a session left open on a shared computer, or a stolen session cookie, lets someone act
as the person without knowing their password (threat S2). For the actions that could do
the most damage, the session alone is not enough: the password must have been entered in
this session within the last 5 minutes.

How it works, step by step:
1. A sensitive action calls require_reauth(session) before it changes anything. Without a
   recent re-entry it answers 403 with the problem type "reauth-required".
2. The interface (js/api/client.js) sees that type, asks for the password, and sends it to
   POST /api/sessions/current/reauth. reauthenticate() checks it and, if it is right,
   stores the moment in the session's reauth_at.
3. The interface repeats the original request, which now passes.

The re-entry belongs to one session: entering the password on one browser does not count
on another. A wrong password is recorded as auth.reauth_failed; once lockouts exist (#50)
it also counts toward the account's lockout, like a wrong password at sign-in.

Changing your own password needs the current password too (an open session must not be
enough to lock the real owner out). It ends every session of the person and gives this
browser a brand-new one (a new token, so a copy of the old cookie stops working), with the
same end date as before: changing the password never makes a session last longer.
"""

from dataclasses import dataclass
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.auth.models import UserSession
from app.auth.passwords import check_password, hash_password, needs_rehash, verify_password
from app.auth.sessions import Current, SignedIn, new_token
from app.db.base import utcnow
from app.db.types import new_id
from app.modules.org.models import Company

# How long a re-entry counts (decision 0025).
REAUTH_WINDOW = timedelta(minutes=5)

# The answer to a wrong password, at re-entry and when changing the password.
WRONG_PASSWORD = "That password is not right."  # noqa: S105 (a message, not a password)


class ReauthRequired(HTTPException):
    """403 with the problem type "reauth-required": enter the password, then try again.

    The error handler (app/core/errors.py) puts problem_type into the answer's "type", so
    the interface can tell this 403 from any other and ask for the password.
    """

    problem_type = "reauth-required"

    def __init__(self) -> None:
        super().__init__(status_code=403, detail="Enter your password again to do this.")


class WrongPassword(HTTPException):
    """403: the password sent is not the person's password."""

    def __init__(self) -> None:
        super().__init__(status_code=403, detail=WRONG_PASSWORD)


def require_reauth(session: UserSession) -> None:
    """Refuse (ReauthRequired) unless the password was entered in this session within the
    last 5 minutes. Sensitive actions call this before changing anything."""
    if session.reauth_at is None or utcnow() - session.reauth_at > REAUTH_WINDOW:
        raise ReauthRequired()


def _matches(current: Current, password: str) -> bool:
    """Whether the password is the signed-in person's own. Someone signed in always has a
    password (no session starts without one); the check is there for safety."""
    stored = current.user.password_hash
    return stored is not None and verify_password(stored, password)


def _record_failure(db: Session, current: Current, during: str) -> None:
    """Record a wrong password (never the password itself) and save it at once, so a
    refused attempt is kept even though the request fails."""
    record(
        db,
        actor=Actor.user(current.user.id),
        action="auth.reauth_failed",
        target_type="session",
        target_id=current.session.id,
        details={"during": during},  # "reauth" or "password_change"
    )
    db.commit()


def reauthenticate(db: Session, current: Current, password: str) -> None:
    """Check the password again; on success, sensitive actions are allowed for 5 minutes in
    this session. Raises WrongPassword (403) if it is not right."""
    if not _matches(current, password):
        _record_failure(db, current, "reauth")
        raise WrongPassword()
    # Right. As at sign-in, a hash made with older, weaker settings is renewed now, while
    # the plain password is in hand.
    if current.user.password_hash is not None and needs_rehash(current.user.password_hash):
        current.user.password_hash = hash_password(password)
    current.session.reauth_at = utcnow()
    db.commit()


@dataclass
class PasswordChanged:
    """The new session that replaces the old one, and its token for the cookie."""

    signed_in: SignedIn
    other_sessions_ended: int


def change_password(
    db: Session, current: Current, current_password: str, new_password: str
) -> PasswordChanged:
    """Change the signed-in person's own password; see the top of this file.

    Raises WrongPassword (403) if current_password is wrong, and PasswordRejected (shown as
    422 by the endpoint) if the new password breaks a rule. Nothing changes in either case.
    """
    user = current.user
    # 1. The current password first: someone who only has the session learns nothing more,
    #    not even whether a new password would pass the rules.
    if not _matches(current, current_password):
        _record_failure(db, current, "password_change")
        raise WrongPassword()
    # 2. The same rules as every password (app/auth/passwords.py): length, the blocklist,
    #    and not the person's or the company's name.
    company = db.get(Company, user.company_id)
    if company is None:  # the session's own company is always visible to it
        raise RuntimeError("the signed-in person's company is missing")
    check_password(
        new_password, company_name=company.name, email=user.email, display_name=user.display_name
    )

    # 3. Save the new password (only its Argon2id hash).
    now = utcnow()
    user.password_hash = hash_password(new_password)
    user.password_changed_at = now

    # 4. End every session of the person, this one included. A delete with a where
    #    clause: the company filter limits it to this company too.
    ended = db.execute(delete(UserSession).where(UserSession.user_id == user.id))
    other_sessions = max(0, int(ended.rowcount or 0) - 1)  # type: ignore[attr-defined]

    # 5. A brand-new session for this browser: a new token, the old end date (never
    #    longer), and the password counts as just entered.
    token, token_hash = new_token()
    session = UserSession(
        id=new_id(),
        user_id=user.id,
        token_hash=token_hash,
        expires_at=current.session.expires_at,
        last_seen_at=now,
        reauth_at=now,
    )
    db.add(session)
    record(
        db,
        actor=Actor.user(user.id),
        action="auth.password_changed",
        target_type="user",
        target_id=user.id,
        details={"other_sessions_ended": other_sessions},
    )
    db.commit()
    return PasswordChanged(SignedIn(user=user, session=session, token=token), other_sessions)
