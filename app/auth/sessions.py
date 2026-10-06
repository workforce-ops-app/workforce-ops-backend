"""Signing in and out, and loading the signed-in person's session on every request.

Course topic: sessions (authentication.md, decision 0027). How it works, step by step:

1. Sign-in checks the email and password. Every failure (unknown email, wrong password,
   no password yet, deactivated, locked) gets the same answer after the same amount of
   work, so the sign-in form never reveals which emails have accounts (threat I3).
2. On success, the server makes a new random token (32 bytes from the operating system's
   secure generator) and stores only its SHA-256 in the sessions table. The browser gets
   the token itself, once, in the __Host-session cookie.
3. On every later request, the cookie's token is hashed again and looked up. The row says
   who is signed in and for which company; the company is set on the database session,
   so the company filter (app/tenancy/) limits everything after that to this company.
4. A session ends after 1 hour without requests, or 30 days after sign-in, whichever
   comes first. Signing out deletes the row, so the token stops working at once.

Why SHA-256 here but Argon2id for passwords: a token is 256 random bits and cannot be
guessed, so a fast hash is enough to make a leaked database useless for taking over
sessions. Passwords are short and chosen by people, so they need a slow hash.
"""

import base64
import binascii
import hashlib
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.auth.models import UserSession
from app.auth.passwords import hash_password, needs_rehash, verify_password
from app.db.base import utcnow
from app.db.types import new_id
from app.modules.org.models import User
from app.tenancy.context import get_company, set_company
from app.tenancy.filter import cross_company_read

logger = logging.getLogger(__name__)

# The cookie's name. The __Host- prefix makes the browser accept it only over HTTPS, for
# this exact host, with Path=/, so a subdomain can never plant or overwrite it.
COOKIE_NAME = "__Host-session"

# The two time limits (decision 0027); companies may shorten them later (0025).
IDLE_TIMEOUT = timedelta(hours=1)
MAX_LENGTH = timedelta(days=30)
# last_seen_at is written at most this often, so most requests need no write at all.
SEEN_EVERY = timedelta(minutes=1)

# The one answer for every failed sign-in.
SIGN_IN_FAILED = (
    "Email or password is incorrect. After several failed attempts, sign-in is paused for a while."
)

TOKEN_BYTES = 32

# Every failed sign-in takes at least this long. The checks already do the same Argon2id
# work in every case, but a failure for an existing account also writes an audit entry,
# a few milliseconds an unknown email does not spend; measured over many tries, that
# difference could reveal which emails have accounts (threat I3). Waiting until a fixed
# minimum hides it. Kept above the Argon2id time (about 0.5 s on the server).
FAILED_SIGN_IN_SECONDS = 0.5


@lru_cache
def _dummy_hash() -> str:
    """An Argon2id hash of a random password nobody knows, made once.

    When there is no real hash to check (unknown email, no password yet), the password is
    checked against this one instead, so those failures take as long as a wrong password.
    """
    return hash_password(secrets.token_urlsafe(32))


def new_token() -> tuple[str, bytes]:
    """A new session token: the text for the cookie, and the SHA-256 to store."""
    raw = secrets.token_bytes(TOKEN_BYTES)
    # URL-safe base64 without padding: 43 characters, safe in a cookie.
    text = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return text, hashlib.sha256(raw).digest()


def hash_cookie(value: str | None) -> bytes | None:
    """The SHA-256 of a cookie's token, or None if the cookie is missing or malformed."""
    if not value or len(value) != 43:
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (binascii.Error, ValueError):
        return None
    return hashlib.sha256(raw).digest() if len(raw) == TOKEN_BYTES else None


@dataclass
class SignedIn:
    """A successful sign-in: the person, their new session, and the token for the cookie."""

    user: User
    session: UserSession
    token: str


def sign_in(db: Session, email: str, password: str) -> SignedIn | None:
    """Check an email and password, and start a new session. None means: refused.

    db must not have a company yet: which company is only known once the person is found.
    A refusal returns only after FAILED_SIGN_IN_SECONDS, whatever the reason.
    """
    started = time.monotonic()
    result = _check_and_start(db, email, password)
    if result is None:
        # Sleep away whatever is left of the minimum, so every failure takes as long.
        time.sleep(max(0.0, started + FAILED_SIGN_IN_SECONDS - time.monotonic()))
    return result


def _check_and_start(db: Session, email: str, password: str) -> SignedIn | None:
    """sign_in without the minimum time: the checks and the new session."""
    # 1. Find the account by email, across companies (emails are unique on the platform).
    #    This is one of the two reads allowed to look across companies (cross_company_read).
    #    Only the ID and company are read here; everything else is read for that company.
    found = db.execute(
        cross_company_read(
            select(User.id, User.company_id).where(User.email == email.strip().lower())
        )
    ).one_or_none()

    if found is None:
        # No such account: do the same work as a wrong password, then refuse. Logged
        # without the email, which might be a password typed into the wrong field.
        verify_password(_dummy_hash(), password)
        logger.info("sign-in failed: no account with that email")
        return None

    # 2. From here on the database session works for the person's company.
    set_company(db, found.company_id)
    user = db.get(User, found.id)
    if user is None:  # found a moment ago, so only a concurrent change gets here
        return None
    now = utcnow()

    # 3. Check the password, always, so every case takes the same time. Without a password
    #    yet, the dummy hash is checked (and cannot match).
    matches = verify_password(user.password_hash or _dummy_hash(), password)

    # 4. Refuse anything but an active, unlocked account with a matching password.
    reason = None
    if user.password_hash is None:
        reason = "no_password"
    elif user.deactivated_at is not None:
        reason = "deactivated"
    elif user.locked_until is not None and user.locked_until > now:
        reason = "locked"
    elif not matches:
        reason = "wrong_password"
    if reason is not None:
        # Recorded in the company's audit log (never the password). Nobody is signed in,
        # so the actor is the system; the target is the account that was tried.
        record(
            db,
            actor=Actor.system(),
            action="auth.sign_in_failed",
            target_type="user",
            target_id=user.id,
            details={"reason": reason},
        )
        db.commit()
        return None

    # 5. Correct. If the password was hashed with older, weaker settings, hash it again
    #    now, while the plain password is in hand (authentication.md).
    if user.password_hash is not None and needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    # 6. Clear away this person's sessions that have already ended (past 30 days, or idle
    #    for an hour) but were never presented again, so old rows do not pile up. A delete
    #    with a where clause: the company filter limits it to this company as well.
    db.execute(
        delete(UserSession).where(
            UserSession.user_id == user.id,
            (UserSession.expires_at <= now) | (UserSession.last_seen_at <= now - IDLE_TIMEOUT),
        )
    )

    # 7. A brand-new session with a brand-new token: a token from before sign-in (planted
    #    by an attacker, for example) never becomes a signed-in session (session fixation).
    token, token_hash = new_token()
    session = UserSession(
        id=new_id(),
        user_id=user.id,
        token_hash=token_hash,
        expires_at=now + MAX_LENGTH,
        last_seen_at=now,
    )
    db.add(session)
    record(
        db,
        actor=Actor.user(user.id),
        action="auth.signed_in",
        target_type="session",
        target_id=session.id,
    )
    db.commit()
    return SignedIn(user=user, session=session, token=token)


@dataclass
class Current:
    """The signed-in person of this request, and their session."""

    user: User
    session: UserSession

    @property
    def company_id(self) -> uuid.UUID:
        return self.user.company_id


def load_session(db: Session, cookie: str | None) -> Current | None:
    """The session behind a request's cookie, or None if it is missing, unknown, or ended.

    On success the database session is set to the person's company, so every query after
    this is limited to that company.
    """
    token_hash = hash_cookie(cookie)
    if token_hash is None:
        return None

    # The other read allowed across companies: the cookie does not say which company.
    found = db.execute(
        cross_company_read(
            select(UserSession.id, UserSession.company_id).where(
                UserSession.token_hash == token_hash
            )
        )
    ).one_or_none()
    if found is None:
        return None

    set_company(db, found.company_id)
    session = db.get(UserSession, found.id)
    user = db.get(User, session.user_id) if session is not None else None
    if session is None or user is None:
        return None

    # Ended: past the maximum length, idle for an hour, or the person was deactivated.
    # The row is deleted, so the token can never be used again.
    now = utcnow()
    if (
        now >= session.expires_at
        or now - session.last_seen_at >= IDLE_TIMEOUT
        or user.deactivated_at is not None
    ):
        db.delete(session)
        db.commit()
        return None

    # Still active: note the activity (at most once a minute), which restarts the idle timer.
    if now - session.last_seen_at >= SEEN_EVERY:
        session.last_seen_at = now
        db.commit()
    return Current(user=user, session=session)


def end_previous_session(db: Session, cookie: str | None) -> None:
    """End the session a browser carried before signing in again, if it still works.

    The browser gets a new token at sign-in, but the old session would otherwise stay valid
    (for anyone holding a copy of its token) until it timed out. It may belong to another
    company, so it is looked up and ended in a database session of its own.
    """
    with Session(db.get_bind()) as other:
        previous = load_session(other, cookie)
        if previous is not None:
            sign_out(other, previous)


def sign_out(db: Session, current: Current) -> None:
    """End this session: its token stops working at once."""
    db.delete(current.session)
    db.commit()


def sign_out_everywhere(db: Session, current: Current) -> None:
    """End every session of the signed-in person, on every browser."""
    # A delete with a where clause: the company filter adds the company condition too.
    if get_company(db) != current.company_id:
        raise RuntimeError("the database session must work for the signed-in company")
    db.execute(delete(UserSession).where(UserSession.user_id == current.user.id))
    db.commit()


def seconds_left(expires_at: datetime) -> int:
    """Seconds until a session's maximum length is reached, for the cookie's Max-Age."""
    return max(0, int((expires_at - utcnow()).total_seconds()))
