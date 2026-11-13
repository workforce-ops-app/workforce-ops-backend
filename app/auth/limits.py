"""Slowing down password guessing: lockouts and rate limits (authentication.md, "Lockouts
and rate limits"; decision 0027; threats S1 and D1).

Two separate defenses:

1. LOCKOUTS, per account, kept in the users table (failed_sign_ins, locked_until). Every
   wrong password for an existing account counts: at sign-in, at re-entry, and as the
   current password when changing it. The account is locked for a while at the 5th,
   10th, and every failure from the 15th on:

       failures   5      10      15, 16, 17, ...
       locked     15 min 30 min  1 hour each time (the maximum, never longer)

   A successful sign-in or re-entry resets the count, and so do 24 hours without a
   failure. While locked, sign-in is refused with the same answer as any other failure
   (a lock must not reveal that the account exists), and the password is not checked at
   all, so guesses made during a lock are not even tried. The 1 hour maximum means an
   attacker can delay a real person, but never lock them out for good (threat D1).

2. RATE LIMITS, per address and per session, kept in the API process's memory:

       sign-in attempts per address   20 per minute
       requests per session           300 per minute

   Over the limit, the answer is 429 Too Many Requests with Retry-After (seconds until
   the minute ends). These do not depend on which account was tried, so a 429 reveals
   nothing about accounts. The counts are for one API process, which is how the app runs;
   they reset when it restarts (several servers would need a shared store, 0012).

"24 hours without a failure" is read from users.updated_at: a failure writes the count,
so updated_at is the moment of the last failure, unless something else about the account
changed since, which only delays the reset (the cautious direction). That keeps this
slice free of a migration, as planned.
"""

import math
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.modules.org.models import User

# --- Lockouts ----------------------------------------------------------------------------

# The count resets after this long without a failure.
RESET_AFTER = timedelta(hours=24)
# The longest lock there is (decision 0025: companies may never go past it).
MAX_LOCK = timedelta(hours=1)


def lock_for(failures: int) -> timedelta | None:
    """How long the account is locked after this many failures in a row, if at all."""
    if failures >= 15:
        return MAX_LOCK
    if failures == 10:
        return timedelta(minutes=30)
    if failures == 5:
        return timedelta(minutes=15)
    return None


def is_locked(user: User, now: datetime) -> bool:
    """Whether the account is locked right now."""
    return user.locked_until is not None and user.locked_until > now


def register_failure(db: Session, user: User, now: datetime) -> None:
    """Count one wrong password for the account and lock it if the schedule says so.
    Audited as auth.locked when it locks. The caller commits (with its own audit entry)."""
    # 1. A day without failures starts the count again.
    count = user.failed_sign_ins or 0
    if count and user.updated_at is not None and now - user.updated_at >= RESET_AFTER:
        count = 0
    # 2. This failure.
    count += 1
    user.failed_sign_ins = count
    # 3. Lock, if this is the 5th, the 10th, or the 15th or later.
    duration = lock_for(count)
    if duration is not None:
        user.locked_until = now + duration
        record(
            db,
            actor=Actor.system(),
            action="auth.locked",
            target_type="user",
            target_id=user.id,
            details={"failures": count, "minutes": int(duration.total_seconds() // 60)},
        )


def register_success(user: User) -> None:
    """The right password: the count starts again and any lock ends."""
    if user.failed_sign_ins or user.locked_until is not None:
        user.failed_sign_ins = 0
        user.locked_until = None


# --- Rate limits -------------------------------------------------------------------------


class TooManyRequests(HTTPException):
    """429 with Retry-After: the number of seconds until the limit's minute ends."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(
            status_code=429,
            detail="Too many requests. Wait a moment and try again.",
            headers={"Retry-After": str(retry_after)},
        )


@dataclass
class RateLimit:
    """At most `limit` hits per key in each minute (a fixed one-minute window).

    Only the current minute's counts are kept: when a new minute starts, the old counts
    are dropped in one go, so memory holds at most one minute of keys. A flood of new keys
    (every request from a new address) is still bounded: past `max_keys` in one minute,
    new keys share one overflow count with the same limit, so memory stays small and the
    flood is slowed as a whole.

    A fixed window allows up to twice the limit across the moment one minute turns into
    the next; for slowing guessing that is fine, and it needs no per-request history.
    """

    limit: int
    max_keys: int = 100_000
    # Where "now" comes from, in seconds: replaceable in tests.
    clock: object = field(default=time.time)
    _minute: int = -1
    _counts: dict[object, int] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def hit(self, key: object) -> None:
        """Count one request for the key, or raise TooManyRequests (429) over the limit."""
        now = self.clock()  # type: ignore[operator]
        minute = math.floor(now / 60)
        # One lock for the counts: requests run in several threads at once.
        with self._lock:
            if minute != self._minute:
                self._minute, self._counts = minute, {}
            if key not in self._counts and len(self._counts) >= self.max_keys:
                key = "overflow"
            count = self._counts.get(key, 0) + 1
            self._counts[key] = count
        if count > self.limit:
            # Seconds left in this minute, at least 1.
            raise TooManyRequests(max(1, math.ceil((minute + 1) * 60 - now)))


def client_address(request: Request) -> str:
    """The address the request came from, for the per-address limit.

    uvicorn (the web server) has already set request.client from nginx's X-Forwarded-For
    header, but only for requests whose direct sender is listed in FORWARDED_ALLOW_IPS
    (docker-compose.yml: the shared network nginx is on), and it takes the right-most
    address it does not trust, the one nginx itself added. So a browser cannot pick its
    own address by sending the header: anything it adds stays on the left and is ignored.
    Requests that reach the API directly keep their real sender's address.
    """
    return request.client.host if request.client is not None else "unknown"


@dataclass
class Limits:
    """The API's rate limits, one set per app (create_app puts it in app.state.limits)."""

    sign_in_per_address: RateLimit = field(default_factory=lambda: RateLimit(limit=20))
    requests_per_session: RateLimit = field(default_factory=lambda: RateLimit(limit=300))
