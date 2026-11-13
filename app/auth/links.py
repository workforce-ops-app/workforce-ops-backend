"""One-time setup and reset links (authentication.md, "Setup and reset links"; decision 0027).

There is no email service in the core tier, so an administrator creates the link and
passes it on in person or by text. How it works, step by step:

1. Creating a link (create_link): someone with user.manage who is above the person asks
   for a setup link (a new account without a password) or a reset link (a forgotten
   password). The server makes 32 random bytes, stores only their SHA-256, and hands back
   the link once: https://<host>/set-password.html#token=<the token>. The person's
   earlier links are deleted, so only the newest one works.
2. Redeeming it (redeem): the person's browser sends the token and a new password. The
   link must exist, be unused, and be less than 48 hours old; the password must follow
   the usual rules. Then the password is set, the link is marked used, any lockout is
   cleared, and every session of the person ends (a reset may follow a stolen password,
   so nobody stays signed in with the old one).

Why the token is after the "#": browsers never send that part of an address to a server,
so it does not end up in server logs or in the Referer header of other sites. The page
reads it and sends it in the request body instead.

Why SHA-256 is enough here (and not Argon2id, as for passwords): the token is 256 random
bits, so it cannot be guessed, and a fast hash already makes a copied database useless
for setting anyone's password. The same reasoning as for session tokens.

Taking turns: both creating and redeeming lock the person's row first and the link's row
second, always in that order, so two requests for the same person wait for each other
instead of deadlocking, and two redemptions of one link cannot both succeed (the second
reads the link fresh after the first has marked it used). scripts/check_migrations.py
tries that on MySQL.
"""

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from fastapi import HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.auth.models import OneTimeToken, UserSession
from app.auth.passwords import PasswordRejected, check_password, hash_password
from app.auth.sessions import hash_cookie, new_token
from app.authz.check import authorize
from app.db.base import utcnow
from app.db.types import new_id
from app.modules.org.models import Company, User
from app.tenancy.context import set_company
from app.tenancy.filter import cross_company_read

Purpose = Literal["setup", "reset"]

# How long a link works (decision 0027). Companies may shorten it once company settings
# exist (#59), never below 1 hour.
LINK_LIFETIME = timedelta(hours=48)

# The page that reads the token and asks for the new password (frontend).
LINK_PAGE = "/set-password.html"

# The one answer for every link that does not work: unknown, used, expired, cancelled by
# a newer link, or for a deactivated person. Which one is not said: it would only help
# someone holding a link that is not theirs.
LINK_NOT_VALID = "This link does not work. It may be used or expired; ask for a new one."


class NotFound(HTTPException):
    """404: no such person in the user's company."""

    def __init__(self) -> None:
        super().__init__(status_code=404, detail="Not found.")


class Conflict(HTTPException):
    """409: a link of this kind does not fit the account as it is now."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=409, detail=detail)


class LinkNotValid(HTTPException):
    """400: the link does not work (one answer for every reason, see LINK_NOT_VALID)."""

    def __init__(self) -> None:
        super().__init__(status_code=400, detail=LINK_NOT_VALID)


class PasswordNotAccepted(HTTPException):
    """422: the new password breaks a rule; the message says which, in plain words."""

    def __init__(self, detail: str) -> None:
        super().__init__(status_code=422, detail=detail)


@dataclass
class NewLink:
    """A link just created: its row, and the token, which exists only in this answer."""

    link: OneTimeToken
    token: str


def _locked_person(db: Session, person_id: uuid.UUID) -> User | None:
    """The person's row, locked until the end of the transaction and read fresh, so every
    change to this person's links takes turns (see the top of this file)."""
    return db.get(User, person_id, with_for_update=True, populate_existing=True)


def create_link(db: Session, user: User, person_id: uuid.UUID, purpose: Purpose) -> NewLink:
    """Create a setup or reset link for the person, cancelling their earlier links.

    Allowed for someone with user.manage who is above the person (authorize() refuses
    everyone else, and anyone acting on themselves). A setup link is only for an account
    without a password yet, and a reset link only for one with a password; neither for a
    deactivated account (409). Commits.
    """
    # 1. Allowed to create links at all? Checked before the person is even looked up, so
    #    someone without the permission learns nothing about which people exist.
    authorize(db, user, "user.manage")

    # 2. The person, of this company only (another company's person does not exist for
    #    the user: 404), locked so two links for one person are made one after the other.
    person = _locked_person(db, person_id)
    if person is None:
        raise NotFound()

    # 3. Allowed for this person: someone else, in scope, and above them in the reporting
    #    chain (threat E3: one administrator resetting another's password).
    authorize(db, user, "user.manage", person)

    # 4. The kind of link must fit the account.
    if person.deactivated_at is not None:
        raise Conflict("This account is deactivated; reactivate it first.")
    if purpose == "setup" and person.password_hash is not None:
        raise Conflict("This person already has a password; create a reset link instead.")
    if purpose == "reset" and person.password_hash is None:
        raise Conflict("This person has no password yet; create a setup link instead.")

    # 5. Cancel the person's earlier links by deleting them: unused ones stop working at
    #    once, and used or expired ones are cleared away, so a person has at most one row.
    #    A delete with a where clause: the company filter adds the company condition too.
    cancelled = db.execute(delete(OneTimeToken).where(OneTimeToken.user_id == person.id))

    # 6. A new random token; only its SHA-256 is stored.
    token, token_hash = new_token()
    link = OneTimeToken(
        id=new_id(),
        user_id=person.id,
        purpose=purpose,
        token_hash=token_hash,
        created_by=user.id,
        expires_at=utcnow() + LINK_LIFETIME,
    )
    db.add(link)

    # 7. Audited in the same transaction (never the token or its hash).
    record(
        db,
        actor=Actor.user(user.id),
        action="auth.link_created",
        target_type="user",
        target_id=person.id,
        details={
            "purpose": purpose,
            "link_id": str(link.id),
            "links_cancelled": cancelled.rowcount,  # type: ignore[attr-defined]
        },
    )
    db.commit()
    return NewLink(link=link, token=token)


def link_address(origin: str, token: str) -> str:
    """The address to pass on: the application's page, with the token after the "#"."""
    return f"{origin.rstrip('/')}{LINK_PAGE}#token={token}"


def redeem(db: Session, token: str, new_password: str) -> None:
    """Set the person's password with a link. Raises LinkNotValid (400) if the link does
    not work, or PasswordNotAccepted (422) if the password breaks a rule; the link then
    still works, so the person can try another password.

    db must not have a company yet: which company is only known once the link is found.
    """
    # 1. The token's hash. A token of the wrong shape cannot be any link.
    token_hash = hash_cookie(token)
    if token_hash is None:
        raise LinkNotValid()

    # 2. Find the link before the company is known. This is the third (and last) read
    #    allowed to look across companies (cross_company_read; tenancy.md). Only the ID
    #    and company are read here; everything else is read for that company.
    found = db.execute(
        cross_company_read(
            select(OneTimeToken.id, OneTimeToken.company_id).where(
                OneTimeToken.token_hash == token_hash
            )
        )
    ).one_or_none()
    if found is None:
        raise LinkNotValid()
    set_company(db, found.company_id)

    # 3. Lock the person first and the link second, the same order as create_link, then
    #    read the link fresh: a request that used or replaced it meanwhile has committed,
    #    and this one sees that.
    first_look = db.get(OneTimeToken, found.id)
    if first_look is None:
        raise LinkNotValid()
    person = _locked_person(db, first_look.user_id)
    link = db.get(OneTimeToken, found.id, with_for_update=True, populate_existing=True)
    now = utcnow()
    if (
        link is None  # cancelled by a newer link meanwhile
        or link.used_at is not None  # works once
        or link.expires_at <= now  # 48 hours
        or person is None
        or person.deactivated_at is not None  # deactivated people cannot sign in
    ):
        db.rollback()  # releases the locks
        raise LinkNotValid()

    # 4. The usual password rules, with the company's name and the person's names.
    company = db.get(Company, person.company_id)
    if company is None:  # the link's own company is always visible to it
        raise RuntimeError("the link's company is missing")
    try:
        check_password(
            new_password,
            company_name=company.name,
            email=person.email,
            display_name=person.display_name,
        )
    except PasswordRejected as error:
        db.rollback()
        raise PasswordNotAccepted(str(error)) from error

    # 5. Set the password, use up the link, and clear any lockout: the person proved who
    #    they are through the administrator who gave them the link.
    person.password_hash = hash_password(new_password)
    person.password_changed_at = now
    person.failed_sign_ins = 0
    person.locked_until = None
    link.used_at = now

    # 6. End every session of the person, on every browser: after a reset, nobody stays
    #    signed in with the old password (threat S5, test AU8).
    ended = db.execute(delete(UserSession).where(UserSession.user_id == person.id))

    # 7. Audited in the same transaction. The person acts on their own account, though no
    #    session is signed in yet.
    record(
        db,
        actor=Actor.user(person.id),
        action="auth.link_used",
        target_type="user",
        target_id=person.id,
        details={
            "purpose": link.purpose,
            "link_id": str(link.id),
            "sessions_ended": ended.rowcount,  # type: ignore[attr-defined]
        },
    )
    db.commit()
