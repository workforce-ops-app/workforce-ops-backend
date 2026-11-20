"""Company sign-up: one transaction creates a company, its starting roles, a first
department, the owner's account, and the owner's session (docs/features/organization.md,
company sign-up).

Why the work is split across sessions on one connection
-------------------------------------------------------
The company row must be inserted by platform code (a session with no company), and
everything inside the company by a session working for it (the company filter fills in
company_id and refuses anything else). So, as seed_company() in scripts/seed_demo.py
does, one connection is opened with engine.begin() and every session is created on it.
A session given a connection that is already in a transaction only flushes: it never
commits or rolls back. The whole block commits at its end, or rolls back completely if
anything inside raises, leaving nothing behind (no company, role, account, session, or
audit entry in either chain).

The order, and why
------------------
1. Before the transaction (in the router and below): the fields, the password rules,
   and the password hash (the slow part, kept outside any lock), and the per-address
   limit.
2. Platform session: lock the platform audit chain's head (SELECT ... FOR UPDATE), count
   the companies created in the last hour, refuse at 200 (429), then insert the company.
   Sign-ups take turns here, which also makes the platform limit exact.
3. Company session: General, the owner, the starting roles, the owner's roles, the
   session row, and the company chain's entries. A taken email fails here on the unique
   key, and everything rolls back.
4. Platform session again: platform.company_signed_up, last, once everything else has
   been flushed. The platform chain refuses a person as actor, so the actor is system.
5. Commit at the end of the block. Only then does the router set the cookie.

Lock order: the platform chain's head first, then the new company's rows (which no
other transaction can see yet), so sign-ups cannot deadlock with each other.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.audit.models import PLATFORM_CHAIN_ID, AuditChainHead
from app.auth.limits import TooManyRequests
from app.auth.models import UserSession
from app.auth.passwords import check_password, hash_password
from app.auth.sessions import MAX_LENGTH, new_token
from app.authz.roles import assign_role, create_starting_roles
from app.db.base import utcnow
from app.db.types import new_id
from app.modules.org.models import Company, Department, User
from app.modules.org.people import EMAIL_TAKEN
from app.modules.sign_up.schemas import SignUpRequest
from app.tenancy.context import set_company

logger = logging.getLogger(__name__)

# At most this many new companies an hour on the whole platform (the per-address limit
# is in app/auth/limits.py). Counted in the database, so it holds however many API
# processes run.
PLATFORM_PER_HOUR = 200

# The first department every company gets: everyone needs a home department.
FIRST_DEPARTMENT = "General"


class EmailTaken(Exception):  # noqa: N818 (named for what happened, like PasswordRejected)
    """The email already has an account somewhere on the platform (409, EMAIL_TAKEN)."""

    message = EMAIL_TAKEN


@dataclass
class SignedUp:
    """What the router needs to answer: the owner, their session, and its token."""

    company_id: uuid.UUID
    user_id: uuid.UUID
    session_id: uuid.UUID
    token: str


def sign_up(engine: Engine, body: SignUpRequest) -> SignedUp:
    """Create the company and its owner, signed in. Raises PasswordRejected (a weak
    password, before anything is tried), EmailTaken, or TooManyRequests (the platform
    limit). On any of these nothing is saved."""
    password = body.password.get_secret_value()
    # Step 1: the password rules, then the hash, both before the email is tried, so a
    # taken email takes as long as a new one. A new company has chosen no settings yet,
    # so the minimum is the platform default (check_password's own).
    check_password(
        password,
        company_name=body.company_name,
        email=body.email,
        display_name=body.display_name,
    )
    password_hash = hash_password(password)
    try:
        return _create(engine, body, password_hash)
    except EmailTaken:
        # Logged without the email, which is personal data.
        logger.info("sign-up refused: email already has an account")
        raise
    except (IntegrityError, OperationalError) as error:
        # Only without migration 0011's head: the platform chain had no head yet, so the
        # lock in step 2 had no row to hold, and another first sign-up ran at the same
        # moment. Either the head's primary key
        # let only the other one create it (IntegrityError), or MySQL saw both waiting on
        # the same empty gap and stopped one as a deadlock (error 1213). Either way this
        # whole transaction rolled back. Tried once more, now that the head exists; any
        # other database problem is raised again by the second attempt.
        if isinstance(error, OperationalError) and not _is_deadlock(error):
            raise
        return _create(engine, body, password_hash)


def _is_deadlock(error: OperationalError) -> bool:
    """Whether MySQL ended the transaction as a deadlock (error 1213)."""
    args: tuple[object, ...] = tuple(getattr(error.orig, "args", ()))
    return len(args) > 0 and args[0] == 1213


def _create(engine: Engine, body: SignUpRequest, password_hash: str) -> SignedUp:
    """Steps 2 to 5, in one transaction (see the top of this file)."""
    with engine.begin() as connection:
        # Step 2: platform code. Lock the platform chain's head so sign-ups take turns,
        # then count this hour's new companies while holding it. The head always exists
        # in MySQL (migration 0011 creates it empty), so the lock always has a row.
        with Session(connection) as platform:
            platform.scalars(
                select(AuditChainHead)
                .where(AuditChainHead.chain_id == PLATFORM_CHAIN_ID)
                .with_for_update()
            ).one_or_none()
            since = utcnow() - timedelta(hours=1)
            recent = platform.scalar(
                # Counted through the model's column, so the company filter sees which
                # model is read (a platform session may read the companies table).
                select(func.count(Company.id)).where(Company.created_at >= since)
            )
            if (recent or 0) >= PLATFORM_PER_HOUR:
                raise TooManyRequests(retry_after=3600)
            company = Company(name=body.company_name, timezone=body.timezone)
            platform.add(company)
            platform.flush()  # sends the row and gives the company its ID; not saved yet
            company_id = company.id

        # Step 3: everything inside the new company.
        with Session(connection) as session:
            set_company(session, company_id)
            signed_up = _inside_company(session, company_id, body, password_hash)

        # Step 4: the platform's own record, last. Only the company's ID: platform
        # operators can count and review sign-ups without reading company data.
        with Session(connection) as platform:
            record(
                platform,
                actor=Actor.system(),
                action="platform.company_signed_up",
                target_type="company",
                target_id=company_id,
                details={"company_id": str(company_id)},
            )
    # Step 5: the block above committed on leaving it.
    return signed_up


def _inside_company(
    session: Session, company_id: uuid.UUID, body: SignUpRequest, password_hash: str
) -> SignedUp:
    """The company's first department, its owner, roles, and the owner's session, each
    audited in the company's own chain. Everything is only flushed: the caller commits."""
    general = Department(name=FIRST_DEPARTMENT)
    session.add(general)
    session.flush()  # gives the department its ID for the owner

    owner = User(
        email=body.email.lower(),
        display_name=body.display_name,
        department_id=general.id,
        password_hash=password_hash,
    )
    session.add(owner)
    try:
        session.flush()  # a taken email (in any company, any case) fails here
    except IntegrityError:
        # The unique key on users.email: the only key the new company's rows can collide
        # on, as every other row is new. Raising leaves engine.begin(), which rolls
        # everything back, the company row included.
        raise EmailTaken() from None
    actor = Actor.user(owner.id)

    record(
        session,
        actor=actor,
        action="company.created",
        target_type="company",
        target_id=company_id,
        details={"name": body.company_name, "timezone": body.timezone},
    )
    record(
        session,
        actor=actor,
        action="department.created",
        target_type="department",
        target_id=general.id,
        details={"name": FIRST_DEPARTMENT},
    )
    # The four starting roles, the owner's account entry, then the owner's roles: Owner
    # for the whole company and Employee for General, as the seed script gives its
    # owners. No reporting lines: the Owner is above everyone.
    roles = create_starting_roles(session, actor)
    record(
        session,
        actor=actor,
        action="user.created",
        target_type="user",
        target_id=owner.id,
        details={"via": "sign_up"},
    )
    assign_role(session, actor, user_id=owner.id, role=roles["owner"], scope_type="company")
    assign_role(
        session,
        actor,
        user_id=owner.id,
        role=roles["employee"],
        scope_type="department",
        scope_id=general.id,
    )

    # A new session, exactly as at sign-in: a new token, of which only the hash is kept.
    now = utcnow()
    token, token_hash = new_token()
    user_session = UserSession(
        id=new_id(),
        user_id=owner.id,
        token_hash=token_hash,
        expires_at=now + MAX_LENGTH,
        last_seen_at=now,
    )
    session.add(user_session)
    record(
        session,
        actor=actor,
        action="auth.signed_in",
        target_type="session",
        target_id=user_session.id,
    )
    session.flush()
    return SignedUp(
        company_id=company_id, user_id=owner.id, session_id=user_session.id, token=token
    )
