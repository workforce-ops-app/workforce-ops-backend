"""Verifying audit chains: on demand for one company, and nightly for every chain
(docs/architecture/audit-log.md, verification).

The checking itself is app/audit/verify.py. This file decides WHICH chain is checked,
who may ask, and what happens with the result:

- Every check is recorded in the chain it checked, as an audit entry `audit.verified`
  with what was found. A broken chain still takes new entries (record() links them to
  the head), so the record of the check survives next to the damage it found.
- A failure also becomes a security event, so it shows on the security page (DT5):
  - on demand: in the company's own security_events, naming the person who ran it;
  - nightly: in platform_security_events, which has no company or person (rule DE9),
    so the row only says that a chain failed; which one is in the application log.
- Nightly, each chain's head (seq and signature) is also written to the application log.
  That copy lives outside the database, so if the whole database were put back to an
  older state (removing entries AND moving the head back), the head in the log from an
  earlier night would be further along than the one in the database.
"""

import logging
import uuid
from typing import Any

from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.audit.models import PLATFORM_CHAIN_ID, AuditChainHead, AuditEvent
from app.audit.verify import Result, available_keys, verify_chain
from app.authz.check import authorize
from app.db.base import utcnow
from app.modules.org.models import User
from app.modules.security import repository as security_events
from app.modules.security.models import SecurityEvent
from app.tenancy.context import get_company, set_company

logger = logging.getLogger(__name__)

# The security event kind for a chain that failed its check.
CHAIN_BROKEN = "audit.chain_broken"


def _details(result: Result, *, nightly: bool) -> dict[str, Any]:
    """What the audit entry of a check keeps: the result, never a key or a signature."""
    return {
        "ok": result.ok,
        "checked": result.checked,
        "last_seq": result.last_seq,
        "first_bad_seq": result.first_bad_seq,
        "problem": result.problem,
        "nightly": nightly,
    }


def verify_company_chain(db: Session, user: User) -> Result:
    """Check the signed-in person's company's chain now (POST /api/audit/verify)."""
    # 1. Permission first: audit.verify is a company permission (Owner and Administrator).
    authorize(db, user, "audit.verify")
    # 2. The chain is the session's company, set from the person's session at sign-in
    #    (app/auth/dependencies.py), never an ID from the request: the audit tables are not
    #    company-filtered, so this is what keeps one company from checking another's.
    company_id = get_company(db)
    if company_id is None:  # a signed-in request always works for its company
        raise RuntimeError("verify_company_chain needs a session working for a company")
    result = verify_chain(db, company_id, available_keys())

    # 3. Record the check in the chain it checked, and a failure as a security event.
    record(
        db,
        actor=Actor.user(user.id),
        action="audit.verified",
        details=_details(result, nightly=False),
    )
    if not result.ok:
        # The company filter fills in company_id from the session (tenancy layer 1).
        db.add(
            SecurityEvent(
                kind=CHAIN_BROKEN,
                user_id=user.id,
                method="POST",
                route="/api/audit/verify",
                excerpt=f"first bad entry {result.first_bad_seq}",
                occurred_at=utcnow(),
            )
        )
        _log_failure(result)
    db.commit()
    return result


def _every_chain(engine: Engine) -> list[uuid.UUID]:
    """Every chain there is: each head, and (in case a head was removed) each chain an
    entry names. Read by platform code: a session with no company."""
    with Session(engine) as platform:
        heads = set(platform.scalars(select(AuditChainHead.chain_id)))
        named = set(platform.scalars(select(AuditEvent.chain_id).distinct()))
    return sorted(heads | named)


def verify_every_chain(engine: Engine) -> list[Result]:
    """The nightly check: every chain from the start, each in its own transaction."""
    keys = available_keys()  # before anything: no key, no check (AuditError)
    results = []
    for chain_id in _every_chain(engine):
        # A company's chain is checked, and its result recorded, in a session working for
        # that company (record() takes the chain from the session); the platform chain in
        # a session with no company.
        company_id = None if chain_id == PLATFORM_CHAIN_ID else chain_id
        with Session(engine) as db:
            if company_id is not None:
                set_company(db, company_id)
            result = verify_chain(db, chain_id, keys)
            # The outside copy: the head as it was when this check read it. IDs and
            # numbers only (decision 0031); a signature is not secret, and it is the point.
            logger.info(
                "audit chain head",
                extra={
                    "fields": {
                        "chain_id": str(chain_id),
                        "last_seq": result.last_seq,
                        "last_signature": result.head_signature.hex(),
                    }
                },
            )
            record(
                db,
                actor=Actor.system(),
                action="audit.verified",
                details=_details(result, nightly=True),
            )
            db.commit()
        if not result.ok:
            _log_failure(result)
            # No company or person on this table (DE9): which chain is in the log line.
            security_events.insert_platform_events(
                engine,
                [
                    {
                        "kind": CHAIN_BROKEN,
                        "excerpt": "an audit chain failed its nightly check; see the log",
                        "occurred_at": utcnow(),
                    }
                ],
            )
        results.append(result)
    return results


def _log_failure(result: Result) -> None:
    """A failed check in the application log, for whoever looks after the platform."""
    logger.error(
        "audit chain failed verification",
        extra={
            "fields": {
                "chain_id": str(result.chain_id),
                "first_bad_seq": result.first_bad_seq,
                "problem": result.problem,
            }
        },
    )
