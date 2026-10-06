"""Writing an audit entry: record() (audit-log.md, decision 0018).

    record(session, actor=Actor.user(user_id), action="shift.assigned",
           target_type="shift", target_id=shift.id, details={"employee_id": "..."})

Service code calls it in the same session as the action it records, before the session
is committed. It never commits itself. So the action and its entry are saved together or
not at all: an action cannot succeed without its entry, and a failed action leaves no
entry behind.

Which chain: the session's company (app/tenancy/context.py), never a value from the
caller, so one company's actions can never be written into another company's log. A
session with no company is platform code and writes to the platform chain.
"""

import copy
import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import (
    ACTOR_TYPES,
    NO_SIGNATURE,
    PLATFORM_CHAIN_ID,
    AuditChainHead,
    AuditEvent,
)
from app.audit.signing import sign
from app.core.config import get_settings
from app.db.base import utcnow
from app.db.types import new_id
from app.tenancy.context import get_company


class AuditError(RuntimeError):
    """An audit entry could not be written, so the action must not go ahead either."""


@dataclass(frozen=True)
class Actor:
    """Who did something: a person (user), platform staff (platform_user), or the system."""

    type: str
    id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        # The same rule as the table's CHECK constraint, caught early with a clear message.
        if self.type not in ACTOR_TYPES:
            raise AuditError(f"unknown actor type: {self.type!r}")
        if (self.type == "system") != (self.id is None):
            raise AuditError("the system acts without an ID; everyone else needs one")

    @classmethod
    def user(cls, user_id: uuid.UUID) -> "Actor":
        """A person of the session's company."""
        return cls("user", user_id)

    @classmethod
    def system(cls) -> "Actor":
        """The application itself, for automatic actions such as expirations."""
        return cls("system")


# Actions are dotted lowercase names: "shift.assigned", "auth.sign_in_failed".
_ACTION = re.compile(r"^[a-z_]+(\.[a-z_]+)+$")

# The range of whole numbers MySQL's JSON column stores exactly (64 bits). A larger one
# would come back changed, like a decimal, and no longer match its signature.
_SMALLEST_INT = -(2**63)
_LARGEST_INT = 2**64 - 1

# Words that must never appear in a details key, at any depth: the log is kept forever
# and read by owners, so it must not become a store of passwords, tokens, or secrets
# (or their hashes, which can be attacked offline).
_FORBIDDEN_KEY_WORDS = ("password", "token", "secret", "hash")


def _check_details(value: Any, path: str = "details") -> None:
    """Refuse details that are unsafe to keep, or that would not sign the same way later.

    Allowed: objects with text keys, lists, text, whole numbers (64 bits), true/false, and
    null. Keys are checked for words that mean credentials; values cannot be checked that
    way, so callers never put credentials into details at all.
    Decimal numbers are refused: the database may write them back differently (1.0 as 1),
    which would change the signed bytes. Store amounts as text or whole numbers instead.
    """
    if isinstance(value, dict):
        for key, inner in value.items():
            if not isinstance(key, str):
                raise AuditError(f"{path}: keys must be text")
            if any(word in key.lower() for word in _FORBIDDEN_KEY_WORDS):
                raise AuditError(f"{path}.{key}: passwords, tokens, and secrets are never logged")
            _check_details(inner, f"{path}.{key}")
    elif isinstance(value, list):
        for index, inner in enumerate(value):
            _check_details(inner, f"{path}[{index}]")
    # bool is a kind of int in Python, so it passes this check too.
    elif value is not None and not isinstance(value, str | int):
        raise AuditError(f"{path}: only text, whole numbers, true/false, and null")
    elif isinstance(value, int) and not _SMALLEST_INT <= value <= _LARGEST_INT:
        raise AuditError(f"{path}: whole numbers must fit in 64 bits")


def _signing_key() -> tuple[bytes, str]:
    """The signing key (as bytes) and its ID, from the settings; never from the database."""
    settings = get_settings()
    if settings.audit_signing_key is None:
        # Refuse instead of writing unsigned entries: the action fails with it.
        raise AuditError("AUDIT_SIGNING_KEY is not set, so no audit entry can be written")
    return settings.audit_signing_key.get_secret_value().encode("utf-8"), settings.audit_key_id


def record(
    session: Session,
    *,
    actor: Actor,
    action: str,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Add one signed entry to the session's chain, in the session's transaction.

    Returns the entry. Raises AuditError, before anything is written, if the entry is not
    allowed (no signing key, a malformed action, unsafe details, a person acting outside a
    company session).
    """
    # 1. Check everything before touching the database.
    key, key_id = _signing_key()
    if not _ACTION.match(action) or len(action) > 100:
        raise AuditError(f"action must be a dotted lowercase name: {action!r}")
    # A deep copy: the entry keeps exactly what was signed, even if the caller later
    # changes its own dictionary.
    details = copy.deepcopy(details or {})
    _check_details(details)

    # 2. Which chain: the session's company, or the platform chain for platform code.
    company_id = get_company(session)
    if company_id is None and actor.type == "user":
        raise AuditError("a person's action is recorded in a session for their company")
    chain_id = company_id if company_id is not None else PLATFORM_CHAIN_ID

    # 3. Lock the chain's head (SELECT ... FOR UPDATE). Another transaction adding to the
    #    same chain now waits here until this one commits or rolls back, so two entries
    #    can never take the same number. Other companies' chains are not blocked.
    #    populate_existing: use the row just read under the lock, even if this session
    #    already holds an older copy of the head (another transaction may have added
    #    entries since); otherwise the entry would reuse a number and fail.
    head = session.scalars(
        select(AuditChainHead)
        .where(AuditChainHead.chain_id == chain_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()

    # A chain's first entry creates its head. If two first entries ever raced, the head's
    # primary key lets only one transaction create it; the other fails and rolls back,
    # with its action, instead of starting a second chain.
    if head is None:
        head = AuditChainHead(
            chain_id=chain_id, company_id=company_id, last_seq=0, last_signature=NO_SIGNATURE
        )
        session.add(head)
        session.flush()

    # 4. The entry, numbered after the newest one and linked to its signature.
    event = AuditEvent(
        id=new_id(),
        chain_id=chain_id,
        seq=head.last_seq + 1,
        company_id=company_id,
        actor_type=actor.type,
        actor_id=actor.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        # Whole microseconds, as DATETIME(6) stores them, so the signed value is exactly
        # the value read back later.
        occurred_at=utcnow(),
        details=details,
        key_id=key_id,
        prev_signature=head.last_signature,
    )

    # 5. Sign it (app/audit/signing.py), then move the head to it.
    event.signature = sign(key, event, head.last_signature)
    session.add(event)
    head.last_seq = event.seq
    head.last_signature = event.signature

    # 6. Send both to the database now, inside the caller's transaction, so a problem
    #    shows up here rather than at commit. Committing is the caller's job.
    session.flush()
    return event
