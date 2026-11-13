"""Checking an audit chain: verify_chain() (audit-log.md, verification; decision 0018).

The log is only evidence if someone checks it. verify_chain() reads one chain from its
first entry to its last and recomputes everything record() wrote:

1. The numbering: 1, 2, 3... with no gaps. A missing number is a removed entry.
2. The links: each entry's prev_signature is the signature of the entry before it (32
   zero bytes before the first). A broken link is an entry removed or put in between.
3. The signatures: each one is recomputed with the signing key (app/audit/signing.py). A
   wrong signature is an entry that was changed, or one written without the key.
4. The end: the last entry found must be the one the chain head points at (its seq and
   signature). Each entry only vouches for the one BEFORE it, so removing the newest
   entries leaves a chain that checks out entry by entry; only the head shows that it
   used to be longer.

The first problem found stops the check, and the result names that entry's seq: every
entry after a broken one is suspect anyway, and the first bad place is where to look.

Reading is limited to one chain by its ID. The audit tables are not company-owned (the
platform chain has no company), so the company filter does not protect them: callers
pass the chain of the session's own company, never an ID from a request
(app/modules/audit_log/service.py).

Consistency: the head is read first and the entries after it, in the same transaction.
On MySQL (REPEATABLE READ) every plain read in a transaction sees the same snapshot, and
record() moves the head in the same transaction as it adds an entry, so an entry being
added at this moment is either fully seen (entry and head) or not at all. A check never
reports a "missing" entry just because someone was writing while it ran.
"""

import hmac
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.models import NO_SIGNATURE, AuditChainHead, AuditEvent
from app.audit.record import AuditError
from app.audit.signing import sign
from app.core.config import get_settings

# Entries are read in batches of this many, so a long chain never sits in memory at once.
BATCH = 500


@dataclass(frozen=True)
class Result:
    """What one check found. ok is True only if every entry and the end checked out."""

    chain_id: uuid.UUID
    ok: bool
    checked: int  # how many entries were checked and found good
    last_seq: int  # the seq the chain head points at (0 for an empty chain)
    # The first bad entry's seq (or, when the end is missing, the seq the head expected),
    # and what was wrong there, in words that name no secret. Both None when ok.
    first_bad_seq: int | None = None
    problem: str | None = None
    # The head's signature, for the nightly outside copy (never sent to a browser: it is
    # not secret, but nobody needs it there).
    head_signature: bytes = NO_SIGNATURE


def available_keys() -> dict[str, bytes]:
    """Every key that can check entries, by key ID: the current key and any older ones.

    Raises AuditError without a current key: a chain that cannot be checked must not be
    reported as fine.
    """
    settings = get_settings()
    if settings.audit_signing_key is None:
        raise AuditError("AUDIT_SIGNING_KEY is not set, so the audit log cannot be verified")
    keys = {
        key_id: key.get_secret_value().encode("utf-8")
        for key_id, key in settings.audit_previous_keys.items()
    }
    keys[settings.audit_key_id] = settings.audit_signing_key.get_secret_value().encode("utf-8")
    return keys


def verify_chain(db: Session, chain_id: uuid.UUID, keys: dict[str, bytes]) -> Result:
    """Check one chain from the start; see the module text for what is checked."""
    # 1. The head first (see "Consistency" above). No head and no entries: an empty
    #    chain, which is fine (a company where nothing has been recorded yet).
    head = db.scalars(select(AuditChainHead).where(AuditChainHead.chain_id == chain_id)).first()
    head_seq = head.last_seq if head is not None else 0
    head_signature = head.last_signature if head is not None else NO_SIGNATURE

    def bad(seq: int, problem: str, checked: int) -> Result:
        return Result(chain_id, False, checked, head_seq, seq, problem, head_signature)

    # 2. Every entry in order, in batches.
    expected = 1  # the seq the next entry must have
    previous = NO_SIGNATURE  # the signature it must link to
    entries = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.chain_id == chain_id)
        .order_by(AuditEvent.seq)
        .execution_options(yield_per=BATCH)
    )
    for entry in entries:
        checked = expected - 1
        # The unique key on (chain_id, seq) rules out two entries with one number, so a
        # different number here can only be a higher one: something was removed.
        if entry.seq != expected:
            return bad(expected, f"entry {expected} is missing", checked)
        # Past the end the head points at: added outside record(), which always moves
        # the head with the entry.
        if entry.seq > head_seq:
            return bad(entry.seq, "entry is after the end the chain head records", checked)
        if entry.prev_signature != previous:
            return bad(entry.seq, "entry does not link to the entry before it", checked)
        key = keys.get(entry.key_id)
        if key is None:
            # Named by ID only: the ID is not secret, the key is.
            problem = f"entry was signed with key {entry.key_id!r}, which is not available"
            return bad(entry.seq, problem, checked)
        # compare_digest takes the same time however many bytes match, so timing does not
        # help someone guess a signature byte by byte.
        if not hmac.compare_digest(entry.signature, sign(key, entry, previous)):
            return bad(entry.seq, "entry's signature does not match: it was changed", checked)
        previous = entry.signature
        expected += 1

    # 3. The end. Every entry found was good; the last one must be where the head points.
    found = expected - 1
    if found < head_seq:
        # The newest entries were removed: name the seq the head expected to find.
        problem = f"the chain ends at entry {found}, but its head expects {head_seq}"
        return bad(head_seq, problem, found)
    if head is not None and head_seq > 0 and previous != head.last_signature:
        return bad(head_seq, "the last entry is not the one the chain head records", found - 1)
    return Result(chain_id, True, found, head_seq, head_signature=head_signature)
