"""Turning an audit entry into exact bytes, and signing those bytes (decision 0018).

Two steps, both needed to make the log tamper-evident:

1. Canonical JSON: the entry's fields written as JSON in one fixed way (sorted keys, no
   spaces, UTF-8, one timestamp format, IDs as hyphenated strings). The same entry always
   gives the same bytes, so a later check (verification, #58) can recompute them exactly
   from the stored row. Any change to any field changes the bytes.

2. The signature: HMAC-SHA256(key, canonical bytes + previous entry's signature).
   - Including the previous signature links the entries into a chain: changing, removing,
     or inserting an entry breaks every link after it.
   - Using a secret key (HMAC), not a plain hash, is what stops someone with database
     access from repairing the chain after editing it: with a plain SHA-256 they could
     recompute every hash after their change; without the key they cannot produce a
     valid signature. The key lives only in the environment, never in the database.
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime
from typing import Any

from app.audit.models import AuditEvent

# The fields that are signed, by name. Everything that describes the entry is in; the
# links (prev_signature is added separately below, signature is the result) and the
# bookkeeping timestamps (created_at, updated_at) are not.
SIGNED_FIELDS = (
    "id",
    "chain_id",
    "seq",
    "company_id",
    "actor_type",
    "actor_id",
    "action",
    "target_type",
    "target_id",
    "occurred_at",
    "details",
    "key_id",
)


def _plain(value: Any) -> Any:
    """One field value in its fixed JSON form."""
    # IDs as lowercase hyphenated strings, e.g. "0192f1c4-...".
    if isinstance(value, uuid.UUID):
        return str(value)
    # Moments (UTC, stored without a time zone) always with microseconds and a Z, e.g.
    # "2026-10-05T14:00:00.000000Z", so 14:00 and 14:00:00.000000 cannot differ.
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    # Text, whole numbers, true/false, null, and the details object as they are.
    return value


def canonical_json(event: AuditEvent) -> bytes:
    """The entry's signed fields as canonical JSON bytes."""
    fields = {name: _plain(getattr(event, name)) for name in SIGNED_FIELDS}
    # sort_keys: the same order every time, also inside details. separators: no spaces.
    # ensure_ascii=False plus encode("utf-8"): letters such as "é" as their UTF-8 bytes.
    text = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def sign(key: bytes, event: AuditEvent, prev_signature: bytes) -> bytes:
    """The entry's signature: HMAC-SHA256 over its canonical JSON plus the previous link."""
    return hmac.new(key, canonical_json(event) + prev_signature, hashlib.sha256).digest()
