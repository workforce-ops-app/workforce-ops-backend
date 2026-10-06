"""The audit log's two tables: the chain heads and the entries (audit-log.md, decision 0018).

Each company has its own chain of entries, and the platform has one more (for actions by
platform code and, later, platform staff). A chain head is the bookmark at the end of a
chain: the newest entry's number and signature. Adding an entry locks the head row, so
two entries can never take the same number.

Not company-owned (CompanyOwned): the platform chain belongs to no company, so
company_id is null there. Instead, only app/audit/record.py writes these tables, and it
takes the company from the session, never from the caller. Reading the log (the viewer
and verification, Phase 4) gets its own checks.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BINARY,
    JSON,
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps, Timestamps
from app.db.types import UUIDBinary

# The platform chain's ID: the all-zero UUID (company chains use the company's ID).
PLATFORM_CHAIN_ID = uuid.UUID(int=0)

# HMAC-SHA256 signatures are 32 bytes. Before a chain's first entry, its "previous
# signature" is 32 zero bytes.
SIGNATURE_BYTES = 32
NO_SIGNATURE = bytes(SIGNATURE_BYTES)

# Who can act: a person of a company, platform staff (later), or the application itself
# for automatic actions such as expirations.
ACTOR_TYPES = ("user", "platform_user", "system")


class AuditChainHead(Timestamps, Base):
    """Where one chain currently ends: its newest entry's number and signature."""

    __tablename__ = "audit_chain_heads"
    __table_args__ = (
        # A company's chain has the company's ID; the platform chain has no company.
        CheckConstraint(
            "company_id IS NULL OR chain_id = company_id", name="audit_chain_heads_company"
        ),
        CheckConstraint("last_seq >= 0", name="audit_chain_heads_seq"),
    )

    chain_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True)
    # The company, or null for the platform chain; at most one chain per company.
    company_id: Mapped[uuid.UUID | None] = mapped_column(
        UUIDBinary, ForeignKey("companies.id"), unique=True
    )
    # 0 and 32 zero bytes before the first entry.
    last_seq: Mapped[int] = mapped_column(BigInteger)
    last_signature: Mapped[bytes] = mapped_column(BINARY(SIGNATURE_BYTES))


class AuditEvent(IdAndTimestamps, Base):
    """One recorded action. Only ever added: never changed or removed."""

    __tablename__ = "audit_events"
    __table_args__ = (
        # One entry per number in each chain: two entries can never share a place.
        UniqueConstraint("chain_id", "seq"),
        CheckConstraint("seq >= 1", name="audit_events_seq"),
        # The system acts without an ID; a person or platform staff member always has one.
        CheckConstraint(
            "(actor_type = 'system' AND actor_id IS NULL)"
            " OR (actor_type IN ('user', 'platform_user') AND actor_id IS NOT NULL)",
            name="audit_events_actor",
        ),
        Index("ix_audit_events_company", "company_id"),
    )

    # Which chain, and the entry's place in it: 1, 2, 3... with no gaps.
    chain_id: Mapped[uuid.UUID] = mapped_column(
        UUIDBinary, ForeignKey("audit_chain_heads.chain_id")
    )
    seq: Mapped[int] = mapped_column(BigInteger)
    # The company, or null on the platform chain.
    company_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary, ForeignKey("companies.id"))
    # Who acted (actor_id is null for the system).
    actor_type: Mapped[str] = mapped_column(String(16))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    # What happened, as a dotted name such as "shift.assigned", and to what.
    action: Mapped[str] = mapped_column(String(100))
    target_type: Mapped[str | None] = mapped_column(String(50))
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUIDBinary)
    occurred_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    # Extra facts, such as before and after values. Never passwords, tokens, or secrets.
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    # Which key signed this entry, so old entries stay verifiable after a key change.
    key_id: Mapped[str] = mapped_column(String(40))
    # The chain links: the previous entry's signature, and this entry's own.
    prev_signature: Mapped[bytes] = mapped_column(BINARY(SIGNATURE_BYTES))
    signature: Mapped[bytes] = mapped_column(BINARY(SIGNATURE_BYTES))
