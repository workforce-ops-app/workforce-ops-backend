"""The two security event tables (docs/features/detection.md, "Data: two tables").

- security_events: one company's events, from requests that carried a valid session.
  Company-owned like every other company table, so the company filter protects it
  (tenancy layers 1 to 3), and its person link goes through (company_id, user_id), so a
  row can never name a person of another company (layer 2).
- platform_security_events: events from requests WITHOUT a valid session, which belong to
  no company (rule DE9), plus the writer's own drop counts. It has no company_id and no
  user_id at all, so a row cannot point at a company or a person even by mistake, and no
  company query can ever match it.

Both tables are insert-only: rows are a plain record of what someone sent, so they are
never changed (rule DE6). That is why they have no updated_at column. Only
app/modules/security/writer.py inserts into them; rows older than a year are removed
(writer.remove_old_events).

Security events are NOT audit entries: they record what someone sent, not something the
application did, and a flood of them must not grow the signed audit chain.
"""

import uuid
from datetime import datetime

from sqlalchemy import ForeignKeyConstraint, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base
from app.db.types import UUIDBinary, new_id
from app.tenancy.filter import CompanyOwned

# The kinds of rows (the `kind` column). detection.<type> for each attack type the
# detector knows (app/detection/patterns.py); later authz.denied and csrf.refused (#92).
SUMMARY = "detection.summary"  # how many events the rate cap held back (DE6)
DROPPED = "detection.dropped"  # how many request copies a full queue dropped (DE11)


class _EventColumns:
    """The columns both tables share (the detection page's column table)."""

    # UUIDv7, so IDs sort by time like everywhere else (decision 0019).
    id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True, default=new_id)
    # detection.<type>, detection.summary, or detection.dropped.
    kind: Mapped[str] = mapped_column(String(50))
    # Which pattern matched, for example "SQLI-02"; null for summary and drop rows.
    pattern_id: Mapped[str | None] = mapped_column(String(20))
    # Where the value was, for example "body.note"; null for summary and drop rows.
    field: Mapped[str | None] = mapped_column(String(100))
    # The route TEMPLATE (/api/shifts/{shift_id}), never the raw path, which may carry
    # attacker text of its own.
    method: Mapped[str | None] = mapped_column(String(10))
    route: Mapped[str | None] = mapped_column(String(200))
    # IPv4 or IPv6, from nginx's header only when the request came through nginx (DE8).
    client_address: Mapped[str | None] = mapped_column(String(45))
    # Links the event to the application log line of the same request (#92).
    request_id: Mapped[str | None] = mapped_column(String(40))
    # At most 200 characters of what was sent: attacker text, stored as plain text and
    # always shown with textContent (DE7, threat T7).
    excerpt: Mapped[str | None] = mapped_column(String(200))
    # 1 for an event; for a summary or drop row, how many it stands for.
    count: Mapped[int] = mapped_column(Integer, default=1)
    # When it happened, in UTC (for summary and drop rows: the end of their minute).
    occurred_at: Mapped[datetime] = mapped_column(UTC_DATETIME)


class SecurityEvent(_EventColumns, CompanyOwned, Base):
    """One company's security event: a request with a valid session of this company."""

    __tablename__ = "security_events"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        UniqueConstraint("company_id", "id"),
        # Layer 2: the person belongs to the event's company.
        ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        # The security page asks "newest first" and "newest first of this kind".
        Index("ix_security_events_company_time", "company_id", "occurred_at"),
        Index("ix_security_events_company_kind_time", "company_id", "kind", "occurred_at"),
        # "This person's events, newest first"; it also serves the person link above, so
        # MySQL does not add an unnamed index of its own for that key.
        Index("ix_security_events_company_user_time", "company_id", "user_id", "occurred_at"),
    )

    # The person whose session sent the request (always known here: no session, no row).
    user_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)


class PlatformSecurityEvent(_EventColumns, Base):
    """An event from a request without a valid session, or a drop count. Not company-owned,
    and deliberately without company_id or user_id (DE9)."""

    __tablename__ = "platform_security_events"
    __table_args__ = (Index("ix_platform_security_events_time", "occurred_at"),)
