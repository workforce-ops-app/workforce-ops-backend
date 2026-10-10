"""The sessions table: one row per signed-in browser (data-model.md, authentication.md).

Deleting a row signs that browser out. The browser holds only a random token in its
cookie; this table stores the token's SHA-256, never the token itself, so a copy of the
database cannot be used to take over anyone's session.
"""

import uuid
from datetime import datetime

from sqlalchemy import BINARY, ForeignKeyConstraint, Index, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import UTC_DATETIME, Base, IdAndTimestamps
from app.db.types import UUIDBinary
from app.tenancy.filter import CompanyOwned


class UserSession(IdAndTimestamps, CompanyOwned, Base):
    """A signed-in browser of one person. (Named UserSession, not Session, so it is never
    confused with SQLAlchemy's database session.)"""

    __tablename__ = "sessions"
    __table_args__ = (
        ForeignKeyConstraint(["company_id"], ["companies.id"]),
        # Layer 2: other tables link to a session through (company_id, id).
        UniqueConstraint("company_id", "id"),
        # Layer 2: the person must belong to the session's company.
        ForeignKeyConstraint(["company_id", "user_id"], ["users.company_id", "users.id"]),
        Index("ix_sessions_company_user", "company_id", "user_id"),
        # Each request finds its session by the token's hash, so it is unique and indexed.
        UniqueConstraint("token_hash"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(UUIDBinary)
    # SHA-256 of the 32-byte token in the cookie.
    token_hash: Mapped[bytes] = mapped_column(BINARY(32))
    # The maximum length: 30 days after sign-in, however active.
    expires_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    # The last request, for the 1 hour idle timeout (updated at most once a minute).
    last_seen_at: Mapped[datetime] = mapped_column(UTC_DATETIME)
    # When the password was last re-entered in this session (S5); null until then.
    reauth_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
