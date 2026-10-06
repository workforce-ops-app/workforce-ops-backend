"""The base every table builds on: the shared ID and timestamp columns (decisions 0019, 0021)."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime
from sqlalchemy.dialects.mysql import DATETIME
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.types import UUIDBinary, new_id


class Base(DeclarativeBase):
    """Every model inherits from Base; Alembic reads Base.metadata to know the tables."""


def utcnow() -> datetime:
    """The current moment in UTC, without time zone information (MySQL DATETIME has none)."""
    return datetime.now(UTC).replace(tzinfo=None)


# A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021). Use it for every
# moment column, e.g.  archived_at: Mapped[datetime | None] = mapped_column(UTC_DATETIME)
UTC_DATETIME = DateTime().with_variant(DATETIME(fsp=6), "mysql")


class Timestamps:
    """created_at and updated_at, for tables whose key is not a single id column.

    Example: team_members, whose key is (team_id, user_id).
    """

    created_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTC_DATETIME, default=utcnow, onupdate=utcnow)


class IdAndTimestamps(Timestamps):
    """Columns every table has: id, created_at, updated_at.

    Use it together with Base:  class Shift(IdAndTimestamps, Base): ...
    """

    id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True, default=new_id)
