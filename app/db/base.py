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


_TIMESTAMP = DateTime().with_variant(DATETIME(fsp=6), "mysql")


class IdAndTimestamps:
    """Columns every table has: id, created_at, updated_at.

    Use it together with Base:  class Shift(IdAndTimestamps, Base): ...
    """

    id: Mapped[uuid.UUID] = mapped_column(UUIDBinary, primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(_TIMESTAMP, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(_TIMESTAMP, default=utcnow, onupdate=utcnow)
