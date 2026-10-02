"""Record IDs: UUIDv7 values stored as BINARY(16) (decision 0019)."""

import uuid

import uuid6
from sqlalchemy import BINARY
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class UUIDBinary(TypeDecorator[uuid.UUID]):
    """A UUID in Python, 16 raw bytes in the database."""

    impl = BINARY(16)
    cache_ok = True

    def process_bind_param(self, value: uuid.UUID | None, dialect: Dialect) -> bytes | None:
        """Python → database: called for every value written or compared in a query."""
        return value.bytes if value is not None else None

    def process_result_value(self, value: bytes | None, dialect: Dialect) -> uuid.UUID | None:
        """Database → Python: called for every value read back."""
        return uuid.UUID(bytes=value) if value is not None else None


def new_id() -> uuid.UUID:
    """A new UUIDv7: time-ordered and unguessable."""
    return uuid6.uuid7()
