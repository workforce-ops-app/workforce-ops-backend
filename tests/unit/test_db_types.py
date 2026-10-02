"""Record IDs: UUIDv7, stored as 16 raw bytes (decision 0019)."""

import uuid

from sqlalchemy.dialects import mysql

from app.db.types import UUIDBinary, new_id

DIALECT = mysql.dialect()
SAMPLE = uuid.UUID("01920000-0000-7000-8000-000000000001")


def test_column_type_is_binary_16() -> None:
    assert UUIDBinary().compile(dialect=DIALECT) == "BINARY(16)"


def test_uuid_is_written_as_its_16_bytes() -> None:
    stored = UUIDBinary().process_bind_param(SAMPLE, DIALECT)

    assert stored == SAMPLE.bytes
    assert stored is not None and len(stored) == 16


def test_bytes_are_read_back_as_the_same_uuid() -> None:
    assert UUIDBinary().process_result_value(SAMPLE.bytes, DIALECT) == SAMPLE


def test_missing_values_stay_missing() -> None:
    # NULL in the database is None in Python, in both directions.
    assert UUIDBinary().process_bind_param(None, DIALECT) is None
    assert UUIDBinary().process_result_value(None, DIALECT) is None


def test_new_ids_are_version_7_and_unique() -> None:
    ids = [new_id() for _ in range(1000)]

    assert all(isinstance(i, uuid.UUID) and i.version == 7 for i in ids)
    assert len(set(ids)) == 1000


def test_new_ids_are_time_ordered() -> None:
    # UUIDv7 starts with the time, so later IDs sort after earlier ones: new rows land at
    # the end of the index instead of all over it (decision 0019).
    ids = [new_id() for _ in range(100)]

    assert [i.bytes for i in ids] == sorted(i.bytes for i in ids)
