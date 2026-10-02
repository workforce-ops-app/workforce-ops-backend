"""The shared columns: what SQL a model becomes, and that id and timestamps fill themselves.

The model below exists only for these tests. The SQL checks need no database: SQLAlchemy
compiles the CREATE TABLE statement for MySQL as text. The save-and-read checks use
SQLite in memory, which needs no server.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, String, create_engine, select
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.schema import CreateTable

from app.db.base import Base, IdAndTimestamps, utcnow


@pytest.fixture(scope="module")
def note_model() -> Any:
    """A small model for these tests only, defined once per test run."""

    class SampleNote(IdAndTimestamps, Base):
        __tablename__ = "sample_notes_test_only"

        title: Mapped[str] = mapped_column(String(100))

    return SampleNote


@pytest.fixture
def engine(note_model: Any) -> Iterator[Engine]:
    """An empty SQLite database in memory with the test table; closed after each test."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[note_model.__table__])
    yield engine
    engine.dispose()


def test_create_table_has_the_shared_columns(note_model: Any) -> None:
    sql = str(CreateTable(note_model.__table__).compile(dialect=mysql.dialect()))

    assert "id BINARY(16) NOT NULL" in sql
    assert "created_at DATETIME(6) NOT NULL" in sql
    assert "updated_at DATETIME(6) NOT NULL" in sql
    assert "title VARCHAR(100) NOT NULL" in sql
    assert "PRIMARY KEY (id)" in sql


def test_utcnow_is_utc_without_time_zone() -> None:
    now = utcnow()

    assert now.tzinfo is None  # MySQL DATETIME stores no time zone (decision 0021)
    assert abs(now - datetime.now(UTC).replace(tzinfo=None)) < timedelta(seconds=5)


def test_saving_fills_in_id_and_timestamps(note_model: Any, engine: Engine) -> None:
    with Session(engine) as session:
        session.add(note_model(title="Hello"))
        session.commit()
        note = session.scalars(select(note_model)).one()

        assert note.id.version == 7
        assert note.created_at.tzinfo is None
        assert abs(note.created_at - utcnow()) < timedelta(seconds=5)
        assert note.updated_at >= note.created_at


def test_updating_moves_updated_at_but_not_created_at(note_model: Any, engine: Engine) -> None:
    with Session(engine) as session:
        note = note_model(title="Hello")
        session.add(note)
        session.commit()
        created, first_update = note.created_at, note.updated_at

        note.title = "Changed"
        session.commit()

        assert note.created_at == created
        assert note.updated_at > first_update
