"""Database connections: one engine for the app, one session per request.

The engine keeps a pool of connections to MySQL (PyMySQL driver, decision 0034). A
session is one unit of work: queries and changes in it are committed together, or not
at all. Only repository.py files use sessions (decision 0004).
"""

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    """The engine, created on first use from DATABASE_URL."""
    # pool_pre_ping: check a pooled connection is still alive before using it, so a
    # MySQL restart does not turn into errors for the next requests.
    return create_engine(get_settings().database_url, pool_pre_ping=True)


def get_session() -> Iterator[Session]:
    """A session for one request; FastAPI closes it when the request ends.

    Use it as a dependency:  def handler(session: Session = Depends(get_session)): ...
    """
    with Session(get_engine()) as session:
        yield session
