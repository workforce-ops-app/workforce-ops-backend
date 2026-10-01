"""How Alembic connects: the app's own settings and models.

Every module's models.py is imported so Base.metadata knows all tables (used when a
migration is generated with `alembic revision --autogenerate`).
"""

import contextlib
import importlib
import pkgutil

from alembic import context
from sqlalchemy import create_engine

from app import modules
from app.core.config import get_settings
from app.db.base import Base

for module_info in pkgutil.iter_modules(modules.__path__):
    if module_info.ispkg:
        with contextlib.suppress(ModuleNotFoundError):  # a module without tables
            importlib.import_module(f"app.modules.{module_info.name}.models")

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Write the SQL instead of running it (`alembic upgrade head --sql`)."""
    context.configure(url=get_settings().database_url, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations against the database."""
    engine = create_engine(get_settings().database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
