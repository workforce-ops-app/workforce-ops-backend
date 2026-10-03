"""How Alembic connects: the app's own settings and models.

Every feature's models.py is imported so Base.metadata knows all tables (used when a
migration is generated with `alembic revision --autogenerate`). A models.py that fails
to import stops Alembic with the error (app/db/registry.py).
"""

from alembic import context
from sqlalchemy import create_engine

from app.core.config import get_settings
from app.db.base import Base
from app.db.registry import import_all_models
from app.tenancy.filter import trust_connection

# Load every feature's tables into Base.metadata before Alembic compares it with the
# database; a broken models.py raises here and nothing is generated.
import_all_models()

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Write the SQL instead of running it (`alembic upgrade head --sql`)."""
    context.configure(url=get_settings().sqlalchemy_url, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations against the database."""
    engine = create_engine(get_settings().sqlalchemy_url)
    with engine.connect() as connection:
        # Migrations are operator-run code that no request can reach; a data fix may need
        # to touch every company's rows, so the company filter's last guard lets this
        # connection through (app/tenancy/filter.py).
        trust_connection(connection)
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
