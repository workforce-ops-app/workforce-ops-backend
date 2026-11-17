"""How Alembic connects: the migrations user, the app's settings, and its models.

Alembic connects as the migrations user (MIGRATIONS_DATABASE_URL), the only one that may
change the structure. After every online upgrade or downgrade it makes the application
user's rights match app/db/grants.py, so a new table is usable by the app (and an audit
table stays insert-only) without anyone granting rights by hand.

Every feature's models.py is imported so Base.metadata knows all tables (used when a
migration is generated with `alembic revision --autogenerate`). A models.py that fails
to import stops Alembic with the error (app/db/registry.py).
"""

import logging

from alembic import context
from sqlalchemy import create_engine, make_url

from app.core.config import get_settings
from app.db.base import Base
from app.db.grants import grant_app_rights
from app.db.registry import import_all_models
from app.tenancy.filter import trust_connection

# Load every feature's tables into Base.metadata before Alembic compares it with the
# database; a broken models.py raises here and nothing is generated.
import_all_models()

target_metadata = Base.metadata

log = logging.getLogger("alembic.grants")


def run_migrations_offline() -> None:
    """Write the SQL instead of running it (`alembic upgrade head --sql`)."""
    # The SQL only: the grants are not written out, run an online upgrade to apply them.
    context.configure(url=get_settings().migrations_sqlalchemy_url, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run the migrations against the database."""
    settings = get_settings()
    migrations_url = settings.migrations_sqlalchemy_url
    # The application user is the one in DATABASE_URL.
    app_user = make_url(settings.database_url).username
    engine = create_engine(migrations_url)
    with engine.connect() as connection:
        # Migrations are operator-run code that no request can reach; a data fix may need
        # to touch every company's rows, so the company filter's last guard lets this
        # connection through (app/tenancy/filter.py).
        trust_connection(connection)
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()

        # Then the application user's rights. Skipped when both URLs name one user: the
        # grants would take that user's own rights away (and a single user that may do
        # everything is only for throwaway databases).
        if app_user and app_user != migrations_url.username:
            tables = grant_app_rights(connection, app_user)
            connection.commit()
            log.info("rights for %s set on %d tables", app_user, len(tables))
        else:
            log.warning("one database user for the app and migrations: no grants set")
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
