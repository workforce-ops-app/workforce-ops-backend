"""CI check: the migrations form one line, and they apply and undo on a fresh MySQL 8.4.

    python -m scripts.check_migrations

1. Exactly one head: two pull requests that each added a migration on the same parent
   create two heads; one of them must update its down_revision (contributor guide,
   modularity).
2. upgrade head → downgrade base → upgrade head on an empty MySQL 8.4, so every migration
   works in both directions.
3. The tables the migrations created match the models exactly (Alembic compares the
   database with Base.metadata). A hand-written or edited migration that drifted from
   its models fails here.

The database is a throwaway Docker container (removed afterwards), unless
MIGRATION_CHECK_DATABASE_URL points at an empty database to use instead.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import time

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, make_url, text
from sqlalchemy.exc import OperationalError

MYSQL_IMAGE = "mysql:8.4"
READY_TIMEOUT_SECONDS = 180


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(url: str) -> None:
    engine = create_engine(url)
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    try:
        while True:
            try:
                with engine.connect() as connection:
                    connection.execute(text("SELECT 1"))
                return
            except OperationalError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)
    finally:
        engine.dispose()


def _docker() -> str:
    """The full path of the docker program, so a lookalike elsewhere on PATH is not run."""
    path = shutil.which("docker")
    if not path:
        raise RuntimeError("Docker is needed for the migration check; start Docker Desktop")
    return path


def _start_mysql() -> tuple[str, str]:
    """Start an empty MySQL container; return its name and a database URL for it."""
    name = f"workforce-ops-migration-check-{secrets.token_hex(4)}"
    password = secrets.token_hex(16)  # throwaway, never stored
    port = _free_port()
    # Every argument is fixed or generated here; nothing comes from user input.
    subprocess.run(  # noqa: S603
        [
            _docker(), "run", "--detach", "--rm", "--name", name,
            "--publish", f"127.0.0.1:{port}:3306",
            "--env", f"MYSQL_ROOT_PASSWORD={password}",
            "--env", "MYSQL_DATABASE=migration_check",
            "--env", "MYSQL_USER=migration_check",
            "--env", f"MYSQL_PASSWORD={password}",
            MYSQL_IMAGE,
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    url = f"mysql+pymysql://migration_check:{password}@127.0.0.1:{port}/migration_check"
    return name, url


def _differences_from_models(url: str) -> list[str]:
    """What differs between the migrated database and the models (empty when they match)."""
    # Load every feature's models into Base.metadata, the same way migrations/env.py does.
    from app.db.base import Base
    from app.db.registry import import_all_models

    import_all_models()

    # Let Alembic compare the real tables with the models, as autogenerate would; any
    # difference means a migration and its models disagree. alembic_version is Alembic's
    # own bookkeeping table, not a model.
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection,
                opts={"include_name": lambda name, kind, parent: name != "alembic_version"},
            )
            return [str(difference) for difference in compare_metadata(context, Base.metadata)]
    finally:
        engine.dispose()


def main() -> int:
    config = Config("alembic.ini")
    heads = ScriptDirectory.from_config(config).get_heads()
    if len(heads) != 1:
        print(f"expected one migration head, found {len(heads)}: {', '.join(heads)}")
        return 1

    container = None
    url = os.environ.get("MIGRATION_CHECK_DATABASE_URL")
    if not url:
        container, url = _start_mysql()
    try:
        _wait_until_ready(url)
        # migrations/env.py reads the URL from the app settings: the address goes in
        # DATABASE_URL and the password in DATABASE_PASSWORD, the same split the app uses.
        # Setting both here also overrides any DATABASE_PASSWORD in the developer's .env.
        parsed = make_url(url)
        os.environ["DATABASE_URL"] = parsed.set(password=None).render_as_string()
        os.environ["DATABASE_PASSWORD"] = parsed.password or ""
        from app.core.config import get_settings

        get_settings.cache_clear()
        command.upgrade(config, "head")
        command.downgrade(config, "base")
        command.upgrade(config, "head")
        differences = _differences_from_models(url)
    finally:
        if container:
            subprocess.run([_docker(), "stop", container], capture_output=True)  # noqa: S603

    if differences:
        print("the migrated tables do not match the models:")
        for difference in differences:
            print(f"  {difference}")
        return 1

    where = "a fresh MySQL 8.4" if container else "MIGRATION_CHECK_DATABASE_URL"
    print(f"one head ({heads[0]}); upgrade, downgrade, upgrade passed on {where}; models match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
