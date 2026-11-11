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
4. The database's own rules hold in MySQL itself (_database_rule_problems): tests run on
   SQLite, which compares text differently, so the rules that depend on MySQL are tried
   here on the real thing.
5. Changes that must take turns do so in MySQL (_race_problems): two requests adding
   reporting lines at the same moment cannot add a duplicate or a loop. SQLite has no row
   locks, so this too can only be tried on MySQL.

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
from sqlalchemy import Connection, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError, OperationalError

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


def _refused(connection: Connection, sql: str, params: dict[str, object]) -> bool:
    """Whether MySQL refuses this statement (tried inside a savepoint, then undone)."""
    savepoint = connection.begin_nested()
    try:
        connection.execute(text(sql), params)
    except DBAPIError:
        savepoint.rollback()
        return True
    savepoint.rollback()
    return False


def _database_rule_problems(url: str) -> list[str]:
    """Try the database-level rules on the migrated MySQL; return the ones that failed.

    Everything runs in one transaction that is rolled back at the end, so the database is
    left empty. Plain SQL on a trusted connection on purpose: the point is what MySQL
    itself allows, without the app's checks in front of it.
    """
    from app.tenancy.filter import trust_connection

    problems = []
    engine = create_engine(url)
    try:
        with engine.connect() as connection, connection.begin() as transaction:
            trust_connection(connection)

            # Two companies, and a department in company A.
            company_a, company_b, department_a = (secrets.token_bytes(16) for _ in range(3))
            for company in (company_a, company_b):
                connection.execute(
                    text(
                        "INSERT INTO companies (id, name, timezone, created_at, updated_at) "
                        "VALUES (:id, 'probe', 'UTC', NOW(6), NOW(6))"
                    ),
                    {"id": company},
                )
            connection.execute(
                text(
                    "INSERT INTO departments (id, company_id, name, created_at, updated_at) "
                    "VALUES (:id, :company, 'Kitchen', NOW(6), NOW(6))"
                ),
                {"id": department_a, "company": company_a},
            )

            # A person in company A, with a given email.
            add_user = (
                "INSERT INTO users (id, company_id, department_id, email, display_name, "
                "created_at, updated_at) VALUES (:id, :company, :department, :email, 'probe', "
                "NOW(6), NOW(6))"
            )

            def user(email: str) -> dict[str, object]:
                return {
                    "id": secrets.token_bytes(16),
                    "company": company_a,
                    "department": department_a,
                    "email": email,
                }

            # 1. Company B's team inside company A's department: the company-aware key must
            # refuse it (tenancy layer 2).
            team_sql = (
                "INSERT INTO teams (id, company_id, department_id, name, created_at, "
                "updated_at) VALUES (:id, :company, :department, 'probe', NOW(6), NOW(6))"
            )
            team = {"id": secrets.token_bytes(16), "company": company_b, "department": department_a}
            if not _refused(connection, team_sql, team):
                problems.append("a team in one company could link to another company's department")

            # 2. A mixed-case email: the lowercase CHECK must refuse it (MySQL's default
            # comparison ignores case, which would let it through).
            if not _refused(connection, add_user, user("Mixed@Example.com")):
                problems.append("an email with capital letters was stored")

            # 3. Two addresses that differ only by an accent are different addresses
            # (MySQL's default comparison ignores accents and would call them duplicates).
            connection.execute(text(add_user), user("jose@example.com"))
            if _refused(connection, add_user, user("josé@example.com")):
                problems.append("two different emails (jose, josé) were treated as one")

            # 4 and 5. Reporting lines (Z2): nobody reports to themselves (the CHECK, which
            # MySQL only enforces from 8.0.16), and a line never joins two companies' people
            # (the company-aware keys). Two people of company A to try them on.
            ana, ben = user("ana@example.com"), user("ben@example.com")
            connection.execute(text(add_user), ana)
            connection.execute(text(add_user), ben)
            line_sql = (
                "INSERT INTO reporting_lines (id, company_id, manager_id, employee_id, "
                "created_at, updated_at) VALUES (:id, :company, :manager, :employee, NOW(6), "
                "NOW(6))"
            )

            def line(company: bytes, manager: object, employee: object) -> dict[str, object]:
                return {
                    "id": secrets.token_bytes(16),
                    "company": company,
                    "manager": manager,
                    "employee": employee,
                }

            if not _refused(connection, line_sql, line(company_a, ana["id"], ana["id"])):
                problems.append("a person could report to themselves")
            if not _refused(connection, line_sql, line(company_b, ana["id"], ben["id"])):
                problems.append("a reporting line could join people of another company")
            # And the rule check itself works: a proper line in company A is accepted.
            current = line(company_a, ana["id"], ben["id"])
            if _refused(connection, line_sql, current):
                problems.append("a valid reporting line was refused")

            # 6. One current line per pair (the current_line unique key): a second current
            # line is refused, but once the first has ended the same line may be added
            # again. This depends on MySQL's generated column and on a unique key allowing
            # many NULLs, so it is tried here on the real thing.
            connection.execute(text(line_sql), current)
            if not _refused(connection, line_sql, line(company_a, ana["id"], ben["id"])):
                problems.append("a second current reporting line for the same pair was stored")
            connection.execute(
                text("UPDATE reporting_lines SET ended_at = NOW(6) WHERE id = :id"),
                {"id": current["id"]},
            )
            if _refused(connection, line_sql, line(company_a, ana["id"], ben["id"])):
                problems.append("an ended reporting line blocked adding the same line again")

            transaction.rollback()
    finally:
        engine.dispose()
    return problems


def _race_problems(url: str) -> list[str]:
    """Try two requests changing reporting lines at the same moment; return what failed.

    add_reporting_line() locks the company first and then checks with fresh, locking
    reads (app/authz/chain.py). Both only mean something in MySQL: the tests run on
    SQLite, which has no row locks. So the races are tried here, through the app's own
    code and sessions, on the migrated MySQL. These checks commit (two transactions must
    see each other's work), so main() runs them before the downgrade, which drops
    everything again.
    """
    import threading

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.authz.chain import ReportingLineError, add_reporting_line, lock_reporting_lines
    from app.authz.models import ReportingLine
    from app.core.config import get_settings
    from app.modules.org.models import Company, Department, User
    from app.tenancy.context import set_company

    # Adding a line writes a signed audit entry, so the settings need a signing key; a
    # throwaway one is enough for a throwaway database.
    os.environ.setdefault("AUDIT_SIGNING_KEY", secrets.token_urlsafe(32))
    get_settings.cache_clear()

    problems = []
    engine = create_engine(url)
    try:
        # A company, made by platform code (a session with no company).
        with Session(engine) as platform:
            company = Company(name="race probe", timezone="UTC")
            platform.add(company)
            platform.commit()
            company_id = company.id

        def session() -> Session:
            """A new session for the company: one per simulated request."""
            db = Session(engine)
            set_company(db, company_id)
            return db

        # Four people in one department.
        with session() as db:
            department = Department(name="Kitchen")
            db.add(department)
            db.flush()
            people = {
                name: User(
                    email=f"{name}@race.example.com",
                    display_name=name,
                    department_id=department.id,
                )
                for name in ("a", "b", "c", "d")
            }
            db.add_all(people.values())
            db.commit()
            ids = {name: person.id for name, person in people.items()}

        def add(db: Session, manager: str, employee: str) -> None:
            add_reporting_line(
                db, Actor.system(), manager_id=ids[manager], employee_id=ids[employee]
            )

        def refused_after_late_commit(first: tuple[str, str], second: tuple[str, str]) -> bool:
            """Request 2 has already read something (as its permission check would), which
            fixes what its ordinary SELECTs see under MySQL's REPEATABLE READ. Request 1
            then adds `first` and commits. Is request 2's `second` still refused?"""
            with session() as request_2:
                request_2.scalars(select(ReportingLine)).all()  # its view is now fixed
                with session() as request_1:
                    add(request_1, *first)
                    request_1.commit()
                try:
                    add(request_2, *second)
                except ReportingLineError:
                    return True
                except DBAPIError:
                    # Refused by the database's unique key instead: still safe, but it
                    # means the service's own check read an old view.
                    return False
                return False

        # 1. The same line, added by two requests: the second must be refused.
        if not refused_after_late_commit(("a", "b"), ("a", "b")):
            problems.append("a duplicate reporting line committed meanwhile was not seen")
        # 2. b -> c by one request, c -> b by another: fine alone, a loop together.
        if not refused_after_late_commit(("b", "c"), ("c", "b")):
            problems.append("a reporting line loop committed meanwhile was not seen")

        # 3. Two changes in one company take turns: while request 1 holds the company lock,
        # request 2 (in another thread) must wait, and go ahead once request 1 commits.
        # Request 1 only takes the lock and writes nothing: adding a line also locks the
        # audit log's chain head, which would make request 2 wait even without the
        # company lock, so this tries the company lock on its own.
        errors: list[BaseException] = []

        def second_request() -> None:
            try:
                with session() as request_2:
                    add(request_2, "c", "d")
                    request_2.commit()
            except BaseException as error:  # reported below
                errors.append(error)

        with session() as request_1:
            lock_reporting_lines(request_1)
            waiting = threading.Thread(target=second_request)
            waiting.start()
            waiting.join(timeout=2)
            if not waiting.is_alive():
                problems.append("a second reporting line change did not wait for the first")
            request_1.commit()
        waiting.join(timeout=30)
        if waiting.is_alive() or errors:
            problems.append(f"the waiting reporting line change did not finish: {errors}")
    finally:
        engine.dispose()
    return problems


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
        # The race checks commit rows, so they run before the downgrade removes everything.
        race_problems = _race_problems(url)
        command.downgrade(config, "base")
        command.upgrade(config, "head")
        differences = _differences_from_models(url)
        rule_problems = _database_rule_problems(url) + race_problems
    finally:
        if container:
            subprocess.run([_docker(), "stop", container], capture_output=True)  # noqa: S603

    if differences:
        print("the migrated tables do not match the models:")
        for difference in differences:
            print(f"  {difference}")
        return 1

    if rule_problems:
        print("the database's own rules do not hold in MySQL:")
        for problem in rule_problems:
            print(f"  {problem}")
        return 1

    where = "a fresh MySQL 8.4" if container else "MIGRATION_CHECK_DATABASE_URL"
    print(
        f"one head ({heads[0]}); upgrade, downgrade, upgrade passed on {where}; "
        "models match; database rules hold"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
