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
   reporting lines at the same moment cannot add a duplicate or a loop, and two requests
   booking one person at the same moment cannot double-book them, account changes
   take turns with team and department changes, wrong passwords sent together are
   each counted toward the lockout, one setup link used twice at the same moment
   sets a password only once, and role changes see what other requests committed while
   they waited (grants, the actor's own access, the role limit), and so do giving and
   removing roles (the giver's access, the role's grants and state, the person's place,
   the same-level rule), and so do approval decisions (the reviewer's access, the
   requested role's grants and state), and so do reporting line changes (the actor's
   reporting_line.manage, each person's place and active status), and an overdue
   request noticed by two requests lapses once, with both seeing it declined. SQLite
   has no row locks, so this too can only be tried on MySQL. They run as the
   application user, so they also show its rights are enough for the app's own writes
   and locking reads.
6. A company that existed before a migration still works after it
   (_existing_company_problems): its starting roles get the permissions a migration adds
   (announcement.create in 0014).
7. The application user's rights (_grant_problems, #43): created by the same first-start
   script Docker Compose uses (docker/mysql/init/01-users.sh) and granted by the
   migrations (app/db/grants.py), it cannot change the structure, cannot change or
   remove audit entries, and can read every table the app uses.

The database is a throwaway Docker container (removed afterwards), unless
MIGRATION_CHECK_DATABASE_URL points at an empty database to use instead. That one URL
is then used for everything, and step 7 is skipped: it needs the two users.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, create_engine, make_url, text
from sqlalchemy.exc import DBAPIError, OperationalError

if TYPE_CHECKING:  # names used only in type hints
    import uuid
    from collections.abc import Callable
    from datetime import datetime

    from sqlalchemy.orm import Session

MYSQL_IMAGE = "mysql:8.4"
READY_TIMEOUT_SECONDS = 180
# The first-start scripts Docker Compose gives MySQL; the throwaway container gets the same.
INIT_SCRIPTS = Path(__file__).resolve().parents[1] / "docker" / "mysql" / "init"


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


def _start_mysql() -> tuple[str, str, str]:
    """Start an empty MySQL container with the two users, as Docker Compose creates them.

    Returns the container's name, the migrations user's URL, and the application user's.
    """
    name = f"workforce-ops-migration-check-{secrets.token_hex(4)}"
    # Throwaway passwords, never stored. Hex only, so they fit in a URL as they are.
    root, app, migrations = (secrets.token_hex(16) for _ in range(3))
    port = _free_port()
    # Every argument is fixed or generated here; nothing comes from user input.
    subprocess.run(  # noqa: S603
        [
            _docker(), "run", "--detach", "--rm", "--name", name,
            "--publish", f"127.0.0.1:{port}:3306",
            "--volume", f"{INIT_SCRIPTS}:/docker-entrypoint-initdb.d:ro",
            "--env", f"MYSQL_ROOT_PASSWORD={root}",
            "--env", "MYSQL_DATABASE=migration_check",
            "--env", f"MYSQL_APP_PASSWORD={app}",
            "--env", f"MYSQL_MIGRATIONS_PASSWORD={migrations}",
            MYSQL_IMAGE,
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    address = f"127.0.0.1:{port}/migration_check"
    return (
        name,
        f"mysql+pymysql://workforce_migrations:{migrations}@{address}",
        f"mysql+pymysql://workforce_app:{app}@{address}",
    )


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

            # 7 and 8. Announcements (AN1): the audience CHECK keeps exactly the ID the
            # type needs (MySQL only enforces CHECKs from 8.0.16), and the company-aware
            # keys keep an announcement out of another company's department.
            announcement_sql = (
                "INSERT INTO announcements (id, company_id, author_id, audience_type, "
                "department_id, team_id, title, body, created_at, updated_at) VALUES (:id, "
                ":company, :author, :type, :department, NULL, 'probe', 'probe', NOW(6), NOW(6))"
            )

            def announcement(company: bytes, kind: str, dept: bytes | None) -> dict[str, object]:
                return {
                    "id": secrets.token_bytes(16),
                    "company": company,
                    "author": ana["id"],
                    "type": kind,
                    "department": dept,
                }

            if not _refused(
                connection, announcement_sql, announcement(company_a, "company", department_a)
            ):
                problems.append("a company-wide announcement could name a department")
            if not _refused(
                connection, announcement_sql, announcement(company_a, "department", None)
            ):
                problems.append("a department announcement could have no department")
            if not _refused(
                connection, announcement_sql, announcement(company_b, "department", department_a)
            ):
                problems.append("an announcement could point at another company's department")
            if _refused(
                connection, announcement_sql, announcement(company_a, "department", department_a)
            ):
                problems.append("a valid department announcement was refused")

            # 9 and 10. Read marks (AN2): the company-aware keys keep a mark out of another
            # company's announcement, and the primary key allows one mark per person.
            posted = announcement(company_a, "department", department_a)
            connection.execute(text(announcement_sql), posted)
            read_sql = (
                "INSERT INTO announcement_reads (company_id, announcement_id, user_id, "
                "read_at) VALUES (:company, :announcement, :user, NOW(6))"
            )

            def mark(company: bytes) -> dict[str, object]:
                return {"company": company, "announcement": posted["id"], "user": ben["id"]}

            if not _refused(connection, read_sql, mark(company_b)):
                problems.append("a read mark could point at another company's announcement")
            if _refused(connection, read_sql, mark(company_a)):
                problems.append("a valid read mark was refused")
            connection.execute(text(read_sql), mark(company_a))
            if not _refused(connection, read_sql, mark(company_a)):
                problems.append("a second read mark by the same person was stored")

            transaction.rollback()
    finally:
        engine.dispose()
    return problems


def _race_problems(url: str) -> list[str]:
    """Try two requests changing the same thing at the same moment; return what failed.

    The locks and locking reads that make these safe only mean something in MySQL: the
    tests run on SQLite, which has no row locks. So the races are tried here, through
    the app's own code and sessions, on the migrated MySQL. These checks commit (two
    transactions must see each other's work), so main() runs them before the downgrade,
    which drops everything again. Each group of races uses its own company.
    """
    from app.core.config import get_settings

    # Adding a reporting line writes a signed audit entry, so the settings need a signing
    # key; a throwaway one is enough for a throwaway database.
    os.environ.setdefault("AUDIT_SIGNING_KEY", secrets.token_urlsafe(32))
    get_settings.cache_clear()

    engine = create_engine(url)
    try:
        return (
            _reporting_line_race_problems(engine)
            + _line_authz_race_problems(engine)
            + _shift_race_problems(engine)
            + _org_race_problems(engine)
            + _people_race_problems(engine)
            + _lockout_race_problems(engine)
            + _link_race_problems(engine)
            + _sign_up_race_problems(engine)
            + _read_mark_race_problems(engine)
            + _role_race_problems(engine)
            + _lapse_race_problems(engine)
            + _assignment_race_problems(engine)
            + _approval_race_problems(engine)
            + _owner_race_problems(engine)
        )
    finally:
        engine.dispose()


def _read_mark_race_problems(engine: Engine) -> list[str]:
    """One person marking one announcement read several times at the same moment; return
    what failed.

    Marking read is idempotent (app/modules/announcements/service.py): it looks for the
    person's mark and adds one if there is none. Requests sent together (a page sending it
    twice) can all find none and all add one; the primary key on (announcement, person)
    then refuses all but the first. Each refused one must be answered as a success, not a
    500, and exactly one mark must be saved.
    """
    import threading

    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from app.modules.announcements import service
    from app.modules.announcements.models import Announcement, AnnouncementRead
    from app.modules.org.models import Company, Department, User
    from app.tenancy.context import set_company

    with Session(engine) as platform:
        company = Company(name="read mark race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id
    with Session(engine) as db:
        set_company(db, company_id)
        home = Department(name="Office")
        db.add(home)
        db.flush()
        reader = User(
            email=f"reader-{company_id.hex}@read-race.example.com",
            display_name="reader",
            department_id=home.id,
        )
        db.add(reader)
        db.flush()
        # Added directly: posting has its own tests, only the read marks matter here.
        item = Announcement(
            author_id=reader.id,
            audience_type="company",
            title="probe",
            body="probe",
        )
        db.add(item)
        db.commit()
        reader_id, announcement_id = reader.id, item.id

    marks = 4
    start = threading.Barrier(marks)
    errors: list[str] = []

    def mark_read() -> None:
        # Each mark is its own request, with its own session for the company.
        with Session(engine) as db:
            set_company(db, company_id)
            person = db.get(User, reader_id)
            start.wait()
            try:
                if person is None:
                    raise LookupError("the probe's reader was not found")
                service.mark_read(db, person, announcement_id)
            except Exception as error:  # a 500 in the app: reported below
                errors.append(f"error: {error!r}"[:300])

    threads = [threading.Thread(target=mark_read) for _ in range(marks)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    with Session(engine) as db:
        set_company(db, company_id)
        saved = db.scalar(
            select(func.count(AnnouncementRead.user_id)).where(
                AnnouncementRead.announcement_id == announcement_id
            )
        )
    problems = [f"read marks at the same moment: {error}" for error in errors]
    if saved != 1:
        problems.append(f"{marks} read marks at the same moment saved {saved} (expected 1)")
    return problems


def _reporting_line_race_problems(engine: Engine) -> list[str]:
    """Two requests changing reporting lines at the same moment; return what failed.

    add_reporting_line() and end_reporting_line() lock the company first and then check
    with fresh, locking reads (app/authz/chain.py).
    """
    import threading

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.authz.chain import (
        ReportingLineError,
        add_reporting_line,
        end_reporting_line,
        lock_reporting_lines,
    )
    from app.authz.models import ReportingLine
    from app.modules.org.models import Company, Department, User
    from app.tenancy.context import set_company

    problems = []
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
        add_reporting_line(db, Actor.system(), manager_id=ids[manager], employee_id=ids[employee])

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

    # 3. One line ended by two requests (#56): the second must see that it has ended,
    # not end it twice. Line a -> b was added in race 1.
    with session() as db:
        line_ab = db.scalars(
            select(ReportingLine.id).where(
                ReportingLine.manager_id == ids["a"],
                ReportingLine.employee_id == ids["b"],
                ReportingLine.ended_at.is_(None),
            )
        ).one()
    with session() as request_2:
        request_2.scalars(select(ReportingLine)).all()  # its view is now fixed
        with session() as request_1:
            end_reporting_line(request_1, Actor.system(), line_ab)
            request_1.commit()
        try:
            end_reporting_line(request_2, Actor.system(), line_ab)
            problems.append("a reporting line ended meanwhile was ended a second time")
        except ReportingLineError:
            pass

    # 4. Two changes in one company take turns: while request 1 holds the company lock,
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
    return problems


def _line_authz_race_problems(engine: Engine) -> list[str]:
    """Adding and ending reporting lines while another request changed who may do it;
    return what failed (review of #164).

    add_line() and end_line() take the company's lock, then check everything again on
    fresh reads: the actor's reporting_line.manage over both people, each person's place
    in its scope, the place above each, and for a new line that both are still active
    (app/modules/reporting_lines/service.py, top of the file). Each check below fixes
    request 2's view first (ordinary reads, as its session and permission checks make),
    lets request 1 commit a change, and then runs request 2's change through the service.
    Request 2's checks before the lock still see the old view, so only the ones after the
    lock can catch the change:

    1. A person deactivated meanwhile: no new line for them (409).
    2. A person moved meanwhile to a department outside the actor's grant: refused (403).
    3. The actor's reporting_line.manage taken away meanwhile: adding is refused (403).
    4. The same, for ending a line: refused (403).

    The service commits when it goes ahead, so a check that wrongly passes leaves its
    line behind: each check uses its own employee, so it cannot change the next one.
    """
    from sqlalchemy import delete, select, update
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.auth.models import UserSession
    from app.authz.chain import add_reporting_line
    from app.authz.check import Forbidden
    from app.authz.models import ReportingLine, Role, RoleAssignment
    from app.authz.roles import assign_role, create_starting_roles
    from app.db.base import utcnow
    from app.modules.org.models import Company, Department, User
    from app.modules.org.service import Conflict
    from app.modules.reporting_lines import service as lines
    from app.modules.reporting_lines.schemas import LineCreate
    from app.modules.roles import service as role_service
    from app.modules.roles.schemas import RoleCreate
    from app.tenancy.context import set_company

    problems: list[str] = []
    # A company of its own, made by platform code (a session with no company).
    with Session(engine) as platform:
        company = Company(name="line authorization race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # A sign-in session whose password was just entered again (changing lines needs
    # it). It is never saved: require_reauth() only looks at its reauth_at.
    reauthed = UserSession(reauth_at=utcnow())

    # The owner, and a boss above a and the employees b, d, e (one per check) and c, all
    # in Office; Floor is elsewhere. The line a -> c is there to be ended (check 4).
    with session() as db:
        office, floor = Department(name="Office"), Department(name="Floor")
        db.add_all([office, floor])
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        people = {
            name: User(
                email=f"{name}@line-race.example.com",
                display_name=name,
                department_id=office.id,
            )
            for name in ("owner", "boss", "a", "b", "c", "d", "e")
        }
        db.add_all(people.values())
        db.flush()
        assign_role(
            db,
            Actor.system(),
            user_id=people["owner"].id,
            role=roles["owner"],
            scope_type="company",
        )
        for manager, employee in (
            ("boss", "a"),
            ("boss", "b"),
            ("boss", "c"),
            ("boss", "d"),
            ("boss", "e"),
            ("a", "c"),
        ):
            add_reporting_line(
                db, Actor.system(), manager_id=people[manager].id, employee_id=people[employee].id
            )
        db.commit()
        ids = {name: person.id for name, person in people.items()}
        office_id, floor_id = office.id, floor.id

    def person(db: Session, name: str) -> User:
        found = db.get(User, ids[name])
        if found is None:  # made above, in this company
            raise RuntimeError("a line race probe person is missing")
        return found

    # The boss's role: reporting_line.manage for Office, made by the owner.
    with session() as db:
        manages = role_service.create_role(
            db,
            person(db, "owner"),
            RoleCreate(name="Line keeper", permissions=["reporting_line.manage"]),
        ).id
        db.commit()

    def give_boss_the_role() -> None:
        with session() as db:
            found = db.get(Role, manages)
            if found is None:  # made above
                raise RuntimeError("the line race probe role is missing")
            assign_role(
                db,
                Actor.system(),
                user_id=ids["boss"],
                role=found,
                scope_type="department",
                scope_id=office_id,
            )
            db.commit()

    give_boss_the_role()
    with session() as db:
        line_ac = db.scalars(
            select(ReportingLine.id).where(
                ReportingLine.manager_id == ids["a"],
                ReportingLine.employee_id == ids["c"],
            )
        ).one()

    def meanwhile(change: object) -> None:
        """Request 1: one change, committed."""
        with session() as request_1:
            request_1.execute(change)  # type: ignore[call-overload]
            request_1.commit()

    def fixed_view(db: Session) -> User:
        """Request 2 reads what its permission checks would, so its view is now fixed."""
        db.scalars(select(RoleAssignment)).all()
        for name in ("a", "b", "c", "d", "e"):
            person(db, name)
        return person(db, "boss")

    def add_a_over(db: Session, boss: User, employee: str) -> None:
        lines.add_line(
            db, boss, LineCreate(manager_id=ids["a"], employee_id=ids[employee]), session=reauthed
        )

    # 1. b deactivated meanwhile.
    with session() as request_2:
        boss = fixed_view(request_2)
        meanwhile(update(User).where(User.id == ids["b"]).values(deactivated_at=utcnow()))
        try:
            add_a_over(request_2, boss, "b")
        except Conflict:
            pass  # refused: the deactivation was seen
        else:
            problems.append("a reporting line was added for a person deactivated meanwhile")
        request_2.rollback()
    meanwhile(update(User).where(User.id == ids["b"]).values(deactivated_at=None))

    # 2. d moved meanwhile to Floor, outside the boss's Office grant.
    with session() as request_2:
        boss = fixed_view(request_2)
        meanwhile(update(User).where(User.id == ids["d"]).values(department_id=floor_id))
        try:
            add_a_over(request_2, boss, "d")
        except Forbidden:
            pass  # refused: the move was seen
        else:
            problems.append("a reporting line was added for a person moved out of scope meanwhile")
        request_2.rollback()
    meanwhile(update(User).where(User.id == ids["d"]).values(department_id=office_id))

    take_away = delete(RoleAssignment).where(
        RoleAssignment.user_id == ids["boss"], RoleAssignment.role_id == manages
    )
    # 3. The boss's reporting_line.manage taken away, then adding.
    with session() as request_2:
        boss = fixed_view(request_2)
        meanwhile(take_away)
        try:
            add_a_over(request_2, boss, "e")
        except Forbidden:
            pass  # refused: the boss's current grants were seen
        else:
            problems.append("a reporting line was added after reporting_line.manage was taken away")
        request_2.rollback()
    give_boss_the_role()

    # 4. The same, then ending a line.
    with session() as request_2:
        boss = fixed_view(request_2)
        request_2.get(ReportingLine, line_ac)
        meanwhile(take_away)
        try:
            lines.end_line(request_2, boss, line_ac, session=reauthed)
        except Forbidden:
            pass  # refused: the boss's current grants were seen
        else:
            problems.append("a reporting line was ended after reporting_line.manage was taken away")
        request_2.rollback()
    return problems


def _shift_race_problems(engine: Engine) -> list[str]:
    """Two requests booking one person on overlapping shifts; return what failed.

    The double-booking check locks the person's row and then looks for overlaps with a
    locking read (app/modules/schedules/repository.py, has_overlap). This runs the same
    check the service runs for every assignment (_check_assignable); a time change in
    update_shift() uses the same overlap query.
    """
    from datetime import timedelta

    from sqlalchemy.orm import Session

    from app.db.base import utcnow
    from app.modules.org.models import Company, Department, User
    from app.modules.schedules import repository, service
    from app.modules.schedules.models import Shift
    from app.tenancy.context import set_company

    problems = []
    # A company, made by platform code (a session with no company).
    with Session(engine) as platform:
        company = Company(name="shift race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # One person who can be assigned (set up, active, home department), and two open
    # shifts in their department tomorrow that overlap: 09:00 to 17:00 and 12:00 to 20:00.
    with session() as db:
        department = Department(name="Kitchen")
        db.add(department)
        db.flush()
        person = User(
            email="worker@race.example.com",
            display_name="worker",
            department_id=department.id,
            # Any value counts as "has set up their account". Random text is never a
            # valid Argon2id hash, so no password can sign in as this probe person.
            password_hash=secrets.token_hex(16),
        )
        tomorrow = utcnow().replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        shifts = [
            Shift(
                department_id=department.id,
                starts_at=tomorrow + timedelta(hours=start),
                ends_at=tomorrow + timedelta(hours=end),
                timezone="UTC",
                status="open",
            )
            for start, end in ((9, 17), (12, 20))
        ]
        db.add(person)
        db.add_all(shifts)
        db.commit()
        person_id = person.id
        department_id = department.id
        first_id, second_id = (item.id for item in shifts)

    # Request 2 reads its shift first, as the endpoint does before checking permission.
    # Under MySQL's REPEATABLE READ, that read fixes what its ordinary SELECTs see.
    with session() as request_2:
        second = repository.shift(request_2, second_id)
        if second is None:  # made above, in this company, so always found
            raise RuntimeError("the race probe's second shift is missing")
        # Request 1 now books the person on the first shift and commits.
        with session() as request_1:
            first = repository.shift(request_1, first_id)
            if first is None:
                raise RuntimeError("the race probe's first shift is missing")
            service._check_assignable(request_1, first, person_id)
            first.employee_id = person_id
            first.status = "scheduled"
            request_1.commit()
        # Request 2 books the same person on the overlapping shift: it must be refused.
        try:
            service._check_assignable(request_2, second, person_id)
        except service.Conflict:
            pass  # refused: the overlap committed meanwhile was seen
        else:
            problems.append("an overlapping shift committed meanwhile was not seen")

    # 2. Two assignments truly at the same moment, through the service as an endpoint calls
    #    it (assign_shift, with its permission checks and audit entry). Both requests have a
    #    shift change to make while they compete for the same person's lock. Exactly one
    #    must succeed and the other be refused (409); a deadlock, or any other error, means
    #    the locks are taken in different orders (_lock_for_change). A deadlock only happens
    #    when the timing is unlucky, so this is tried several times.
    problems += _concurrent_assignment_problems(session, department_id, person_id, tomorrow)
    return problems


def _concurrent_assignment_problems(
    session: Callable[[], Session],
    department_id: uuid.UUID,
    person_id: uuid.UUID,
    first_day: datetime,
) -> list[str]:
    """Rounds of two threads assigning overlapping shifts to one person at the same moment."""
    import threading
    from datetime import timedelta

    from app.audit import Actor
    from app.authz.roles import assign_role, create_starting_roles
    from app.modules.org.models import User
    from app.modules.schedules import service
    from app.modules.schedules.models import Shift

    rounds = 10
    problems = []

    # Someone allowed to assign shifts: an owner, given the starting Owner role.
    with session() as db:
        roles = create_starting_roles(db, Actor.system())
        owner = User(
            email="owner@race.example.com", display_name="owner", department_id=department_id
        )
        db.add(owner)
        db.flush()
        assign_role(db, Actor.system(), user_id=owner.id, role=roles["owner"], scope_type="company")
        db.commit()
        owner_id = owner.id

    for number in range(rounds):
        # Two open shifts that overlap (09:00 to 17:00 and 12:00 to 20:00), on a day of
        # their own, so earlier rounds' bookings never get in the way.
        day = first_day + timedelta(days=number + 1)
        with session() as db:
            pair = [
                Shift(
                    department_id=department_id,
                    starts_at=day + timedelta(hours=start),
                    ends_at=day + timedelta(hours=end),
                    timezone="UTC",
                    status="open",
                )
                for start, end in ((9, 17), (12, 20))
            ]
            db.add_all(pair)
            db.commit()
            shift_ids = [item.id for item in pair]

        # Both threads wait at the barrier, then assign at the same moment.
        start_together = threading.Barrier(2)
        outcomes: list[str] = []

        def request(
            shift_id: uuid.UUID, start_together: threading.Barrier, outcomes: list[str]
        ) -> None:
            with session() as db:
                acting = db.get(User, owner_id)
                if acting is None:  # made above, in this company
                    outcomes.append("error: the owner is missing")
                    return
                start_together.wait()
                try:
                    service.assign_shift(db, acting, shift_id, person_id)
                    outcomes.append("assigned")
                except service.Conflict:
                    outcomes.append("refused")
                except Exception as error:  # a deadlock, or anything else: reported below
                    outcomes.append(f"error: {error!r}"[:300])

        threads = [
            threading.Thread(target=request, args=(shift_id, start_together, outcomes))
            for shift_id in shift_ids
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        if sorted(outcomes) != ["assigned", "refused"]:
            problems.append(f"concurrent assignments, round {number + 1}: {outcomes}")
            break  # one failing round is enough to show the problem
    return problems


def _org_race_problems(engine: Engine) -> list[str]:
    """Departments and teams changed by two requests at the same moment; return what failed.

    1. Archiving a department checks, after locking it, that nobody still depends on it:
       people, upcoming shifts, active teams. Each check is a locking read, so it sees a
       row another request committed while this one waited (app/modules/org/repository.py).
    2. A team change locks the team and reads it fresh, so a change that waited for an
       archive is refused (app/modules/org/service.py, _changeable_team).
    3. Two requests creating the same department name at the same moment: one is saved,
       the other is refused with 409. The database refuses the second when its row is
       sent, before the commit; that must still be a 409, never an error.
    """
    import threading
    from datetime import timedelta

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.authz.roles import assign_role, create_starting_roles
    from app.db.base import utcnow
    from app.modules.org import repository, service
    from app.modules.org.models import Company, Department, Team, User
    from app.modules.org.schemas import DepartmentCreate
    from app.modules.schedules.models import Shift
    from app.tenancy.context import set_company

    problems = []
    # A company of its own, made by platform code (a session with no company).
    with Session(engine) as platform:
        company = Company(name="org race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # An owner, for the requests that go through the service's permission check.
    with session() as db:
        home = Department(name="Office")
        db.add(home)
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        owner = User(
            email="owner@org-race.example.com", display_name="owner", department_id=home.id
        )
        db.add(owner)
        db.flush()
        assign_role(db, Actor.system(), user_id=owner.id, role=roles["owner"], scope_type="company")
        db.commit()
        owner_id, home_id = owner.id, home.id

    # 1. Each archive check, against a row committed by another request meanwhile.
    tomorrow = utcnow() + timedelta(days=1)
    late_rows = {
        "team": lambda department_id: Team(department_id=department_id, name="Late"),
        "person": lambda department_id: User(
            email=f"late-{department_id}@org-race.example.com",
            display_name="late",
            department_id=department_id,
        ),
        "upcoming shift": lambda department_id: Shift(
            department_id=department_id,
            starts_at=tomorrow,
            ends_at=tomorrow + timedelta(hours=6),
            timezone="UTC",
            status="open",
        ),
    }
    checks = {
        "team": lambda db, department_id: repository.has_active_teams(db, department_id),
        "person": lambda db, department_id: repository.is_anyones_home(db, department_id),
        "upcoming shift": lambda db, department_id: repository.has_upcoming_shifts(
            db, department_id, utcnow()
        ),
    }
    for kind, make_row in late_rows.items():
        # A department of its own for each kind, empty to begin with.
        with session() as db:
            department = Department(name=f"Archive probe ({kind})")
            db.add(department)
            db.commit()
            department_id = department.id
        with session() as request_2:
            # Request 2 has read something (as its session and permission checks do),
            # which fixes what its ordinary SELECTs see under REPEATABLE READ.
            request_2.scalars(select(Department)).all()
            # Request 1 adds the row and commits.
            with session() as request_1:
                request_1.add(make_row(department_id))
                request_1.commit()
            # Request 2 locks the department, as archive_department() does, and checks.
            repository.department(request_2, department_id, lock=True)
            if not checks[kind](request_2, department_id):
                problems.append(f"archiving a department missed this, committed meanwhile: {kind}")

    # 2. A team archived while another request held an old copy of it.
    with session() as db:
        team = Team(department_id=home_id, name="Archive probe")
        db.add(team)
        db.commit()
        team_id = team.id
    with session() as request_2:
        stale = repository.team(request_2, team_id)  # read while the team is active
        with session() as request_1:
            archived = request_1.get(Team, team_id)
            if archived is None:  # made above, in this company
                raise RuntimeError("the race probe's team is missing")
            archived.archived_at = utcnow()
            request_1.commit()
        try:
            service._changeable_team(request_2, team_id)
        except service.Conflict:
            pass  # refused: the archive committed meanwhile was seen
        else:
            problems.append("a team archived meanwhile could still be changed")
        del stale

    # 3. Two requests creating the same department name at the same moment, several
    #    rounds (the timing differs each time). Exactly one is saved, the other refused.
    for number in range(5):
        start_together = threading.Barrier(2)
        outcomes: list[str] = []

        def request(name: str, start_together: threading.Barrier, outcomes: list[str]) -> None:
            with session() as db:
                acting = db.get(User, owner_id)
                if acting is None:  # made above, in this company
                    outcomes.append("error: the owner is missing")
                    return
                start_together.wait()
                try:
                    service.create_department(db, acting, DepartmentCreate(name=name))
                    outcomes.append("created")
                except service.Conflict:
                    outcomes.append("refused")
                except Exception as error:  # a 500 in the app: reported below
                    outcomes.append(f"error: {error!r}"[:300])

        name = f"Same name {number + 1}"
        threads = [
            threading.Thread(target=request, args=(name, start_together, outcomes))
            for _ in range(2)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        if sorted(outcomes) != ["created", "refused"]:
            problems.append(f"two departments with one name, round {number + 1}: {outcomes}")
            break  # one failing round is enough to show the problem
    return problems


def _role_race_problems(engine: Engine) -> list[str]:
    """Role changes made while another request changed the same things; return what failed.

    The role service takes the company's lock and then reads everything it depends on
    fresh (app/modules/roles/service.py, top of the file). Each check below fixes request
    2's view first (an ordinary read, as its session and permission checks make), lets
    request 1 commit a change, and then runs request 2 through the service:

    1. Two edits of one role: request 1 adds a permission, request 2 then sends its own full list.
       Request 2's result must be exactly its list (worked out from request 1's result),
       never a mix that neither request asked for.
    2. An administrator whose role was taken away meanwhile: their change is refused.
    3. The role limit: a company one role short of it, and one role created meanwhile.
       Request 2 must be refused, so the company never goes past the limit.
    """
    from sqlalchemy import delete, select
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.auth.models import UserSession
    from app.authz.check import Forbidden
    from app.authz.delegation import what_role_grants
    from app.authz.models import Role, RoleAssignment
    from app.authz.roles import assign_role, create_starting_roles
    from app.db.base import utcnow
    from app.modules.org.models import Company, Department, User
    from app.modules.org.service import Conflict
    from app.modules.roles import service
    from app.modules.roles.schemas import RoleCreate, RoleUpdate
    from app.tenancy.context import set_company

    problems = []
    # A company of its own, made by platform code (a session with no company).
    with Session(engine) as platform:
        company = Company(name="role race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # A sign-in session whose password was just entered again, for the sensitive changes.
    # It is never saved: require_reauth() only looks at its reauth_at.
    reauthed = UserSession(reauth_at=utcnow())

    # An owner and an administrator, and a role to edit.
    with session() as db:
        home = Department(name="Office")
        db.add(home)
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        owner = User(
            email="owner@role-race.example.com", display_name="owner", department_id=home.id
        )
        admin = User(
            email="admin@role-race.example.com", display_name="admin", department_id=home.id
        )
        db.add_all([owner, admin])
        db.flush()
        assign_role(db, Actor.system(), user_id=owner.id, role=roles["owner"], scope_type="company")
        assign_role(
            db, Actor.system(), user_id=admin.id, role=roles["administrator"], scope_type="company"
        )
        db.commit()
        owner_id, admin_id = owner.id, admin.id
    with session() as db:
        acting = db.get(User, owner_id)
        if acting is None:  # made above, in this company
            raise RuntimeError("the role race probe's owner is missing")
        edited = service.create_role(
            db, acting, RoleCreate(name="Edited", permissions=["schedule.view_self"])
        )
        db.commit()
        edited_id = edited.id

    def person(db: Session, user_id: uuid.UUID) -> User:
        found = db.get(User, user_id)
        if found is None:  # made above, in this company
            raise RuntimeError("a role race probe person is missing")
        return found

    # 1. Two edits of one role.
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        with session() as request_1:
            service.update_role(
                request_1,
                person(request_1, owner_id),
                edited_id,
                RoleUpdate(permissions=["schedule.view_self", "schedule.view"]),
                session=reauthed,
            )
            request_1.commit()
        wanted = ["schedule.view_self", "user.view"]
        service.update_role(
            request_2,
            person(request_2, owner_id),
            edited_id,
            RoleUpdate(permissions=wanted),
            session=reauthed,
        )
        request_2.commit()
    with session() as db:  # a new request, so it sees both commits
        saved = db.get(Role, edited_id)
        result = sorted(what_role_grants(db, saved)) if saved is not None else []
        if result != sorted(wanted):
            problems.append(f"two role edits mixed their lists: {result}, wanted {wanted}")

    # 2. An administrator whose role was taken away while their request waited.
    with session() as request_2:
        acting = person(request_2, admin_id)
        request_2.scalars(select(RoleAssignment)).all()  # its view is now fixed
        with session() as request_1:
            request_1.execute(delete(RoleAssignment).where(RoleAssignment.user_id == admin_id))
            request_1.commit()
        try:
            service.create_role(request_2, acting, RoleCreate(name="Too late", permissions=[]))
        except Forbidden:
            pass  # refused: the role taken away meanwhile was seen
        else:
            problems.append("an administrator whose role was taken away could still create roles")
        request_2.rollback()

    # 3. The role limit: fill the company up to one short of it.
    with session() as db:
        count = len(db.scalars(select(Role.id)).all())
        db.add_all(Role(name=f"Filler {n}") for n in range(service.MAX_ROLES - 1 - count))
        db.commit()
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        with session() as request_1:
            service.create_role(
                request_1, person(request_1, owner_id), RoleCreate(name="Last", permissions=[])
            )
            request_1.commit()
        try:
            service.create_role(
                request_2, person(request_2, owner_id), RoleCreate(name="Over", permissions=[])
            )
        except Conflict:
            pass  # refused: the role created meanwhile was counted
        else:
            problems.append(f"a company went past {service.MAX_ROLES} roles")
        request_2.rollback()
    return problems


def _lapse_race_problems(engine: Engine) -> list[str]:
    """Two requests noticing one overdue request at once; return what failed (review of #166).

    lapse() (app/approvals/service.py) claims the request with one conditional UPDATE, so
    only one request lapses it. The one that loses then reads the request again, and
    under MySQL's REPEATABLE READ an ordinary read there answers from its old snapshot:
    it would still see "pending" after the winner committed the denial. So request 2
    fixes its view first (an ordinary read, as a list page makes), request 1 lapses the
    request and commits, and then request 2 runs lapse() and time off's refresh():

    1. Request 2 must not lapse it again (one audit entry, from request 1).
    2. Request 2's copies must show what was committed: the approval declined as not
       reviewed, and the time-off request declined.
    3. What request 2 answers must show it too (second review of #166): its own list
       filtered to "denied" includes the request, and its not-reviewed flag is set. Those
       are ordinary queries after refresh(), so they would answer from request 2's old
       snapshot unless refresh() ended it.
    """
    from datetime import timedelta

    from sqlalchemy import func, select, update
    from sqlalchemy.orm import Session

    import app.modules.time_off.approval  # noqa: F401  (registers the "time_off" handler)
    from app.approvals.models import ApprovalRequest
    from app.approvals.service import lapse, open_request
    from app.audit import Actor
    from app.audit.models import AuditEvent
    from app.authz.roles import assign_role, create_starting_roles
    from app.db.base import utcnow
    from app.modules.org.models import Company, Department, User
    from app.modules.time_off.models import TimeOffRequest
    from app.modules.time_off.service import list_requests, not_reviewed, refresh
    from app.tenancy.context import set_company

    problems: list[str] = []
    with Session(engine) as platform:
        company = Company(name="lapse race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # One person asking for tomorrow off, as time off's ask() records it.
    with session() as db:
        home = Department(name="Office")
        db.add(home)
        db.flush()
        asker = User(
            email="asker@lapse-race.example.com", display_name="asker", department_id=home.id
        )
        db.add(asker)
        db.flush()
        # The Employee role, so the asker may list their own requests (check 3).
        roles = create_starting_roles(db, Actor.system())
        assign_role(
            db,
            Actor.system(),
            user_id=asker.id,
            role=roles["employee"],
            scope_type="department",
            scope_id=home.id,
        )
        tomorrow = (utcnow() + timedelta(days=1)).date()
        approval = open_request(
            db,
            kind="time_off",
            requested_by=asker.id,
            subject_user_id=asker.id,
            payload={},
            details={},
            review_by=utcnow() + timedelta(days=1),
        )
        row = TimeOffRequest(
            employee_id=asker.id,
            first_day=tomorrow,
            last_day=tomorrow,
            status="pending",
            approval_request_id=approval.id,
        )
        db.add(row)
        db.flush()
        approval.payload = {"time_off_request_id": str(row.id)}
        db.commit()
        approval_id, row_id, asker_id = approval.id, row.id, asker.id
    # Its deadline passes, as if its first day had begun undecided.
    with session() as db:
        db.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == approval_id)
            .values(review_by=utcnow() - timedelta(seconds=1))
        )
        db.commit()

    with session() as request_2:
        copy = request_2.get(ApprovalRequest, approval_id)
        old_row = request_2.get(TimeOffRequest, row_id)  # its view is now fixed
        if copy is None or old_row is None:  # made above, in this company
            raise RuntimeError("the lapse race probe's request is missing")
        with session() as request_1:
            first = request_1.get(ApprovalRequest, approval_id)
            if first is None or not lapse(request_1, first):
                problems.append("an overdue request did not lapse")
            request_1.commit()
        if lapse(request_2, copy):
            problems.append("an overdue request lapsed twice")
        if copy.status != "denied" or not copy.not_reviewed:
            problems.append(
                f"the request that lost the lapse race saw the approval as {copy.status!r}"
            )
        refresh(request_2, [old_row])
        if old_row.status != "denied":
            problems.append(
                f"the request that lost the lapse race saw the time off as {old_row.status!r}"
            )
        # 3. What request 2 answers: its list filtered to "denied", and the flag.
        me = request_2.get(User, asker_id)
        if me is None:  # made above
            raise RuntimeError("the lapse race probe's asker is missing")
        denied = list_requests(
            request_2,
            me,
            mine=True,
            status="denied",
            employee_id=None,
            first=None,
            last=None,
            limit=50,
        )
        if row_id not in {row.id for row in denied}:
            problems.append("a request lapsed by another request was missing from the denied list")
        if not not_reviewed(request_2, denied or [old_row]).get(row_id):
            problems.append("a request lapsed by another request was not flagged as not reviewed")
        request_2.rollback()
    with session() as db:
        entries = db.scalar(
            select(func.count()).where(
                AuditEvent.chain_id == company_id,
                AuditEvent.action == "approval.not_reviewed",
                AuditEvent.target_id == approval_id,
            )
        )
        if entries != 1:
            problems.append(f"an overdue request has {entries} not-reviewed audit entries")
    return problems


def _assignment_race_problems(engine: Engine) -> list[str]:
    """Giving and removing roles while another request changed what the checks depend on;
    return what failed (review of #162).

    give() and remove() take the company's lock and then make every check again on fresh
    reads (app/modules/roles/assignments.py, top of the file). Each check below fixes
    request 2's view first (an ordinary read, as its session and permission checks make),
    lets request 1 commit a change, and then runs request 2 through the service. Request
    2's quick checks before the lock still see the old view, so only the checks after
    the lock can catch the change:

    1. A role edited meanwhile to grant a permission the giver lacks: refused (AZ3).
    2. A giver who lost permissions meanwhile, so the role is now at their own level: the
       role is not given straight away; an approval request is opened instead (AZ14).
    3. A person moved meanwhile to a department the giver does not cover: refused.
    4. A role archived meanwhile: refused.
    5. The giver's role.assign taken away meanwhile: giving and removing are refused.

    Check 3 moves "mover" out of the giver's reach for good, so the later checks give to
    "worker", with roles nobody gave them yet (so no other refusal can stand in).

    Request 2 always rolls back, so a check that wrongly passes leaves nothing behind.
    """
    from sqlalchemy import delete, select, update
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.auth.models import UserSession
    from app.authz.chain import add_reporting_line
    from app.authz.check import Forbidden
    from app.authz.models import Role, RoleAssignment
    from app.authz.roles import assign_role, create_starting_roles
    from app.db.base import utcnow
    from app.modules.org.models import Company, Department, User
    from app.modules.org.service import Conflict
    from app.modules.roles import assignments, service
    from app.modules.roles.schemas import AssignmentCreate, RoleCreate, RoleUpdate
    from app.tenancy.context import set_company

    problems: list[str] = []
    # A company of its own, made by platform code (a session with no company).
    with Session(engine) as platform:
        company = Company(name="assignment race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # A sign-in session whose password was just entered again (role.assign is admin
    # level). It is never saved: require_reauth() only looks at its reauth_at.
    reauthed = UserSession(reauth_at=utcnow())

    # The owner; a giver who manages the Office department with a role of its own; and two
    # people in Office who report to the giver.
    with session() as db:
        office, elsewhere = Department(name="Office"), Department(name="Elsewhere")
        db.add_all([office, elsewhere])
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        people = {
            name: User(
                email=f"{name}@assignment-race.example.com",
                display_name=name,
                department_id=office.id,
            )
            for name in ("owner", "giver", "worker", "mover")
        }
        db.add_all(people.values())
        db.flush()
        assign_role(
            db,
            Actor.system(),
            user_id=people["owner"].id,
            role=roles["owner"],
            scope_type="company",
        )
        for report in ("worker", "mover"):
            add_reporting_line(
                db, Actor.system(), manager_id=people["giver"].id, employee_id=people[report].id
            )
        db.commit()
        ids = {name: person.id for name, person in people.items()}
        office_id, elsewhere_id = office.id, elsewhere.id

    def person(db: Session, name: str) -> User:
        found = db.get(User, ids[name])
        if found is None:  # made above, in this company
            raise RuntimeError("an assignment race probe person is missing")
        return found

    # The roles, made by the owner: the giver's own, and one to give for each check.
    with session() as db:
        owner = person(db, "owner")

        def role(name: str, codes: list[str]) -> uuid.UUID:
            return service.create_role(db, owner, RoleCreate(name=name, permissions=codes)).id

        giver_role = role("Giver", ["role.assign", "schedule.view_self", "schedule.view"])
        edited = role("Edited", ["schedule.view_self"])
        level = role("Level", ["role.assign", "schedule.view_self"])
        small = role("Small", ["schedule.view_self"])
        archived = role("Archived", ["schedule.view_self"])
        last = role("Last", ["schedule.view_self"])
        db.commit()
    with session() as db:
        for role_id, holder in ((giver_role, "giver"), (small, "worker")):
            found = db.get(Role, role_id)
            if found is None:  # made above
                raise RuntimeError("an assignment race probe role is missing")
            assign_role(
                db,
                Actor.system(),
                user_id=ids[holder],
                role=found,
                scope_type="department",
                scope_id=office_id,
            )
        db.commit()
        held = db.scalars(
            select(RoleAssignment.id).where(RoleAssignment.user_id == ids["worker"])
        ).one()

    def give(db: Session, name: str, role_id: uuid.UUID) -> assignments.Given:
        """Request 2 gives the role for Office, as the giver."""
        body = AssignmentCreate(
            user_id=ids[name], role_id=role_id, scope_type="department", scope_id=office_id
        )
        return assignments.give(db, person(db, "giver"), body, session=reauthed)

    def owner_changes(change: Callable[[Session, User], object]) -> None:
        """Request 1: the owner makes a change and commits."""
        with session() as request_1:
            change(request_1, person(request_1, "owner"))
            request_1.commit()

    # 1. A role edited to grant a permission the giver lacks (schedule.edit).
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        owner_changes(
            lambda db, owner: service.update_role(
                db,
                owner,
                edited,
                RoleUpdate(permissions=["schedule.view_self", "schedule.edit"]),
                session=reauthed,
            )
        )
        try:
            give(request_2, "worker", edited)
        except Forbidden:
            pass  # refused: what the role grants now was seen
        else:
            problems.append("a role edited to grant more than the giver holds was still given")
        request_2.rollback()

    # 2. The giver loses schedule.view, so "Level" now holds everything they hold there.
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        owner_changes(
            lambda db, owner: service.update_role(
                db,
                owner,
                giver_role,
                RoleUpdate(permissions=["role.assign", "schedule.view_self"]),
                session=reauthed,
            )
        )
        try:
            given = give(request_2, "worker", level)
        except (Forbidden, Conflict) as error:
            problems.append(f"a same-level role was refused instead of waiting: {error!r}")
        else:
            if given.assignment is not None or given.request is None:
                problems.append("a role at the giver's own level was given without approval")
        request_2.rollback()

    # 3. A person moved to a department the giver does not cover.
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        person(request_2, "mover")
        owner_changes(
            lambda db, _: db.execute(
                update(User).where(User.id == ids["mover"]).values(department_id=elsewhere_id)
            )
        )
        try:
            give(request_2, "mover", small)
        except Forbidden:
            pass  # refused: the person's current department was seen
        else:
            problems.append("a role was given to someone who had moved out of the giver's reach")
        request_2.rollback()

    # 4. A role archived.
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        owner_changes(
            lambda db, _: db.execute(
                update(Role).where(Role.id == archived).values(archived_at=utcnow())
            )
        )
        try:
            give(request_2, "worker", archived)
        except Conflict:
            pass  # refused: the archive was seen
        else:
            problems.append("an archived role was still given")
        request_2.rollback()

    # 5. The giver's role.assign taken away (their only role), while a give and a remove
    #    both waited.
    with session() as giving, session() as removing:
        giving.scalars(select(Role)).all()  # both views are now fixed
        removing.scalars(select(Role)).all()
        owner_changes(
            lambda db, _: db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id == ids["giver"])
            )
        )
        try:
            give(giving, "worker", last)
        except Forbidden:
            pass  # refused: the giver's current grants were seen
        else:
            problems.append("a giver whose role.assign was taken away could still give roles")
        giving.rollback()
        try:
            assignments.remove(removing, person(removing, "giver"), held, session=reauthed)
        except Forbidden:
            pass
        else:
            problems.append("a giver whose role.assign was taken away could still remove roles")
        removing.rollback()
    return problems


def _approval_race_problems(engine: Engine) -> list[str]:
    """Deciding and lapsing approval requests while another request changed what they
    depend on; return what failed (review of #163).

    A decision takes the company's lock, then reads the decider, the reviewers, and what
    approval changes again with locking reads (app/approvals/service.py and
    app/modules/roles/approval.py, top of each file). Each check below fixes request 2's
    view first (an ordinary read, as its session and permission checks make), lets
    request 1 commit a change, and then runs request 2's approval through the service.
    Request 2's checks before the lock still see the old view, so only the ones after
    the lock can catch the change:

    1. The reviewer's role.assign taken away meanwhile: the approval is refused.
    2. The requested role edited meanwhile to grant a permission the reviewer lacks: the
       reviewer can no longer give it, so the approval is refused (AZ3).
    3. The requested role archived meanwhile: the approval is refused (409).
    4. Two requests noticing one overdue request at once: only one lapses it (one
       not-reviewed audit entry), and the one that lost sees it declined as not reviewed,
       not its old snapshot's "pending" (lapse() claims it with one conditional UPDATE).

    Request 2 always rolls back, so a check that wrongly passes leaves nothing behind.
    """
    from datetime import timedelta

    from sqlalchemy import delete, func, select, update
    from sqlalchemy.orm import Session

    import app.modules.roles.approval  # noqa: F401  (registers the "role_assignment" handler)
    from app.approvals.models import ApprovalRequest
    from app.approvals.service import lapse, open_request
    from app.audit import Actor
    from app.audit.models import AuditEvent
    from app.auth.models import UserSession
    from app.authz.chain import add_reporting_line
    from app.authz.check import Forbidden
    from app.authz.models import Role, RoleAssignment
    from app.authz.roles import assign_role, create_starting_roles
    from app.db.base import utcnow
    from app.modules.approval_requests import service as approvals
    from app.modules.org.models import Company, Department, User
    from app.modules.org.service import Conflict
    from app.modules.roles import service
    from app.modules.roles.schemas import RoleCreate, RoleUpdate
    from app.tenancy.context import set_company

    problems: list[str] = []
    # A company of its own, made by platform code (a session with no company).
    with Session(engine) as platform:
        company = Company(name="approval race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # A sign-in session whose password was just entered again (role.assign is admin
    # level). It is never saved: require_reauth() only looks at its reauth_at.
    reauthed = UserSession(reauth_at=utcnow())

    # The owner; a reviewer who manages a giver, who manages a worker, all in Office.
    with session() as db:
        office = Department(name="Office")
        db.add(office)
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        people = {
            name: User(
                email=f"{name}@approval-race.example.com",
                display_name=name,
                department_id=office.id,
            )
            for name in ("owner", "reviewer", "giver", "worker")
        }
        db.add_all(people.values())
        db.flush()
        assign_role(
            db,
            Actor.system(),
            user_id=people["owner"].id,
            role=roles["owner"],
            scope_type="company",
        )
        for manager, employee in (("reviewer", "giver"), ("giver", "worker")):
            add_reporting_line(
                db, Actor.system(), manager_id=people[manager].id, employee_id=people[employee].id
            )
        db.commit()
        ids = {name: person.id for name, person in people.items()}
        office_id = office.id

    def person(db: Session, name: str) -> User:
        found = db.get(User, ids[name])
        if found is None:  # made above, in this company
            raise RuntimeError("an approval race probe person is missing")
        return found

    # The roles, made by the owner: the reviewer's own (for Office), and one to ask for in
    # each check. The reviewer holds everything each requested role grants.
    with session() as db:
        owner = person(db, "owner")

        def role(name: str, codes: list[str]) -> uuid.UUID:
            return service.create_role(db, owner, RoleCreate(name=name, permissions=codes)).id

        reviewer_role = role("Reviewer", ["role.assign", "schedule.view_self", "schedule.view"])
        edited = role("Edited", ["schedule.view_self"])
        archived = role("Archived", ["schedule.view_self"])
        revoked = role("Revoked", ["schedule.view_self"])
        lapsing = role("Lapsing", ["schedule.view_self"])
        db.commit()
    with session() as db:
        found = db.get(Role, reviewer_role)
        if found is None:  # made above
            raise RuntimeError("an approval race probe role is missing")
        assign_role(
            db,
            Actor.system(),
            user_id=ids["reviewer"],
            role=found,
            scope_type="department",
            scope_id=office_id,
        )
        db.commit()

    def ask(role_id: uuid.UUID) -> uuid.UUID:
        """The giver asks for the role for the worker, in Office (as a same-level grant
        does); committed, so both simulated requests see it."""
        with session() as db:
            request = open_request(
                db,
                kind="role_assignment",
                requested_by=ids["giver"],
                subject_user_id=ids["worker"],
                payload={
                    "role_id": str(role_id),
                    "scope_type": "department",
                    "scope_id": str(office_id),
                },
                details={},
            )
            db.commit()
            return request.id

    def owner_changes(change: Callable[[Session, User], object]) -> None:
        """Request 1: the owner makes a change and commits."""
        with session() as request_1:
            change(request_1, person(request_1, "owner"))
            request_1.commit()

    def approve(db: Session, request_id: uuid.UUID) -> None:
        """Request 2 approves, as the reviewer."""
        approvals.approve(db, person(db, "reviewer"), request_id, session=reauthed)

    # 2 first: edited and archived roles are refused whoever reviews, so they run while
    # the reviewer still holds role.assign (check 1 takes it away for good).
    # 2. The requested role edited to grant schedule.edit, which the reviewer lacks.
    asked = ask(edited)
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        person(request_2, "reviewer")
        owner_changes(
            lambda db, owner: service.update_role(
                db,
                owner,
                edited,
                RoleUpdate(permissions=["schedule.view_self", "schedule.edit"]),
                session=reauthed,
            )
        )
        try:
            approve(request_2, asked)
        except Forbidden:
            pass  # refused: what the role grants now was seen
        else:
            problems.append("a role edited to grant more than the reviewer holds was approved")
        request_2.rollback()

    # 3. The requested role archived.
    asked = ask(archived)
    with session() as request_2:
        request_2.scalars(select(Role)).all()  # its view is now fixed
        person(request_2, "reviewer")
        owner_changes(
            lambda db, _: db.execute(
                update(Role).where(Role.id == archived).values(archived_at=utcnow())
            )
        )
        try:
            approve(request_2, asked)
        except (Conflict, Forbidden):
            pass  # refused: the archive was seen
        else:
            problems.append("a request for an archived role was approved")
        request_2.rollback()

    # 1. The reviewer's role.assign taken away (their only role).
    asked = ask(revoked)
    with session() as request_2:
        request_2.scalars(select(RoleAssignment)).all()  # its view is now fixed
        person(request_2, "reviewer")
        owner_changes(
            lambda db, _: db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id == ids["reviewer"])
            )
        )
        try:
            approve(request_2, asked)
        except Forbidden:
            pass  # refused: the reviewer's current grants were seen
        else:
            problems.append("a reviewer whose role.assign was taken away could still approve")
        request_2.rollback()

    # 4. Two requests noticing one overdue request at once.
    asked = ask(lapsing)
    with session() as db:
        db.execute(
            update(ApprovalRequest)
            .where(ApprovalRequest.id == asked)
            .values(review_by=utcnow() - timedelta(seconds=1))
        )
        db.commit()
    with session() as request_2:
        copy = request_2.get(ApprovalRequest, asked)  # its view is now fixed
        if copy is None:  # made above, in this company
            raise RuntimeError("the approval race probe's request is missing")
        with session() as request_1:
            first = request_1.get(ApprovalRequest, asked)
            if first is None or not lapse(request_1, first):
                problems.append("an overdue request did not lapse")
            request_1.commit()
        if lapse(request_2, copy):
            problems.append("an overdue request lapsed twice")
        if copy.status != "denied" or not copy.not_reviewed:
            problems.append(f"the request that lost the lapse race saw {copy.status!r}")
        request_2.rollback()
    with session() as db:
        entries = db.scalar(
            select(func.count()).where(
                AuditEvent.chain_id == company_id,
                AuditEvent.action == "approval.not_reviewed",
                AuditEvent.target_id == asked,
            )
        )
        if entries != 1:
            problems.append(f"an overdue request has {entries} not-reviewed audit entries")
    return problems


def _owner_race_problems(engine: Engine) -> list[str]:
    """Owner changes while another request changed who they depend on; return what
    failed (review of #165).

    Proposing and approving an owner change take the company's lock, then read the
    proposer's permission and the owners again with locking reads, and lock the person's
    row (app/modules/owners/service.py, top of the file). Deactivation locks the same
    person row and checks for an owner on fresh reads (app/modules/org/people.py). Each
    check below fixes request 2's view first (an ordinary read, as its session and
    permission checks make), lets request 1 commit a change, and then runs request 2
    through the service, so only the checks after the lock can catch the change:

    1. The proposer's Owner role taken away meanwhile: their proposal is refused (403).
    2. The person deactivated meanwhile, with one owner (added at once): refused (409).
    3. The person deactivated meanwhile, while a request waits: the last approval is
       refused (409), and nobody becomes an owner.
    4. A person made an owner meanwhile: their deactivation is refused (409), so a company
       never ends up with a deactivated owner.
    5. An owner added while a request waits: the approval that used to be the last one is
       no longer enough; the new owner must agree too (AZ15).

    Request 2 always rolls back, so a check that wrongly passes leaves nothing behind.
    """
    from sqlalchemy import delete, select, update
    from sqlalchemy.orm import Session

    import app.modules.owners.approval  # noqa: F401  (registers the owner request kinds)
    from app.approvals.models import ApprovalRequest
    from app.audit import Actor
    from app.auth.models import UserSession
    from app.authz.check import Forbidden
    from app.authz.delegation import active_owners
    from app.authz.models import Role, RoleAssignment
    from app.authz.roles import assign_role, create_starting_roles
    from app.db.base import utcnow
    from app.modules.approval_requests import service as approvals
    from app.modules.org import people as accounts
    from app.modules.org.models import Company, Department, User
    from app.modules.org.service import Conflict
    from app.modules.owners import service as owners
    from app.tenancy.context import set_company

    problems: list[str] = []
    # A company of its own, made by platform code (a session with no company).
    with Session(engine) as platform:
        company = Company(name="owner race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # A sign-in session whose password was just entered again (owner changes always need
    # it). It is never saved: require_reauth() only looks at its reauth_at.
    reauthed = UserSession(reauth_at=utcnow())

    # Two owners to start with ("first" and "second"), and people to make owners.
    names = ("first", "second", "third", "dropped", "quitter", "waiting", "promoted", "late")
    with session() as db:
        office = Department(name="Office")
        db.add(office)
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        made = {
            name: User(
                email=f"{name}@owner-race.example.com",
                display_name=name,
                department_id=office.id,
            )
            for name in names
        }
        db.add_all(made.values())
        db.flush()
        for name in ("first", "second"):
            assign_role(
                db, Actor.system(), user_id=made[name].id, role=roles["owner"], scope_type="company"
            )
        db.commit()
        ids = {name: person.id for name, person in made.items()}
        owner_role = roles["owner"].id

    def person(db: Session, name: str) -> User:
        found = db.get(User, ids[name])
        if found is None:  # made above, in this company
            raise RuntimeError("an owner race probe person is missing")
        return found

    def fix_view(db: Session) -> None:
        """Request 2 reads the people and roles: its view is now fixed."""
        db.scalars(select(User)).all()
        db.scalars(select(RoleAssignment)).all()

    def committed(change: Callable[[Session], object]) -> None:
        """Request 1 makes a change and commits."""
        with session() as request_1:
            change(request_1)
            request_1.commit()

    def deactivated(name: str) -> Callable[[Session], object]:
        return lambda db: db.execute(
            update(User).where(User.id == ids[name]).values(deactivated_at=utcnow())
        )

    def made_owner(name: str) -> Callable[[Session], object]:
        def change(db: Session) -> None:
            role = db.get(Role, owner_role)
            if role is None:  # every company has one
                raise RuntimeError("the owner race probe's Owner role is missing")
            assign_role(db, Actor.system(), user_id=ids[name], role=role, scope_type="company")

        return change

    def owners_now() -> set[uuid.UUID]:
        with session() as db:
            return active_owners(db, fresh=False)

    # 3 first, while "first" and "second" are both owners: "first" asks to make "quitter"
    # an owner, and "second"'s approval meets the deactivation.
    with session() as db:
        asked = owners.add_owner(db, person(db, "first"), ids["quitter"], session=reauthed)
        if asked.request is None:
            raise RuntimeError("an owner change with two owners did not wait for approval")
        quitter_request = asked.request.id
    with session() as request_2:
        fix_view(request_2)
        request_2.get(ApprovalRequest, quitter_request)
        committed(deactivated("quitter"))
        try:
            approvals.approve(
                request_2, person(request_2, "second"), quitter_request, session=reauthed
            )
        except Conflict:
            pass  # refused: the deactivation was seen
        else:
            problems.append("a person deactivated while a request waited was made an owner")
        request_2.rollback()
    if ids["quitter"] in owners_now():
        problems.append("a deactivated person is an owner")

    # 5. "first" asks to make "waiting" an owner (needs "second"); meanwhile "third" is
    #    made an owner, so "second"'s approval is no longer the last one needed.
    with session() as db:
        asked = owners.add_owner(db, person(db, "first"), ids["waiting"], session=reauthed)
        if asked.request is None:
            raise RuntimeError("an owner change with two owners did not wait for approval")
        waiting_request = asked.request.id
    with session() as request_2:
        fix_view(request_2)
        request_2.get(ApprovalRequest, waiting_request)
        committed(made_owner("third"))
        decided = approvals.approve(
            request_2, person(request_2, "second"), waiting_request, session=reauthed
        )
        if decided.status != "pending":
            problems.append("an owner added while a request waited was not asked to agree")
        request_2.rollback()

    # 1. "second" loses the Owner role while proposing "dropped" as an owner.
    with session() as request_2:
        fix_view(request_2)
        committed(
            lambda db: db.execute(
                delete(RoleAssignment).where(
                    RoleAssignment.user_id == ids["second"], RoleAssignment.role_id == owner_role
                )
            )
        )
        try:
            owners.add_owner(
                request_2, person(request_2, "second"), ids["dropped"], session=reauthed
            )
        except Forbidden:
            pass  # refused: the removal was seen
        else:
            problems.append("an owner removed meanwhile could still propose an owner change")
        request_2.rollback()
    # "third" too, so "first" is the only owner from here on (owner changes at once).
    committed(
        lambda db: db.execute(
            delete(RoleAssignment).where(
                RoleAssignment.user_id == ids["third"], RoleAssignment.role_id == owner_role
            )
        )
    )

    # 2. "late" deactivated while the sole owner makes them an owner.
    with session() as request_2:
        fix_view(request_2)
        committed(deactivated("late"))
        try:
            owners.add_owner(request_2, person(request_2, "first"), ids["late"], session=reauthed)
        except Conflict:
            pass  # refused: the deactivation was seen
        else:
            problems.append("a person deactivated meanwhile was made an owner")
        request_2.rollback()

    # 4. "promoted" made an owner while the sole owner deactivates them.
    with session() as request_2:
        fix_view(request_2)
        committed(
            lambda db: owners.add_owner(db, person(db, "first"), ids["promoted"], session=reauthed)
        )
        try:
            accounts.deactivate(
                request_2, person(request_2, "first"), ids["promoted"], session=reauthed
            )
        except Conflict:
            pass  # refused: the new owner was seen
        else:
            problems.append("a person made an owner meanwhile could be deactivated")
        request_2.rollback()
    return problems


def _lockout_race_problems(engine: Engine) -> list[str]:
    """Wrong passwords for one account sent at the same moment; return what failed.

    Each sign-in locks the account's row before it reads the count of wrong passwords
    (app/auth/sessions.py). Without that, guesses sent together would each read the same
    count and each write it plus one, so a burst of parallel guesses would count as one
    and never reach the lockout. Six guesses sent together must take turns: the first
    five are counted and the fifth locks the account, so the sixth is refused as locked
    without being tried or counted. Without the lock they all read the same count, and
    the account ends up below 5 and unlocked (tried).
    """
    import threading

    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.auth import sessions
    from app.auth.passwords import hash_password
    from app.authz.roles import create_starting_roles
    from app.modules.org.models import Company, Department, User
    from app.tenancy.context import set_company

    with Session(engine) as platform:
        company = Company(name="lockout race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id
    with Session(engine) as db:
        set_company(db, company_id)
        home = Department(name="Office")
        db.add(home)
        db.flush()
        create_starting_roles(db, Actor.system())
        person = User(
            email=f"guessed-{company_id.hex}@lockout-race.example.com",
            display_name="guessed",
            department_id=home.id,
            password_hash=hash_password("the real long passphrase here"),
        )
        db.add(person)
        db.commit()
        person_id, address = person.id, person.email

    guesses = 6
    start = threading.Barrier(guesses)
    errors: list[str] = []

    def guess() -> None:
        # Each guess is its own request, in a session with no company yet, as at sign-in.
        with Session(engine) as db:
            start.wait()
            try:
                if sessions.sign_in(db, address, "a wrong guess"):
                    errors.append("a wrong password signed in")
            except Exception as error:  # a 500 in the app: reported below
                errors.append(f"error: {error!r}"[:300])

    threads = [threading.Thread(target=guess) for _ in range(guesses)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    with Session(engine) as db:
        set_company(db, company_id)
        guessed = db.get(User, person_id)
        counted = guessed.failed_sign_ins if guessed is not None else None
        locked = guessed is not None and guessed.locked_until is not None
    problems = [f"wrong passwords at the same moment: {error}" for error in errors]
    if counted != 5 or not locked:
        problems.append(
            f"{guesses} wrong passwords at the same moment counted {counted} (expected 5, "
            f"then locked), locked={locked}"
        )
    return problems


def _sign_up_race_problems(engine: Engine) -> list[str]:
    """Sign-ups racing for the last place under the platform limit; return what failed.

    Each sign-up locks the platform audit chain's head before it counts this hour's new
    companies (app/modules/sign_up/service.py). Without that, sign-ups sent together
    would each count the same number and each add a company, past the limit. With one
    place left, four sign-ups sent together must give exactly one new company; the other
    three are refused (429). Nothing else in this check writes to the platform chain, so
    these are the first sign-ups on a new platform: the lock holds the empty head that
    migration 0013 creates (without it, MySQL stopped the racers as deadlocks).
    """
    import threading

    from fastapi import HTTPException
    from pydantic import SecretStr
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from app.modules.org.models import Company
    from app.modules.sign_up import service
    from app.modules.sign_up.schemas import SignUpRequest

    with Session(engine) as platform:
        made_before = platform.scalar(select(func.count(Company.id))) or 0
    racers = 4
    # Every company in this throwaway database was made in the last hour: one place left.
    limit_before = service.PLATFORM_PER_HOUR
    service.PLATFORM_PER_HOUR = made_before + 1
    start = threading.Barrier(racers)
    outcomes: list[str] = []
    errors: list[str] = []

    def sign_up(number: int) -> None:
        body = SignUpRequest(
            company_name=f"Racer {number}",
            timezone="UTC",
            display_name=f"Racer {number}",
            email=f"racer-{number}@sign-up-race.example.com",
            password=SecretStr("lanterns drift over quiet waters"),
        )
        start.wait()
        try:
            service.sign_up(engine, body)
            outcomes.append("made")
        except HTTPException as error:  # TooManyRequests: the limit was reached
            outcomes.append(str(error.status_code))
        except Exception as error:  # a 500 in the app: reported below
            errors.append(f"error: {error!r}"[:300])

    try:
        threads = [threading.Thread(target=sign_up, args=(n,)) for n in range(racers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
    finally:
        service.PLATFORM_PER_HOUR = limit_before
    with Session(engine) as platform:
        made_after = platform.scalar(select(func.count(Company.id))) or 0
    problems = [f"sign-ups at the same moment: {error}" for error in errors]
    if made_after - made_before != 1 or sorted(outcomes) != ["429", "429", "429", "made"]:
        problems.append(
            f"{racers} sign-ups racing for one place made {made_after - made_before} "
            f"companies (expected 1), answers {sorted(outcomes)}"
        )
    return problems


def _link_race_problems(engine: Engine) -> list[str]:
    """Setup and reset links used and replaced at the same moment; return what failed.

    1. One link redeemed by two requests at the same moment, several rounds: exactly one
       sets the password, the other is refused as a link that does not work. Redeeming
       locks the person and then the link and reads the link fresh, so the second request
       sees that the first has used it (app/auth/links.py). Without the lock, both would
       read "not used yet" and both would set a password.
    2. A new link created while the old one is being redeemed: both lock the person first
       and the link second, so they take turns: either the old link is refused, or it
       sets the password first (and then a setup link no longer fits). Never an error.
    """
    import threading

    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.auth import links
    from app.auth.models import UserSession
    from app.authz.roles import assign_role, create_starting_roles
    from app.modules.org.models import Company, Department, User
    from app.tenancy.context import set_company

    problems: list[str] = []
    with Session(engine) as platform:
        company = Company(name="link race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # An owner (above everyone, with user.manage) and a new person without a password.
    with session() as db:
        home = Department(name="Office")
        db.add(home)
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        owner = User(
            email="owner@link-race.example.com", display_name="owner", department_id=home.id
        )
        db.add(owner)
        db.flush()
        assign_role(db, Actor.system(), user_id=owner.id, role=roles["owner"], scope_type="company")
        db.commit()
        owner_id, home_id = owner.id, home.id

    def new_person(number: int) -> object:
        with session() as db:
            person = User(
                email=f"new-{number}@link-race.example.com",
                display_name=f"new {number}",
                department_id=home_id,
            )
            db.add(person)
            db.commit()
            return person.id

    def create(person_id: object) -> str:
        """A setup link for the person, created by the owner; returns the token."""
        with session() as db:
            acting = db.get(User, owner_id)
            if acting is None:  # made above, in this company
                raise RuntimeError("the race probe's owner is missing")
            # create_link wants the acting person's session, for the password re-entry a
            # link for an administrator needs. The new people here hold no role, so it is
            # never asked for; an unsaved session stands in for the owner's.
            return links.create_link(
                db,
                acting,
                person_id,  # type: ignore[arg-type]
                "setup",
                session=UserSession(user_id=owner_id),
            ).token

    def redeem(token: str, password: str, start: threading.Barrier, outcomes: list[str]) -> None:
        # Each redemption is its own request, in a session with no company yet.
        with Session(engine) as db:
            start.wait()
            try:
                links.redeem(db, token, password)
                outcomes.append("set")
            except links.LinkNotValid:
                outcomes.append("refused")
            except Exception as error:  # a 500 in the app: reported below
                outcomes.append(f"error: {error!r}"[:300])

    # 1. One link, two redemptions at once.
    for number in range(3):
        token = create(new_person(number))
        start = threading.Barrier(2)
        outcomes: list[str] = []
        threads = [
            threading.Thread(target=redeem, args=(token, phrase, start, outcomes))
            for phrase in ("first chosen long passphrase", "second chosen long passphrase")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        if sorted(outcomes) != ["refused", "set"]:
            problems.append(f"one link used twice at once, round {number + 1}: {outcomes}")
            break  # one failing round is enough to show the problem

    # 2. A new link for the person while the old one is redeemed.
    for number in range(3):
        person_id = new_person(100 + number)
        token = create(person_id)
        start = threading.Barrier(2)
        outcomes = []

        def replace(start: threading.Barrier, outcomes: list[str], person_id: object) -> None:
            start.wait()
            try:
                create(person_id)
                outcomes.append("replaced")
            except links.Conflict:
                # Redeemed first: the person has a password now, so no setup link.
                outcomes.append("has a password")
            except Exception as error:  # a 500 in the app: reported below
                outcomes.append(f"error: {error!r}"[:300])

        threads = [
            threading.Thread(
                target=redeem, args=(token, "a chosen long passphrase", start, outcomes)
            ),
            threading.Thread(target=replace, args=(start, outcomes, person_id)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        # Either order is fine: replaced first, so the old link is refused; or redeemed
        # first, so the person has a password and a setup link no longer fits. Anything
        # else (an error, a deadlock, or a cancelled link that still set the password) is not.
        if sorted(outcomes) not in (["refused", "replaced"], ["has a password", "set"]):
            problems.append(f"a link replaced while it was used, round {number + 1}: {outcomes}")
            break
    return problems


def _people_race_problems(engine: Engine) -> list[str]:
    """Account changes meeting other changes at the same moment; return what failed.

    Each race runs two real requests in two threads, started together, several rounds
    (the timing differs each time). Whichever goes first, the result must keep the rules,
    and neither request may fail with an error (a deadlock would show up here as one):

    1. Two accounts with the same email: one is created, the other refused with 409.
    2. A deactivation and putting the same person on a team: nobody joins a team after
       being deactivated (both lock the person's row, app/modules/org/people.py). Joining
       just before is fine: a deactivation keeps team memberships for history.
    3. Moving a person to a department and archiving that department: never an archived
       department that is an active person's home. Both lock the department, so they
       take turns: the archive then sees the person who moved in, or the move sees the
       department archived. (Without the move's lock, both succeed: tried.)
    """
    import threading

    from sqlalchemy import or_, select
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.audit.models import AuditEvent
    from app.auth.models import UserSession
    from app.authz.roles import assign_role, create_starting_roles
    from app.modules.org import people, service
    from app.modules.org.models import Company, Department, Team, User
    from app.modules.org.schemas import UserCreate, UserUpdate
    from app.tenancy.context import set_company

    problems: list[str] = []
    with Session(engine) as platform:
        company = Company(name="people race probe", timezone="UTC")
        platform.add(company)
        platform.commit()
        company_id = company.id

    def session() -> Session:
        """A new session for the company: one per simulated request."""
        db = Session(engine)
        set_company(db, company_id)
        return db

    # An owner, who is above everyone, so every request passes the permission checks and
    # only the races decide the outcome.
    with session() as db:
        home = Department(name="Office")
        db.add(home)
        db.flush()
        roles = create_starting_roles(db, Actor.system())
        owner = User(
            email="owner@people-race.example.com", display_name="owner", department_id=home.id
        )
        db.add(owner)
        db.flush()
        assign_role(db, Actor.system(), user_id=owner.id, role=roles["owner"], scope_type="company")
        db.commit()
        owner_id, home_id = owner.id, home.id

    def together(*requests: Callable[[Session, User], str]) -> list[str]:
        """Run the requests at the same moment, each in its own thread and session, as the
        owner; return each one's outcome ("ok", "refused", or the error)."""
        start = threading.Barrier(len(requests))
        outcomes: list[str] = ["not run"] * len(requests)

        def run(index: int, request: Callable[[Session, User], str]) -> None:
            with session() as db:
                acting = db.get(User, owner_id)
                if acting is None:  # made above, in this company
                    outcomes[index] = "error: the owner is missing"
                    return
                start.wait()
                try:
                    outcomes[index] = request(db, acting)
                except service.Conflict:
                    outcomes[index] = "refused"
                except Exception as error:  # a 500 in the app: reported by the caller
                    outcomes[index] = f"error: {error!r}"[:300]

        threads = [threading.Thread(target=run, args=pair) for pair in enumerate(requests)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        return outcomes

    def new_person(name: str) -> uuid.UUID:
        """Someone in the owner's department, committed, for one race."""
        with session() as db:
            made = User(
                email=f"{name}@people-race.example.com", display_name=name, department_id=home_id
            )
            db.add(made)
            db.commit()
            return made.id

    for number in range(1, 6):
        # 1. The same email twice.
        def create(db: Session, acting: User, number: int = number) -> str:
            body = UserCreate(
                display_name="twin",
                email=f"twin-{number}@people-race.example.com",
                department_id=home_id,
            )
            people.create_person(db, acting, body)
            return "ok"

        outcomes = together(create, create)
        if sorted(outcomes) != ["ok", "refused"]:
            problems.append(f"two accounts with one email, round {number}: {outcomes}")

        # 2. Deactivate someone while putting them on a team.
        with session() as db:
            team = Team(department_id=home_id, name=f"Race team {number}")
            db.add(team)
            db.commit()
            team_id = team.id
        joiner_id = new_person(f"joiner-{number}")

        def deactivate(db: Session, acting: User, person_id: uuid.UUID = joiner_id) -> str:
            # The joiner holds no admin-level permission, so no password re-entry is
            # needed: an empty session (never re-entered) is enough.
            people.deactivate(db, acting, person_id, session=UserSession())
            return "ok"

        def join(
            db: Session,
            acting: User,
            team_id: uuid.UUID = team_id,
            person_id: uuid.UUID = joiner_id,
        ) -> str:
            service.add_member(db, acting, team_id, person_id)
            return "ok"

        outcomes = together(deactivate, join)
        # Both may succeed, if the join went first: deactivating keeps team memberships
        # for history. What must never happen is a join AFTER the deactivation, so the
        # order of the two audit entries (their place in the company's chain) decides.
        with session() as db:
            order = {
                action: seq
                for action, seq in db.execute(
                    select(AuditEvent.action, AuditEvent.seq).where(
                        AuditEvent.chain_id == company_id,
                        AuditEvent.action.in_(["user.deactivated", "team_member.added"]),
                        or_(
                            AuditEvent.target_id == joiner_id,
                            AuditEvent.target_id == team_id,
                        ),
                    )
                )
            }
        joined_late = (
            "user.deactivated" in order
            and "team_member.added" in order
            and order["team_member.added"] > order["user.deactivated"]
        )
        if any(outcome.startswith("error") for outcome in outcomes) or joined_late:
            problems.append(
                f"deactivation and joining a team at once, round {number}: {outcomes}, "
                f"joined after deactivation={joined_late}"
            )

        # 3. Move someone into a department while it is archived.
        with session() as db:
            target = Department(name=f"Race department {number}")
            db.add(target)
            db.commit()
            target_id = target.id
        mover_id = new_person(f"mover-{number}")

        def move(
            db: Session,
            acting: User,
            mover_id: uuid.UUID = mover_id,
            target_id: uuid.UUID = target_id,
        ) -> str:
            people.change_person(db, acting, mover_id, UserUpdate(department_id=target_id))
            return "ok"

        def archive(db: Session, acting: User, target_id: uuid.UUID = target_id) -> str:
            service.archive_department(db, acting, target_id)
            return "ok"

        outcomes = together(move, archive)
        with session() as db:
            moved = db.get(User, mover_id)
            archived = db.get(Department, target_id)
            broken = (
                moved is not None
                and archived is not None
                and moved.department_id == target_id
                and archived.archived_at is not None
            )
        if any(outcome.startswith("error") for outcome in outcomes) or broken:
            problems.append(
                f"moving into a department while it is archived, round {number}: {outcomes}"
            )
        if problems:
            break  # one failing round is enough to show the problem
    return problems


# MySQL's error numbers for a missing right: on a table (1142), on a column (1143), on
# the database (1044), and for an action needing a special right (1227). A refusal for any
# other reason (a typo in the SQL, say) would prove nothing, so it counts as a problem.
_NO_RIGHT = {1044, 1142, 1143, 1227}


def _grant_problems(app_url: str) -> list[str]:
    """What the application user can do that it must not, or cannot that it must.

    Each statement runs on its own connection that commits at once (structure changes
    commit anyway in MySQL) and must be refused for a missing right. Then every table
    the app uses must be readable.
    """
    from app.db.grants import APP_RIGHTS

    must_be_refused = [
        # The structure: a break-in through the API cannot create, change, or drop tables.
        "CREATE TABLE grant_probe (id INT)",
        "ALTER TABLE users ADD COLUMN grant_probe INT",
        "CREATE INDEX grant_probe ON users (display_name)",
        "TRUNCATE TABLE sessions",
        "DROP TABLE shifts",
        # The audit log: entries and heads cannot be changed or removed (audit-log.md).
        "UPDATE audit_events SET action = action",
        "DELETE FROM audit_events",
        "DELETE FROM audit_chain_heads",
        # Security events are added and removed after a year, never changed.
        "UPDATE security_events SET occurred_at = occurred_at",
        "UPDATE platform_security_events SET occurred_at = occurred_at",
        # Nothing outside its own database: not MySQL's own users and rights.
        "SELECT user FROM mysql.user",
        # It cannot give itself (or anyone) more rights.
        "GRANT DELETE ON audit_events TO CURRENT_USER()",
        "CREATE USER grant_probe IDENTIFIED BY 'grant-probe-password'",
    ]
    problems = []
    engine = create_engine(app_url, isolation_level="AUTOCOMMIT")
    try:
        for sql in must_be_refused:
            with engine.connect() as connection:
                try:
                    connection.execute(text(sql))
                except DBAPIError as error:
                    code = error.orig.args[0] if error.orig is not None else None
                    if code not in _NO_RIGHT:
                        problems.append(f"application user: {sql!r} failed otherwise: {error.orig}")
                    continue
                problems.append(f"the application user was allowed: {sql}")
        with engine.connect() as connection:
            for table in APP_RIGHTS:
                try:
                    # The names come from APP_RIGHTS in the code, never from input.
                    connection.execute(text(f"SELECT * FROM `{table}` LIMIT 0"))  # noqa: S608
                except DBAPIError as error:
                    problems.append(f"the application user cannot read {table}: {error.orig}")
    finally:
        engine.dispose()
    return problems


def _existing_company_problems(url: str, config: Config) -> list[str]:
    """A company made before announcements can post after the upgrade; return what failed.

    Migration 0014 gives announcement.create to the Owner, Administrator, and Manager
    starting roles of companies that already exist (review of #157). This starts from the
    database as it was just before 0014, adds a company there with its four starting roles
    and one role of its own (plain SQL, as the app of that time had no announcements),
    upgrades to the newest migration, and checks:
    1. exactly those three starting roles now grant it; Employee and the company's own
       role do not;
    2. a manager of that company now holds it, through the app's own permission check.
    main() has upgraded to 0013 before calling this; this upgrades the rest of the way.
    """
    import uuid
    from datetime import UTC, datetime

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.authz.check import effective_permissions
    from app.authz.models import Role
    from app.authz.roles import assign_role
    from app.core.config import get_settings
    from app.modules.org.models import Department, User
    from app.tenancy.context import set_company

    # Giving the manager a role below writes a signed audit entry (as in _race_problems).
    os.environ.setdefault("AUDIT_SIGNING_KEY", secrets.token_urlsafe(32))
    get_settings.cache_clear()

    company_id = uuid.uuid4()
    now = datetime.now(UTC).replace(tzinfo=None)
    engine = create_engine(url)
    try:
        # 1. The company as it was made before 0014: four starting roles and one of its own.
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO companies (id, name, timezone, created_at, updated_at) "
                    "VALUES (:id, 'existing company probe', 'UTC', :now, :now)"
                ),
                {"id": company_id.bytes, "now": now},
            )
            for built_in, name in (
                ("owner", "Owner"),
                ("administrator", "Administrator"),
                ("manager", "Manager"),
                ("employee", "Employee"),
                (None, "Front desk"),
            ):
                connection.execute(
                    text(
                        "INSERT INTO roles (id, company_id, name, built_in, created_at, updated_at)"
                        " VALUES (:id, :company, :name, :built_in, :now, :now)"
                    ),
                    {
                        "id": uuid.uuid4().bytes,
                        "company": company_id.bytes,
                        "name": name,
                        "built_in": built_in,
                        "now": now,
                    },
                )
        # 2. The upgrade, as on a server that already has companies.
        command.upgrade(config, "head")
        # 3. Which of the company's roles grant it now.
        with engine.connect() as connection:
            granted = connection.execute(
                text(
                    "SELECT r.name FROM roles r JOIN role_permissions rp ON rp.role_id = r.id "
                    "WHERE r.company_id = :company AND rp.permission_code = 'announcement.create'"
                ),
                {"company": company_id.bytes},
            ).scalars()
            names = sorted(granted)
        problems = []
        if names != ["Administrator", "Manager", "Owner"]:
            problems.append(f"after the upgrade announcement.create is granted by {names}")
        # 4. A manager of the company, through the app's own check.
        with Session(engine) as db:
            set_company(db, company_id)
            department = Department(name="Kitchen")
            db.add(department)
            db.flush()
            manager = User(
                email="manager@existing.example.com",
                display_name="manager",
                department_id=department.id,
            )
            db.add(manager)
            db.flush()
            role = db.scalars(select(Role).where(Role.built_in == "manager")).one()
            assign_role(
                db,
                Actor.system(),
                user_id=manager.id,
                role=role,
                scope_type="department",
                scope_id=department.id,
            )
            db.commit()
            if "announcement.create" not in effective_permissions(db, manager):
                problems.append("a manager of an existing company cannot post after the upgrade")
        return problems
    finally:
        engine.dispose()


def main() -> int:
    config = Config("alembic.ini")
    heads = ScriptDirectory.from_config(config).get_heads()
    if len(heads) != 1:
        print(f"expected one migration head, found {len(heads)}: {', '.join(heads)}")
        return 1

    container = None
    url = os.environ.get("MIGRATION_CHECK_DATABASE_URL", "")
    # With MIGRATION_CHECK_DATABASE_URL, one user does both jobs.
    app_url = url
    if not url:
        container, url, app_url = _start_mysql()
    try:
        _wait_until_ready(url)
        # migrations/env.py reads the URLs from the app settings: each address goes in its
        # URL setting and each password in its own, the same split the app uses. Setting
        # them here also overrides whatever the developer's .env says.
        for prefix, each in (("", app_url), ("MIGRATIONS_", url)):
            parsed = make_url(each)
            os.environ[f"{prefix}DATABASE_URL"] = parsed.set(password=None).render_as_string()
            os.environ[f"{prefix}DATABASE_PASSWORD"] = parsed.password or ""
        from app.core.config import get_settings

        get_settings.cache_clear()
        # Up to just before announcements, then an existing company is upgraded the rest
        # of the way (the function says what it checks).
        command.upgrade(config, "0013")
        upgrade_problems = _existing_company_problems(url, config)
        # The race checks commit rows, so they run before the downgrade removes everything.
        # They run as the application user, like the app.
        race_problems = _race_problems(app_url)
        command.downgrade(config, "base")
        command.upgrade(config, "head")
        differences = _differences_from_models(url)
        rule_problems = _database_rule_problems(url) + upgrade_problems + race_problems
        # Last, as a refused change that got through could leave the database broken.
        if app_url != url:
            rule_problems += _grant_problems(app_url)
        else:
            print("one database user given: the application user's rights are not checked")
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
        "models match; database rules and the application user's rights hold"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
