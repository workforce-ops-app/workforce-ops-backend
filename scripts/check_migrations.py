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
   booking one person at the same moment cannot double-book them. SQLite has no row
   locks, so this too can only be tried on MySQL. They run as the application user, so
   they also show its rights are enough for the app's own locking reads.
6. The application user's rights (_grant_problems, #43): created by the same first-start
   script Docker Compose uses (docker/mysql/init/01-users.sh) and granted by the
   migrations (app/db/grants.py), it cannot change the structure, cannot change or
   remove audit entries, and can read every table the app uses.

The database is a throwaway Docker container (removed afterwards), unless
MIGRATION_CHECK_DATABASE_URL points at an empty database to use instead. That one URL
is then used for everything, and step 6 is skipped: it needs the two users.
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
            + _shift_race_problems(engine)
            + _org_race_problems(engine)
        )
    finally:
        engine.dispose()


def _reporting_line_race_problems(engine: Engine) -> list[str]:
    """Two requests changing reporting lines at the same moment; return what failed.

    add_reporting_line() locks the company first and then checks with fresh, locking
    reads (app/authz/chain.py).
    """
    import threading

    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from app.audit import Actor
    from app.authz.chain import ReportingLineError, add_reporting_line, lock_reporting_lines
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
        command.upgrade(config, "head")
        # The race checks commit rows, so they run before the downgrade removes everything.
        # They run as the application user, like the app.
        race_problems = _race_problems(app_url)
        command.downgrade(config, "base")
        command.upgrade(config, "head")
        differences = _differences_from_models(url)
        rule_problems = _database_rule_problems(url) + race_problems
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
