"""Demo data: two companies with their departments, teams, and people.

    python -m scripts.seed_demo

For local work, the tests, and the demos (decision 0031, docs/features/organization.md).
The two companies are built alike on purpose (same department and team names, the same
kinds of people), so a leak from one company into the other is obvious in tests and demos.

- Gives the same result on every run: a company that already exists is left alone, so
  running the script twice changes nothing.
- Creates each company all or nothing (one transaction): if a step fails, nothing of that
  company is kept, so the next run builds it again from the start.
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
gets two weeks of shifts (SD1): the current week and the next, counted from Monday in the
company's time zone, so the demo always has a schedule to show. The shifts are added once:
a company that already has shifts is left alone. They wait until every person they go to
has a password, because the application never assigns a shift to someone who has not set
up their account. Reporting lines follow after the midterm (Z2).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import Engine, create_engine, func, select
from sqlalchemy.orm import Session

from app.audit import Actor, record
from app.auth.passwords import PasswordRejected, check_password, hash_password
from app.authz.roles import assign_role, create_starting_roles
from app.core.config import get_settings
from app.db.base import utcnow
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.modules.schedules import repository as shift_repository
from app.modules.schedules.models import Shift
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


# One week of shifts, used for both demo weeks. It covers what the demo and the security
# tests need: shifts in two departments, open shifts, a note, an event, and people with
# several shifts. No person ever has two shifts at the same time, and none is longer than
# 12 hours: the same rules the application enforces.
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
    ShiftPlan(5, "Kitchen", "09:00", "17:00", KITCHEN_B, "Prep line"),
    ShiftPlan(5, "Kitchen", "15:00", "23:00", KITCHEN_A, "Grill"),
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

# How many weeks of shifts each company gets: the current week and the next.
DEMO_WEEKS = 2


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
    # their role for the whole company; managers for their home department. Created by
    # the system (platform code), and audited like any role change.
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


def week_start(timezone: str, today: date | None = None) -> date:
    """The Monday of the current week in a time zone (a company's week starts on its own
    Monday, not on the server's)."""
    if today is None:
        today = datetime.now(ZoneInfo(timezone)).date()
    return today - timedelta(days=today.weekday())


def local_to_utc(day: date, clock: str, timezone: str) -> datetime:
    """A local wall-clock time on a day, as the UTC moment the database stores (without a
    zone, like every stored moment). ZoneInfo applies that day's daylight-saving rule."""
    hours, minutes = (int(part) for part in clock.split(":"))
    local = datetime.combine(day, time(hours, minutes), tzinfo=ZoneInfo(timezone))
    return local.astimezone(UTC).replace(tzinfo=None)


def seed_shifts(engine: Engine, plan: CompanyPlan, monday: date | None = None) -> int | None:
    """Give a company two weeks of shifts, unless it already has some. Returns how many
    shifts were added: 0 if it had shifts already, None if they have to wait because
    someone they go to has no password yet.

    The shifts start on the current week's Monday, so on most days some of them have
    already ended. The API refuses to create an ended shift, so that nobody can write the
    past in after the fact; demo data is the one documented exception (schedules.md,
    "Demo data"). It is added by the operator, not by a user, and each audit entry says
    truthfully that the system added the shift today.

    monday is the first week's Monday; by default the current week's, in the company's
    time zone. All or nothing, like the company itself: every shift and its audit entry
    are saved in one transaction. Shifts are added by the system (platform code), not by a
    person, and each is written to the audit log as "shift.created", the action the API
    records when a manager creates one.
    """
    # Find the company, as platform code (no company on the session).
    with Session(engine) as platform:
        company_id = platform.scalars(select(Company.id).where(Company.name == plan.name)).one()

    # One transaction for all of this company's shifts (see seed_company for how the
    # connection and session work together).
    with engine.begin() as connection, Session(connection) as session:
        set_company(session, company_id)
        # Already has shifts (an earlier run): leave them as they are. Counting a column of
        # the model lets the company filter apply.
        if session.scalar(select(func.count(Shift.company_id))):
            return 0

        departments = {d.name: d for d in session.scalars(select(Department))}
        people = {u.display_name: u for u in session.scalars(select(User))}

        # The same rule as the API: only someone who has set up their account (has a
        # password) and is not deactivated can be given a shift. Until then, add none.
        workers = {plan.people[i.worker].name for i in WEEK_PATTERN if i.worker is not None}
        for name in workers:
            if people[name].password_hash is None or people[name].deactivated_at is not None:
                return None

        first_monday = monday or week_start(plan.timezone)

        added = 0
        for week in range(DEMO_WEEKS):
            for item in WEEK_PATTERN:
                day = first_monday + timedelta(days=7 * week + item.weekday)
                department = departments[item.department]
                # The workplace zone, worked out the way the API does it: the department's
                # own, or else the company's.
                zone = shift_repository.workplace_zone(session, department)
                worker = None if item.worker is None else people[plan.people[item.worker].name]
                first_week = week == 0
                shift = Shift(
                    department_id=department.id,
                    employee_id=worker.id if worker else None,
                    starts_at=local_to_utc(day, item.start, zone),
                    ends_at=local_to_utc(day, item.end, zone),
                    timezone=zone,
                    status="scheduled" if worker else "open",
                    details=item.details,
                    notes=item.notes if first_week else None,
                    event_name=item.event_name if first_week else None,
                    event_description=item.event_description if first_week else None,
                )
                session.add(shift)
                session.flush()  # gives the shift its ID for the audit entry
                # The same entry the API writes for a new shift: IDs and times only, never
                # the text people wrote.
                record(
                    session,
                    actor=Actor.system(),
                    action="shift.created",
                    target_type="shift",
                    target_id=shift.id,
                    details={
                        "department_id": str(shift.department_id),
                        "employee_id": str(shift.employee_id) if shift.employee_id else None,
                        "starts_at": shift.starts_at.isoformat(),
                        "ends_at": shift.ends_at.isoformat(),
                    },
                )
                added += 1
        # Send everything inside the transaction; engine.begin() commits it on the way out.
        session.flush()
        return added


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


def seed(engine: Engine, demo_password: str | None = None) -> list[str]:
    """Create every demo company that does not exist yet, give accounts without a password
    the demo password if one is given, then add the shifts; one line per company."""
    # Check the demo password first, so a weak one changes nothing at all.
    if demo_password is not None:
        check_demo_password(demo_password)

    lines = []
    for plan in DEMO_COMPANIES:
        created = seed_company(engine, plan)
        state = "created" if created else "already there"

        # Passwords before shifts: shifts only go to people who have one.
        if demo_password is None:
            passwords = "no DEMO_PASSWORD, so no one can sign in"
        else:
            given = set_demo_passwords(engine, plan, demo_password)
            passwords = f"demo password set for {given} accounts"

        # Shifts last, so a company seeded before shifts existed, or before it had
        # passwords, gets them on the next run.
        added = seed_shifts(engine, plan)
        shifts = "shifts wait for passwords" if added is None else f"{added} shifts added"
        lines.append(f"{plan.name}: {state}; {passwords}; {shifts}")
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
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
