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

Each person gets the role recorded below (Z1), with the starting roles; SD1 adds two
weeks of shifts. Reporting lines follow after the midterm (Z2).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from app.audit import Actor
from app.auth.passwords import PasswordRejected, check_password, hash_password
from app.authz.roles import assign_role, create_starting_roles
from app.core.config import get_settings
from app.db.base import utcnow
from app.modules.org.models import Company, Department, Team, TeamMember, User
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
    """Create every demo company that does not exist yet, and give accounts without a
    password the demo password if one is given; one line per company."""
    # Check the demo password first, so a weak one changes nothing at all.
    if demo_password is not None:
        check_demo_password(demo_password)

    lines = []
    for plan in DEMO_COMPANIES:
        created = seed_company(engine, plan)
        state = "created" if created else "already there"
        if demo_password is None:
            lines.append(f"{plan.name}: {state}; no DEMO_PASSWORD, so no one can sign in")
            continue
        given = set_demo_passwords(engine, plan, demo_password)
        lines.append(f"{plan.name}: {state}; demo password set for {given} accounts")
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
