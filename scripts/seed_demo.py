"""Demo data: two companies with their departments, teams, and people.

    python -m scripts.seed_demo

For local work, the tests, and the demos (decision 0031, docs/features/organization.md).
The two companies are built alike on purpose (same department and team names, the same
kinds of people), so a leak from one company into the other is obvious in tests and demos.

- Gives the same result on every run: a company that already exists is left alone, so
  running the script twice changes nothing.
- Refuses to run against a production database (APP_ENV=production).
- Uses the reserved example.com and example.org email domains.
- Creates companies the only way the design allows: from a session with no company
  (platform code), then everything inside a company from a session for that company, so
  the company filter fills in and checks company_id as it does for the app.

Later slices extend it: S1 gives the accounts a demo password from an environment
variable (until then they have none and cannot sign in), Z1 gives each person the role
recorded below, and SD1 adds two weeks of shifts. Reporting lines follow after the
midterm (Z2).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
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
    """Create one demo company with everything in it. Returns False if it already exists."""
    # 1. The company itself, created by platform code: a session with no company. If a
    #    company with this name already exists, leave it as it is.
    with Session(engine) as platform:
        if platform.scalars(select(Company.id).where(Company.name == plan.name)).first():
            return False
        company = Company(name=plan.name, timezone=plan.timezone)
        platform.add(company)
        platform.commit()
        company_id = company.id

    # 2. Everything inside the company, from a session working for it: the company filter
    #    fills in company_id on every row and refuses anything for another company.
    with Session(engine) as session:
        set_company(session, company_id)

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

        # The people, each with a home department (no password yet: see S1).
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
        session.commit()
    return True


def seed(engine: Engine) -> list[str]:
    """Create every demo company that does not exist yet; one line per company."""
    lines = []
    for plan in DEMO_COMPANIES:
        created = seed_company(engine, plan)
        state = "created" if created else "already there, left unchanged"
        lines.append(f"{plan.name}: {state}")
    return lines


def main() -> int:
    """Seed the database in DATABASE_URL, unless it is production."""
    settings = get_settings()

    # Never in production: the demo data would mix with real companies.
    if settings.is_production:
        print("refusing to seed demo data: APP_ENV is production")
        return 1

    engine = create_engine(settings.sqlalchemy_url)
    try:
        for line in seed(engine):
            print(line)
    finally:
        engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
