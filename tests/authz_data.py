"""Shared setup for the authorization tests: two companies with real starting roles.

Company A ("Northwind"):
    departments Kitchen and Front; team Weekend Crew (in Kitchen)
    owner      Owner (company)                  + Employee of Front
    admin      Administrator (company)          + Employee of Front
    chef       Manager of the Kitchen department + Employee of Kitchen
    lead       Manager of the Weekend Crew team  + Employee of Front
    ana        Employee of Kitchen
    ben        Employee of Front, on the Weekend Crew team
    gone       Owner (company), but deactivated
    relic      only a role that was archived
    mentor     Manager for one person only: Ben
Company B ("Summit"): owner (Owner) and ana (Employee), the same shape in miniature.

Shifts do not exist yet (SC1), so record permissions are tested on a small stand-in
record, Note, with its own scope resolver, exactly as a module will register one.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

from app.audit import Actor
from app.audit.models import AuditChainHead, AuditEvent
from app.authz.models import Permission, Role, RoleAssignment, RolePermission
from app.authz.roles import assign_role, create_starting_roles
from app.authz.scope import Scope, scope_resolver
from app.db.base import Base, utcnow
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.tenancy.context import set_company
from tests.audit_data import TEST_KEY, use_key

TABLES = [
    model.__table__
    for model in (
        Company,
        Department,
        Team,
        User,
        TeamMember,
        Permission,
        Role,
        RolePermission,
        RoleAssignment,
        AuditChainHead,
        AuditEvent,
    )
]


@dataclass
class Note:
    """A stand-in record (shifts arrive with SC1): it belongs to a department, and maybe to
    an employee, of one company."""

    company_id: uuid.UUID
    department_id: uuid.UUID
    employee_id: uuid.UUID | None


@scope_resolver(Note)
def note_scope(db: Session, note: Note) -> Scope:
    """A note belongs to its department and its employee (and their home department and
    teams), the way a shift will."""
    departments = {note.department_id}
    teams: set[uuid.UUID] = set()
    if note.employee_id is not None:
        employee = db.get(User, note.employee_id)
        if employee is not None:
            departments.add(employee.department_id)
            teams |= {t.team_id for t in db.query(TeamMember).filter_by(user_id=employee.id)}
    return Scope(frozenset(departments), frozenset(teams), note.employee_id)


@dataclass
class Org:
    engine: Engine
    company_a: uuid.UUID
    company_b: uuid.UUID
    ids: dict[str, uuid.UUID]  # people, departments, teams, and roles by name

    def session(self, company_id: uuid.UUID) -> Session:
        session = Session(self.engine)
        set_company(session, company_id)
        return session

    def a(self) -> Session:
        return self.session(self.company_a)

    def user(self, db: Session, name: str) -> User:
        found = db.get(User, self.ids[name])
        assert found is not None
        return found


def _build_company(db: Session, prefix: str, people: dict[str, tuple[str, list]]) -> dict:
    """Departments, a team, people, starting roles, and assignments in one company."""
    ids: dict[str, uuid.UUID] = {}
    kitchen, front = Department(name="Kitchen"), Department(name="Front")
    db.add_all([kitchen, front])
    db.flush()
    crew = Team(name="Weekend Crew", department_id=kitchen.id)
    db.add(crew)
    db.flush()
    ids |= {f"{prefix}kitchen": kitchen.id, f"{prefix}front": front.id, f"{prefix}crew": crew.id}
    homes = {"kitchen": kitchen.id, "front": front.id}

    roles = create_starting_roles(db, Actor.system())
    ids |= {f"{prefix}role_{name}": role.id for name, role in roles.items()}
    for name, (home, grants) in people.items():
        person = User(
            email=f"{prefix}{name}@example.com", display_name=name, department_id=homes[home]
        )
        db.add(person)
        db.flush()
        ids[f"{prefix}{name}"] = person.id
        for role_name, scope_type, scope in grants:
            # A department, the team, or a person created earlier in the list.
            places = {"kitchen": kitchen.id, "front": front.id, "crew": crew.id}
            scope_id = places.get(scope) or ids.get(f"{prefix}{scope}")
            assign_role(
                db,
                Actor.system(),
                user_id=person.id,
                role=roles[role_name],
                scope_type=scope_type,
                scope_id=scope_id,
            )
    return ids


@pytest.fixture
def org(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[Org]:
    use_key(monkeypatch, tmp_path, TEST_KEY)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=TABLES)
    with Session(engine) as platform:
        a = Company(name="Northwind", timezone="America/Chicago")
        b = Company(name="Summit", timezone="America/Denver")
        platform.add_all([a, b])
        platform.commit()
        company_ids = a.id, b.id

    ids: dict[str, uuid.UUID] = {}
    with Session(engine) as db:
        set_company(db, company_ids[0])
        ids |= _build_company(
            db,
            "",
            {
                "owner": (
                    "front",
                    [("owner", "company", None), ("employee", "department", "front")],
                ),
                "admin": (
                    "front",
                    [("administrator", "company", None), ("employee", "department", "front")],
                ),
                "chef": (
                    "kitchen",
                    [("manager", "department", "kitchen"), ("employee", "department", "kitchen")],
                ),
                "lead": (
                    "front",
                    [("manager", "team", "crew"), ("employee", "department", "front")],
                ),
                "ana": ("kitchen", [("employee", "department", "kitchen")]),
                "ben": ("front", [("employee", "department", "front")]),
                "mentor": ("kitchen", [("manager", "employee", "ben")]),
                "gone": ("front", [("owner", "company", None)]),
                "relic": ("front", []),
            },
        )
        # Ben is on the Weekend Crew (a Kitchen team) though his home is Front.
        db.add(TeamMember(team_id=ids["crew"], user_id=ids["ben"]))
        # Gone is deactivated; relic holds only a role that is then archived.
        db.get(User, ids["gone"]).deactivated_at = utcnow()  # type: ignore[union-attr]
        old = Role(name="Old Scheduler")
        db.add(old)
        db.flush()
        db.add(RolePermission(role_id=old.id, permission_code="schedule.edit"))
        db.add(RoleAssignment(user_id=ids["relic"], role_id=old.id, scope_type="company"))
        old.archived_at = utcnow()
        db.commit()
    with Session(engine) as db:
        set_company(db, company_ids[1])
        ids |= _build_company(
            db,
            "b_",
            {
                "owner": ("front", [("owner", "company", None)]),
                "ana": ("kitchen", [("employee", "department", "kitchen")]),
            },
        )
        db.commit()
    yield Org(engine, *company_ids, ids)
    engine.dispose()
