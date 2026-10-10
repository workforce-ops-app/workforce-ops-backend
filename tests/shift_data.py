"""Shared setup for the shift tests: the real app, two companies, people with real roles.

Company A ("Northwind", America/Chicago):
    departments Kitchen and Front (Front works in America/New_York); team Weekend Crew in Kitchen
    owner   Owner (company)
    chef    Manager of Kitchen      (home Kitchen)
    lead    Manager of Weekend Crew (home Front)
    ana     Employee of Kitchen     (home Kitchen)
    cara    Employee of Kitchen     (home Kitchen)
    ben     Employee of Front       (home Front, on the Weekend Crew)
    dana    Employee of Front       (home Front)
    newbie  Employee of Kitchen, no password yet (invited)
    gone    Employee of Kitchen, deactivated
Company B ("Summit"): b_chef (Manager of its Kitchen) and b_ana (Employee of its Kitchen).

Everyone signs in through the API, so every request goes through the session, the CSRF
check, the company filter, and authorize(), exactly as in the application.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.audit import Actor
from app.auth import passwords, sessions
from app.auth.passwords import hash_password
from app.authz.roles import assign_role, create_starting_roles
from app.core.config import Settings
from app.db.base import Base, utcnow
from app.db.registry import import_all_models
from app.db.session import get_session
from app.main import create_app
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.tenancy.context import set_company
from tests.audit_data import TEST_KEY, use_key
from tests.conftest import TEST_CSRF_KEY

PASSWORD = "correct horse battery staple"
BASE_URL = "https://testserver"


def soon(days: int = 1, hour: int = 14) -> datetime:
    """A moment some days ahead at a whole UTC hour (always in the future)."""
    base = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    return base.replace(hour=hour) + timedelta(days=days)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


@dataclass
class ShiftSetup:
    engine: Engine
    app: object
    company_a: uuid.UUID
    company_b: uuid.UUID
    ids: dict[str, uuid.UUID]
    _clients: dict[str, TestClient] = field(default_factory=dict)

    def browser(self, name: str) -> TestClient:
        """A browser where this person is signed in (keeps the CSRF token, as our pages do)."""
        if name not in self._clients:
            client = TestClient(self.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]
            email = f"{name}@{'summit' if name.startswith('b_') else 'northwind'}.example"
            response = client.post("/api/sessions", json={"email": email, "password": PASSWORD})
            assert response.status_code == 201, (name, response.text)
            client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
            self._clients[name] = client
        return self._clients[name]

    def new_shift(self, who: str = "chef", **fields: object) -> dict:
        """Create a shift through the API (Kitchen, tomorrow 14:00 to 20:00 UTC by default)."""
        body = {
            "department_id": str(self.ids["kitchen"]),
            "starts_at": iso(soon()),
            "ends_at": iso(soon() + timedelta(hours=6)),
        } | {k: (str(v) if isinstance(v, uuid.UUID) else v) for k, v in fields.items()}
        response = self.browser(who).post("/api/shifts", json=body)
        assert response.status_code == 201, response.text
        return response.json()

    def db(self, company_id: uuid.UUID | None = None) -> Session:
        session = Session(self.engine)
        set_company(session, company_id or self.company_a)
        return session


def _company(db: Session, prefix: str, domain: str, people: dict, front_zone: str | None) -> dict:
    ids: dict[str, uuid.UUID] = {}
    kitchen, front = Department(name="Kitchen"), Department(name="Front", timezone=front_zone)
    db.add_all([kitchen, front])
    db.flush()
    crew = Team(name="Weekend Crew", department_id=kitchen.id)
    db.add(crew)
    db.flush()
    ids |= {f"{prefix}kitchen": kitchen.id, f"{prefix}front": front.id, f"{prefix}crew": crew.id}
    places = {"kitchen": kitchen.id, "front": front.id, "crew": crew.id, None: None}
    roles = create_starting_roles(db, Actor.system())
    hashed = hash_password(PASSWORD)
    for name, (home, role, scope_type, scope, extra) in people.items():
        person = User(
            email=f"{prefix}{name}@{domain}.example",
            display_name=name.title(),
            department_id=places[home],
            **({"password_hash": hashed} | extra),
        )
        db.add(person)
        db.flush()
        ids[f"{prefix}{name}"] = person.id
        assign_role(
            db,
            Actor.system(),
            user_id=person.id,
            role=roles[role],
            scope_type=scope_type,
            scope_id=places[scope],
        )
    return ids


@pytest.fixture
def shifts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[ShiftSetup]:
    use_key(monkeypatch, tmp_path, TEST_KEY)
    # Cheap password hashing and no minimum wait, so signing everyone in is fast.
    monkeypatch.setattr(
        passwords, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    monkeypatch.setattr(sessions, "FAILED_SIGN_IN_SECONDS", 0.0)
    import_all_models()
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine)

    with Session(engine) as platform:
        a = Company(name="Northwind", timezone="America/Chicago")
        b = Company(name="Summit", timezone="America/Denver")
        platform.add_all([a, b])
        platform.commit()
        company_ids = a.id, b.id

    ids: dict[str, uuid.UUID] = {}
    with Session(engine) as db:
        set_company(db, company_ids[0])
        ids |= _company(
            db,
            "",
            "northwind",
            {
                "owner": ("front", "owner", "company", None, {}),
                "chef": ("kitchen", "manager", "department", "kitchen", {}),
                "lead": ("front", "manager", "team", "crew", {}),
                "ana": ("kitchen", "employee", "department", "kitchen", {}),
                "cara": ("kitchen", "employee", "department", "kitchen", {}),
                "ben": ("front", "employee", "department", "front", {}),
                "dana": ("front", "employee", "department", "front", {}),
                "newbie": ("kitchen", "employee", "department", "kitchen", {"password_hash": None}),
                "gone": (
                    "kitchen",
                    "employee",
                    "department",
                    "kitchen",
                    {"deactivated_at": utcnow()},
                ),
            },
            front_zone="America/New_York",
        )
        db.add(TeamMember(team_id=ids["crew"], user_id=ids["ben"]))
        db.commit()
    with Session(engine) as db:
        set_company(db, company_ids[1])
        ids |= _company(
            db,
            "b_",
            "summit",
            {
                "chef": ("kitchen", "manager", "department", "kitchen", {}),
                "ana": ("kitchen", "employee", "department", "kitchen", {}),
            },
            front_zone=None,
        )
        db.commit()

    app = create_app(Settings(app_env="test", database_url="sqlite://", csrf_key=TEST_CSRF_KEY))  # type: ignore[arg-type]

    def test_session() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = test_session
    yield ShiftSetup(engine, app, *company_ids, ids)
    engine.dispose()
