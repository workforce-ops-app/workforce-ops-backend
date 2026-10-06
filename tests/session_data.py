"""Shared setup for the sign-in tests: the real app on an in-memory database.

Two companies, each with a department and people in every state sign-in cares about
(able to sign in, no password yet, deactivated, locked). Requests go to
https://testserver, because the session cookie is Secure and the test client, like a
browser, only sends it back over HTTPS.
"""

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.audit.models import AuditChainHead, AuditEvent
from app.auth import sessions
from app.auth.models import UserSession
from app.auth.passwords import hash_password
from app.authz.models import Permission, Role, RoleAssignment, RolePermission
from app.core.config import Settings
from app.db.base import Base, utcnow
from app.db.session import get_session
from app.main import create_app
from app.modules.org.models import Company, Department, Team, TeamMember, User
from app.tenancy.context import set_company
from tests.audit_data import TEST_KEY, use_key
from tests.conftest import TEST_CSRF_KEY

PASSWORD = "correct horse battery staple"

# The address of the test app. Clients send it as their Origin, as a browser on our own
# pages would (app/auth/csrf.py).
BASE_URL = "https://testserver"
OTHER_PASSWORD = "a different long passphrase"

TABLES = [
    Company.__table__,
    Department.__table__,
    Team.__table__,
    User.__table__,
    TeamMember.__table__,
    UserSession.__table__,
    AuditChainHead.__table__,
    AuditEvent.__table__,
    Permission.__table__,
    Role.__table__,
    RolePermission.__table__,
    RoleAssignment.__table__,
]


@dataclass
class SignInSetup:
    """The database, the app's client, and the people's IDs by name."""

    engine: Engine
    client: TestClient
    company_a: uuid.UUID
    company_b: uuid.UUID
    people: dict[str, uuid.UUID]

    def new_client(self) -> TestClient:
        """Another browser: its own cookies, the same app."""
        return TestClient(self.client.app, base_url=BASE_URL, headers={"Origin": BASE_URL})

    def sign_in(self, client: TestClient, email: str, password: str = PASSWORD) -> int:
        """Sign in on a client; on success it sends the CSRF token from then on, as
        js/api/client.js does."""
        response = client.post("/api/sessions", json={"email": email, "password": password})
        if response.status_code == 201:
            client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        return response.status_code

    def session_for(self, company_id: uuid.UUID | None) -> Session:
        session = Session(self.engine)
        if company_id is not None:
            set_company(session, company_id)
        return session


def _person(company: Company, department: Department, name: str, **extra: object) -> User:
    return User(
        company_id=company.id,
        department_id=department.id,
        email=f"{name}@{company.name.split()[0].lower()}.example",
        display_name=name.title(),
        **extra,
    )


@pytest.fixture
def signin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[SignInSetup]:
    use_key(monkeypatch, tmp_path, TEST_KEY)
    # No minimum time for failed sign-ins here, so the tests run fast; one security test
    # puts it back to check it.
    monkeypatch.setattr(sessions, "FAILED_SIGN_IN_SECONDS", 0.0)
    # One in-memory database shared by every connection and thread (the test client runs
    # endpoints in worker threads).
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(engine, tables=TABLES)

    people: dict[str, uuid.UUID] = {}
    hashed = hash_password(PASSWORD)
    with Session(engine) as platform:
        a = Company(name="Northwind Cafe", timezone="America/Chicago")
        b = Company(name="Summit Outfitters", timezone="America/Denver")
        platform.add_all([a, b])
        platform.commit()
        ids = a.id, b.id
    for company_id in ids:
        with Session(engine) as session:
            set_company(session, company_id)
            company = session.get(Company, company_id)
            assert company is not None
            kitchen = Department(name="Kitchen")
            session.add(kitchen)
            session.flush()
            rows = {
                "ana": _person(company, kitchen, "ana", password_hash=hashed),
                "newbie": _person(company, kitchen, "newbie"),  # no password yet
                "gone": _person(
                    company, kitchen, "gone", password_hash=hashed, deactivated_at=utcnow()
                ),
                "locked": _person(
                    company,
                    kitchen,
                    "locked",
                    password_hash=hashed,
                    locked_until=utcnow() + timedelta(minutes=15),
                ),
            }
            session.add_all(rows.values())
            session.commit()
            prefix = "a" if company_id == ids[0] else "b"
            people.update({f"{prefix}_{name}": row.id for name, row in rows.items()})

    # The real app, with its database session coming from this engine.
    app = create_app(
        Settings(app_env="test", database_url="sqlite://", csrf_key=TEST_CSRF_KEY)  # type: ignore[arg-type]
    )

    def test_session() -> Iterator[Session]:
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = test_session
    client = TestClient(app, base_url=BASE_URL, headers={"Origin": BASE_URL})
    yield SignInSetup(engine, client, *ids, people)
    engine.dispose()


def email(setup: SignInSetup, key: str) -> str:
    """A person's email by their key, e.g. "a_ana" -> "ana@northwind.example"."""
    with setup.session_for(setup.company_a if key.startswith("a_") else setup.company_b) as s:
        user = s.get(User, setup.people[key])
        assert user is not None
        return user.email
