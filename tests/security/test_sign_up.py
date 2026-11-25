"""Company sign-up (docs/features/organization.md, company sign-up: security tests).

What an attacker would try against an open form: flooding it, taking an existing email,
setting fields the sign-up decides, using it while signed in or from another site, and
making it fail half-way to leave a broken company behind. Each must create nothing.
"""

import json
import uuid

import pytest
from sqlalchemy import select, text

from app.audit.models import PLATFORM_CHAIN_ID, AuditEvent
from app.authz.models import Role, RoleAssignment
from app.modules.org.models import Company, Department, User
from app.modules.sign_up import service
from app.modules.sign_up.schemas import SignUpRequest
from app.tenancy.filter import cross_company_read
from tests.session_data import SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here


@pytest.fixture(autouse=True)
def one_window(signin: SignInSetup) -> None:
    """Every request in a test falls in the same window of every rate limit (#207).

    The limits count in fixed windows on the clock: a minute for sign-in attempts, an hour
    for sign-ups. Real sign-ins take about half a second each (Argon2id), so a test with
    many of them could cross into the next window, where every count starts again, and
    see 401 where it expects 429. Half a minute into some minute, and so also partway
    into some hour, leaves Retry-After above zero for both.
    """
    limits = signin.client.app.state.limits  # type: ignore[attr-defined]
    for limit in (
        limits.sign_in_per_address,
        limits.sign_up_per_address,
        limits.requests_per_session,
    ):
        limit.clock = lambda: 6_000_030.0


URL = "/api/sign-up"
STRONG = "lanterns drift over quiet waters"


def form(**changes: str) -> dict[str, str]:
    """A valid sign-up form, with some fields changed."""
    return {
        "company_name": "Harbor Bakery",
        "timezone": "America/New_York",
        "display_name": "Rosa Park",
        "email": "rosa@harbor.example",
        "password": STRONG,
        **changes,
    }


def counts(setup: SignInSetup) -> dict[str, object]:
    """Everything a sign-up creates, counted across every company, and both chains'
    heads: a refused sign-up must leave all of it exactly as it was. Plain SQL on a raw
    connection, below the company filter, because this check must see every company."""
    tables = [
        "companies",
        "company_locks",
        "departments",
        "users",
        "roles",
        "role_assignments",
        "sessions",
        "audit_events",
    ]
    with setup.engine.connect() as connection:
        found: dict[str, object] = {
            table: connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()  # noqa: S608 (fixed names)
            for table in tables
        }
        heads = connection.execute(
            text("SELECT chain_id, last_seq FROM audit_chain_heads ORDER BY last_seq")
        ).all()
    found["heads"] = sorted((str(chain), seq) for chain, seq in heads)
    return found


def test_a_sign_up_creates_the_company_and_signs_the_owner_in(signin: SignInSetup) -> None:
    answer = signin.client.post(URL, json=form())
    assert answer.status_code == 201, answer.text
    body = answer.json()
    assert body["company"]["name"] == "Harbor Bakery"
    assert body["company"]["timezone"] == "America/New_York"
    assert body["user"]["email"] == "rosa@harbor.example"
    assert "company.transfer_ownership" in body["permissions"]  # Owner for the company
    assert body["csrf_token"]
    assert "__Host-session" in answer.headers["set-cookie"]

    # Signed in: the next request works with the cookie, as the new owner.
    current = signin.client.get("/api/sessions/current")
    assert current.status_code == 200 and current.json()["user"]["display_name"] == "Rosa Park"

    company_id = body["company"]["id"]
    with signin.session_for(None) as db:
        company = db.scalars(
            cross_company_read(select(Company).where(Company.name == "Harbor Bakery"))
        ).one()
        assert str(company.id) == company_id
    with signin.session_for(uuid.UUID(company_id)) as db:
        assert [d.name for d in db.scalars(select(Department))] == ["General"]
        assert sorted(r.built_in or "" for r in db.scalars(select(Role))) == [
            "administrator",
            "employee",
            "manager",
            "owner",
        ]
        held = db.execute(
            select(Role.built_in, RoleAssignment.scope_type).join(
                Role, Role.id == RoleAssignment.role_id
            )
        ).all()
        assert sorted(held) == [("employee", "department"), ("owner", "company")]
        # The company's own chain (its ID is the company's), in order.
        actions = list(
            db.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.chain_id == uuid.UUID(company_id))
                .order_by(AuditEvent.seq)
            )
        )
    # In the order docs/features/organization.md lists them.
    assert actions == [
        "company.created",
        "department.created",
        *["role.created"] * 4,
        "user.created",
        *["role_assignment.added"] * 2,
        "auth.signed_in",
    ]

    # The platform's own record names only the company.
    with signin.session_for(None) as db:
        platform = db.execute(
            select(AuditEvent.action, AuditEvent.actor_type, AuditEvent.details).where(
                AuditEvent.chain_id == PLATFORM_CHAIN_ID
            )
        ).all()
    assert platform == [("platform.company_signed_up", "system", {"company_id": company_id})]


def test_the_new_owner_sees_only_the_new_company(signin: SignInSetup) -> None:
    assert signin.client.post(URL, json=form()).status_code == 201
    departments = signin.client.get("/api/departments").json()["items"]
    assert [d["name"] for d in departments] == ["General"]


def test_a_taken_email_in_any_company_and_case_creates_nothing(signin: SignInSetup) -> None:
    before = counts(signin)
    taken = email(signin, "b_ana").upper()  # another company's person, other case
    answer = signin.client.post(URL, json=form(email=taken))
    assert answer.status_code == 409
    assert answer.json()["detail"] == "This email can't be used."
    assert "set-cookie" not in answer.headers
    assert counts(signin) == before


def test_a_weak_password_is_refused_before_the_email_is_tried(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = counts(signin)
    tried: list[str] = []
    monkeypatch.setattr(service, "_create", lambda *args: tried.append("create"))
    for weak in (
        "too short",
        "harbor bakery opens at six every day",
        "rosa park walks home slowly",
    ):
        answer = signin.client.post(URL, json=form(email=email(signin, "a_ana"), password=weak))
        assert answer.status_code == 422, weak
    assert tried == []  # never got as far as the email
    assert counts(signin) == before


@pytest.mark.parametrize(
    "extra", [{"company_id": "x"}, {"role": "owner"}, {"password_hash": "$argon2id$x"}]
)
def test_fields_the_sign_up_decides_are_refused(signin: SignInSetup, extra: dict[str, str]) -> None:
    before = counts(signin)
    assert signin.client.post(URL, json={**form(), **extra}).status_code == 422
    assert counts(signin) == before


def test_an_unknown_time_zone_is_refused(signin: SignInSetup) -> None:
    assert signin.client.post(URL, json=form(timezone="Mars/Olympus")).status_code == 422


def test_a_signed_in_person_cannot_sign_up_another_company(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    before = counts(signin)
    answer = signin.client.post(URL, json=form())
    assert answer.status_code == 409
    assert counts(signin) == before


def test_another_sites_page_cannot_sign_up(signin: SignInSetup) -> None:
    before = counts(signin)
    answer = signin.client.post(URL, json=form(), headers={"Origin": "https://evil.example"})
    assert answer.status_code == 403
    assert counts(signin) == before


def test_the_sixth_sign_up_in_an_hour_from_one_address_is_refused(signin: SignInSetup) -> None:
    for number in range(5):
        # Failures count too: four refused (weak password), one made.
        password = STRONG if number == 0 else "short"
        signin.client.cookies.clear()
        answer = signin.client.post(URL, json=form(password=password))
        assert answer.status_code in (201, 422)
    signin.client.cookies.clear()
    before = counts(signin)
    refused = signin.client.post(URL, json=form(email="other@harbor.example"))
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) > 0
    assert counts(signin) == before


def test_the_platform_limit_refuses_and_creates_nothing(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The fixture created two companies just now: a limit of two is already reached.
    monkeypatch.setattr(service, "PLATFORM_PER_HOUR", 2)
    before = counts(signin)
    answer = signin.client.post(URL, json=form())
    assert answer.status_code == 429
    assert counts(signin) == before


@pytest.mark.parametrize("where", ["after the owner", "in the platform entry"])
def test_a_failure_half_way_leaves_nothing_behind(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    before = counts(signin)

    class Fault(Exception):
        pass

    if where == "after the owner":

        def broken(*args: object, **kwargs: object) -> None:
            raise Fault()

        monkeypatch.setattr(service, "create_starting_roles", broken)
    else:
        real_record = service.record

        def record(session: object, **kwargs: object) -> object:
            if kwargs.get("action") == "platform.company_signed_up":
                raise Fault()
            return real_record(session, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(service, "record", record)

    with pytest.raises(Fault):
        service.sign_up(signin.engine, SignUpRequest(**form()))  # type: ignore[arg-type]
    assert counts(signin) == before


def test_the_password_is_in_no_answer_or_audit_entry(signin: SignInSetup) -> None:
    answer = signin.client.post(URL, json=form())
    assert STRONG not in answer.text
    with signin.session_for(None) as db:
        details = db.scalars(cross_company_read(select(AuditEvent.details))).all()
        hashes = db.scalars(cross_company_read(select(User.password_hash))).all()
    text = json.dumps(details)
    assert STRONG not in text
    assert all(h is None or h not in text for h in hashes)


@pytest.mark.parametrize(
    "ended",
    [
        # Past the session's maximum length, and idle past the timeout.
        "UPDATE sessions SET expires_at = :past",
        "UPDATE sessions SET last_seen_at = :past",
    ],
)
def test_an_ended_session_cookie_does_not_stop_a_sign_up(signin: SignInSetup, ended: str) -> None:
    """Review of #174: a browser that still carries an ended session's cookie can sign up.

    Looking up that session binds a database session to its company. Done on the
    request's own session, the binding stayed, and saving the new company's cookie then
    failed with a 500 after the company had been created. Now the lookup has its own.
    """
    from datetime import timedelta

    from app.db.base import utcnow

    assert signin.sign_in(signin.client, email(signin, "a_ana")) == 201
    with signin.engine.begin() as connection:
        # Written as text in the column's stored form (SQLite has no datetime type).
        past = (utcnow() - timedelta(days=2)).isoformat(sep=" ")
        connection.execute(text(ended), {"past": past})
    answer = signin.client.post(URL, json=form())
    assert answer.status_code == 201, answer.text
    assert answer.json()["user"]["email"] == "rosa@harbor.example"
    # The ended session is gone (deleted when it was found ended), the new one works.
    assert signin.client.get("/api/sessions/current").status_code == 200


def test_requests_with_invalid_fields_count_toward_the_limit(signin: SignInSetup) -> None:
    """Every sign-up request counts, fields valid or not (review of #174): five refused
    for their fields, then the sixth, a valid one, gets 429 and creates nothing."""
    for _ in range(5):
        answer = signin.client.post(URL, json=form(timezone="Not/AZone", company_name=""))
        assert answer.status_code == 422
    before = counts(signin)
    refused = signin.client.post(URL, json=form())
    assert refused.status_code == 429
    assert counts(signin) == before


def test_a_sign_up_past_its_limit_still_counts_toward_sign_in(signin: SignInSetup) -> None:
    """Both counters move even when the sign-up limit refuses (review of #174): 14 sign-in
    attempts and 6 sign-ups make 20, so the next sign-in attempt is the 21st and gets 429."""
    unknown = {"email": "nobody@nowhere.example", "password": STRONG}
    for _ in range(14):
        assert signin.client.post("/api/sessions", json=unknown).status_code == 401
    for number in range(6):
        answer = signin.client.post(URL, json=form(password="short"))
        assert answer.status_code == (429 if number == 5 else 422)
    assert signin.client.post("/api/sessions", json=unknown).status_code == 429
