"""Signing in and out through the API (app/modules/sessions, app/auth/sessions.py).

The attacks (guessing which emails exist, stealing or planting sessions, timeouts, and
crossing companies) are in tests/security/test_sign_in.py.
"""

import hashlib
from base64 import urlsafe_b64decode

import pytest
from sqlalchemy import select

from app.audit import Actor
from app.audit.models import AuditEvent
from app.auth import sessions
from app.auth.models import UserSession
from app.auth.sessions import COOKIE_NAME
from app.authz.roles import assign_role, create_starting_roles
from app.modules.org.models import User
from tests.session_data import PASSWORD, SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here


def test_signing_in_returns_the_person_and_company_and_sets_the_cookie(
    signin: SignInSetup,
) -> None:
    response = signin.client.post(
        "/api/sessions", json={"email": email(signin, "a_ana"), "password": PASSWORD}
    )

    assert response.status_code == 201
    body = response.json()
    assert body["user"]["id"] == str(signin.people["a_ana"])
    assert body["user"]["display_name"] == "Ana"
    assert body["user"]["department_id"]  # the department week's default
    assert body["company"]["name"] == "Northwind Cafe"
    assert body["permissions"] == []  # no roles yet in this setup
    assert signin.client.cookies.get(COOKIE_NAME)


def test_emails_are_matched_ignoring_case_and_spaces(signin: SignInSetup) -> None:
    typed = "  " + email(signin, "a_ana").upper() + " "
    assert signin.sign_in(signin.client, typed) == 201


def test_the_current_session_names_who_is_signed_in(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    response = signin.client.get("/api/sessions/current")
    assert response.status_code == 200
    assert response.json()["user"]["id"] == str(signin.people["a_ana"])


def test_without_signing_in_there_is_no_current_session(signin: SignInSetup) -> None:
    response = signin.client.get("/api/sessions/current")
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"


def test_signing_out_ends_the_session(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    token = signin.client.cookies.get(COOKIE_NAME)

    assert signin.client.delete("/api/sessions/current").status_code == 204
    # The browser is told to forget the cookie...
    assert signin.client.cookies.get(COOKIE_NAME) is None
    # ...and the token stops working on the server too, even if a copy was kept.
    stolen = signin.new_client()
    stolen.cookies.set(COOKIE_NAME, token or "")
    assert stolen.get("/api/sessions/current").status_code == 401


def test_signing_out_everywhere_ends_every_session_of_the_person(signin: SignInSetup) -> None:
    laptop, phone, coworker = signin.client, signin.new_client(), signin.new_client()
    signin.sign_in(laptop, email(signin, "a_ana"))
    signin.sign_in(phone, email(signin, "a_ana"))
    signin.sign_in(coworker, email(signin, "b_ana"))

    assert laptop.delete("/api/sessions").status_code == 204
    assert phone.get("/api/sessions/current").status_code == 401
    # Someone else's session is untouched.
    assert coworker.get("/api/sessions/current").status_code == 200


def test_only_the_tokens_hash_is_stored(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    token = signin.client.cookies.get(COOKIE_NAME) or ""
    raw = urlsafe_b64decode(token + "=")

    with signin.session_for(signin.company_a) as db:
        row = db.scalars(select(UserSession)).one()
    assert len(raw) == 32  # 32 random bytes
    assert row.token_hash == hashlib.sha256(raw).digest()
    assert token.encode() not in row.token_hash and raw != row.token_hash


def test_activity_is_noted_at_most_once_a_minute(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    with signin.session_for(signin.company_a) as db:
        started = db.scalars(select(UserSession.last_seen_at)).one()

    later = started + sessions.SEEN_EVERY / 2
    monkeypatch.setattr(sessions, "utcnow", lambda: later)
    signin.client.get("/api/sessions/current")
    with signin.session_for(signin.company_a) as db:
        assert db.scalars(select(UserSession.last_seen_at)).one() == started

    later = started + sessions.SEEN_EVERY
    signin.client.get("/api/sessions/current")
    with signin.session_for(signin.company_a) as db:
        assert db.scalars(select(UserSession.last_seen_at)).one() == later


def test_an_outdated_password_hash_is_renewed_at_sign_in(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    with signin.session_for(signin.company_a) as db:
        before = db.get(User, signin.people["a_ana"]).password_hash  # type: ignore[union-attr]
    monkeypatch.setattr(sessions, "needs_rehash", lambda stored: True)

    assert signin.sign_in(signin.client, email(signin, "a_ana")) == 201
    with signin.session_for(signin.company_a) as db:
        after = db.get(User, signin.people["a_ana"]).password_hash  # type: ignore[union-attr]
    assert after != before and after is not None and after.startswith("$argon2id$")


def test_sign_ins_are_written_to_the_companys_audit_log(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    signin.sign_in(signin.client, email(signin, "a_ana"), "a wrong but long password")

    with signin.session_for(None) as db:
        events = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.chain_id == signin.company_a)
            .order_by(AuditEvent.seq)
        ).all()
    assert [(e.action, e.actor_type, e.target_type) for e in events] == [
        ("auth.signed_in", "user", "session"),
        ("auth.sign_in_failed", "system", "user"),
    ]
    assert events[1].details == {"reason": "wrong_password"}


def test_the_session_lists_the_persons_permissions(signin: SignInSetup) -> None:
    # Give Ana the Employee role of her department; the next request shows it, without
    # signing in again (permissions are read on every request).
    signin.sign_in(signin.client, email(signin, "a_ana"))
    with signin.session_for(signin.company_a) as db:
        roles = create_starting_roles(db, Actor.system())
        ana = db.get(User, signin.people["a_ana"])
        assert ana is not None
        assign_role(
            db,
            Actor.system(),
            user_id=ana.id,
            role=roles["employee"],
            scope_type="department",
            scope_id=ana.department_id,
        )
        db.commit()

    permissions = signin.client.get("/api/sessions/current").json()["permissions"]
    assert permissions == sorted(
        [
            "schedule.view_self",
            "schedule.view",
            "time_off.request",
            "time_off.cancel_self",
            "account.change_self",
        ]
    )
