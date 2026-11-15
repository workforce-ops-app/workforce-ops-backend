"""Entering the password again, and changing your own password (app/auth/reauth.py).

The happy paths and the rules. Attacks (a stolen session, an old cookie, other people) are
in tests/security/test_reauth.py.
"""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.audit.models import AuditEvent
from app.auth.models import UserSession
from app.auth.reauth import ReauthRequired, require_reauth
from app.db.base import utcnow
from app.modules.org.models import User
from tests.session_data import OTHER_PASSWORD, PASSWORD, SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here

NEW_PASSWORD = "a fresh long passphrase for today"


def _session_row(setup: SignInSetup) -> UserSession:
    """Ana's one session, as it is in the database."""
    with setup.session_for(setup.company_a) as db:
        return db.scalars(
            select(UserSession).where(UserSession.user_id == setup.people["a_ana"])
        ).one()


def _actions(setup: SignInSetup) -> list[tuple[str, dict]]:
    with setup.session_for(setup.company_a) as db:
        return [
            (e.action, e.details)
            for e in db.scalars(
                select(AuditEvent)
                .where(AuditEvent.action.in_(["auth.reauth_failed", "auth.password_changed"]))
                .order_by(AuditEvent.seq)
            )
        ]


# --- The helper sensitive actions call -------------------------------------------------


@pytest.mark.parametrize(
    ("entered", "allowed"),
    [
        (None, False),  # never entered in this session
        (timedelta(minutes=6), False),  # too long ago
        (timedelta(minutes=4, seconds=50), True),
        (timedelta(seconds=0), True),
    ],
)
def test_sensitive_actions_need_a_reentry_in_the_last_five_minutes(
    entered: timedelta | None, allowed: bool
) -> None:
    session = UserSession(reauth_at=None if entered is None else utcnow() - entered)
    if allowed:
        require_reauth(session)
    else:
        with pytest.raises(ReauthRequired):
            require_reauth(session)


def test_the_refusal_has_the_type_the_interface_looks_for(signin: SignInSetup) -> None:
    from fastapi import APIRouter

    # A stand-in sensitive endpoint, to see the answer exactly as a browser would.
    probe = APIRouter()

    @probe.get("/api/probe-sensitive")
    def sensitive() -> None:
        raise ReauthRequired()

    signin.client.app.include_router(probe)  # type: ignore[attr-defined]
    response = signin.client.get("/api/probe-sensitive")
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["type"] == "reauth-required"


# --- Re-entry ----------------------------------------------------------------------------


def test_the_right_password_allows_sensitive_actions_for_this_session(signin: SignInSetup) -> None:
    assert signin.sign_in(signin.client, email(signin, "a_ana")) == 201
    assert _session_row(signin).reauth_at is None
    response = signin.client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    assert response.status_code == 204 and response.content == b""
    row = _session_row(signin)
    assert row.reauth_at is not None
    require_reauth(row)  # passes now


def test_a_wrong_password_is_refused_and_recorded(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    response = signin.client.post("/api/sessions/current/reauth", json={"password": "nope"})
    assert (
        response.status_code == 403 and response.json()["detail"] == "That password is not right."
    )
    assert _session_row(signin).reauth_at is None
    # Recorded (never the password), and the session itself is still signed in.
    assert _actions(signin) == [("auth.reauth_failed", {"during": "reauth"})]
    assert signin.client.get("/api/sessions/current").status_code == 200


def test_reentry_needs_a_session_and_a_csrf_token(signin: SignInSetup) -> None:
    assert (
        signin.client.post("/api/sessions/current/reauth", json={"password": PASSWORD}).status_code
        == 401
    )
    signin.sign_in(signin.client, email(signin, "a_ana"))
    token = signin.client.headers.pop("X-CSRF-Token")
    refused = signin.client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    signin.client.headers["X-CSRF-Token"] = token
    assert refused.status_code == 403 and _session_row(signin).reauth_at is None


# --- Changing your own password ----------------------------------------------------------


def test_changing_the_password_signs_out_every_other_browser(signin: SignInSetup) -> None:
    other = signin.new_client()
    signin.sign_in(other, email(signin, "a_ana"))
    signin.sign_in(signin.client, email(signin, "a_ana"))
    expires = _session_row_of(signin, signin.client).expires_at

    response = signin.client.put(
        "/api/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}
    )
    assert response.status_code == 200
    # This browser carries on with a new session: a new cookie and a new CSRF token.
    signin.client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    assert signin.client.get("/api/sessions/current").status_code == 200
    # The other browser is signed out.
    assert other.get("/api/sessions/current").status_code == 401
    # One session left: the new one, with the old end date (never longer) and the
    # password counted as just entered.
    with signin.session_for(signin.company_a) as db:
        rows = db.scalars(
            select(UserSession).where(UserSession.user_id == signin.people["a_ana"])
        ).all()
    assert len(rows) == 1 and rows[0].expires_at == expires and rows[0].reauth_at is not None
    assert _actions(signin) == [("auth.password_changed", {"other_sessions_ended": 1})]

    # The new password works, the old one does not.
    assert signin.sign_in(signin.new_client(), email(signin, "a_ana"), NEW_PASSWORD) == 201
    assert signin.sign_in(signin.new_client(), email(signin, "a_ana"), PASSWORD) == 401


def _session_row_of(setup: SignInSetup, client: object) -> UserSession:
    """The newest of ana's sessions (the client's own, right after it signed in)."""
    with setup.session_for(setup.company_a) as db:
        return db.scalars(
            select(UserSession)
            .where(UserSession.user_id == setup.people["a_ana"])
            .order_by(UserSession.created_at.desc(), UserSession.id.desc())
        ).first()  # type: ignore[return-value]


def test_a_wrong_current_password_changes_nothing(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    before = _hash(signin)
    response = signin.client.put(
        "/api/me/password", json={"current_password": OTHER_PASSWORD, "new_password": NEW_PASSWORD}
    )
    assert response.status_code == 403
    assert _hash(signin) == before
    assert signin.client.get("/api/sessions/current").status_code == 200
    assert _actions(signin) == [("auth.reauth_failed", {"during": "password_change"})]


@pytest.mark.parametrize(
    "new_password",
    [
        "too short",
        "000000000000000",  # on the common-password blocklist
        "northwind cafe is my workplace",  # the company's name
        "ana " * 5,  # the person's name
        "x" * 129,
    ],
)
def test_the_new_password_keeps_the_rules(signin: SignInSetup, new_password: str) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    before = _hash(signin)
    response = signin.client.put(
        "/api/me/password", json={"current_password": PASSWORD, "new_password": new_password}
    )
    assert response.status_code == 422, response.text
    assert _hash(signin) == before
    # Refused before anything changed: still signed in with the old session.
    assert signin.client.get("/api/sessions/current").status_code == 200


def test_the_password_change_input_is_checked(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    for body in (
        {"new_password": NEW_PASSWORD},
        {"current_password": PASSWORD},
        {"current_password": PASSWORD, "new_password": NEW_PASSWORD, "user_id": "x"},
        {"current_password": "x" * 1025, "new_password": NEW_PASSWORD},
    ):
        assert signin.client.put("/api/me/password", json=body).status_code == 422, body


def _hash(setup: SignInSetup) -> str | None:
    with setup.session_for(setup.company_a) as db:
        user = db.get(User, setup.people["a_ana"])
        assert user is not None
        return user.password_hash
