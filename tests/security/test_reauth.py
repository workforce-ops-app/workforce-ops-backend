"""Re-entry and password changes against threat S2 (a session someone else is using) and
I5 (secrets in answers or logs): AU8 (password change part), AU9, AU10.

Each test is the attacker's view: someone holding a copy of the session cookie, or a
browser left signed in, and what they can still do.
"""

import logging

import pytest
from sqlalchemy import select

from app.audit.models import AuditEvent
from app.auth.models import UserSession
from app.auth.reauth import ReauthRequired, require_reauth
from app.auth.sessions import COOKIE_NAME
from tests.session_data import PASSWORD, SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here

NEW_PASSWORD = "a fresh long passphrase for today"


def test_a_copied_cookie_stops_working_when_the_password_changes(signin: SignInSetup) -> None:
    """AU8: an attacker copied the cookie; the person notices and changes their password.
    The copy is useless at once, even on the browser it came from."""
    signin.sign_in(signin.client, email(signin, "a_ana"))
    stolen = signin.client.cookies.get(COOKIE_NAME)
    # The thief's browser sends the copied token, as the existing sign-in tests do.
    thief = signin.new_client()
    copied = {"Cookie": f"{COOKIE_NAME}={stolen}"}
    assert thief.get("/api/sessions/current", headers=copied).status_code == 200

    changed = signin.client.put(
        "/api/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}
    )
    assert changed.status_code == 200
    assert thief.get("/api/sessions/current", headers=copied).status_code == 401
    # The person's own browser got a different token.
    assert signin.client.cookies.get(COOKIE_NAME) != stolen


def test_a_session_alone_cannot_change_the_password(signin: SignInSetup) -> None:
    """Someone at a computer left signed in, who does not know the password, cannot lock
    the real owner out by setting a new one."""
    signin.sign_in(signin.client, email(signin, "a_ana"))
    response = signin.client.put(
        "/api/me/password", json={"current_password": "a guess at it", "new_password": NEW_PASSWORD}
    )
    assert response.status_code == 403
    # The real owner can still sign in with their password, from anywhere.
    assert signin.sign_in(signin.new_client(), email(signin, "a_ana")) == 201


def test_a_reentry_counts_only_in_its_own_session(signin: SignInSetup) -> None:
    """AU9: entering the password on one browser does not open sensitive actions on another
    (for instance one where the attacker is signed in with a copied cookie)."""
    other = signin.new_client()
    signin.sign_in(other, email(signin, "a_ana"))
    signin.sign_in(signin.client, email(signin, "a_ana"))
    signin.client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    with signin.session_for(signin.company_a) as db:
        rows = db.scalars(
            select(UserSession).where(UserSession.user_id == signin.people["a_ana"])
        ).all()
    entered = [row for row in rows if row.reauth_at is not None]
    assert len(rows) == 2 and len(entered) == 1
    with pytest.raises(ReauthRequired):
        require_reauth(next(row for row in rows if row.reauth_at is None))


def test_changing_a_password_never_reaches_another_company(signin: SignInSetup) -> None:
    """The delete of the person's sessions goes through the company filter: another
    company's people stay signed in."""
    theirs = signin.new_client()
    signin.sign_in(theirs, email(signin, "b_ana"))
    signin.sign_in(signin.client, email(signin, "a_ana"))
    signin.client.put(
        "/api/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}
    )
    assert theirs.get("/api/sessions/current").status_code == 200


def test_no_answer_entry_or_log_line_holds_a_password(
    signin: SignInSetup, caplog: pytest.LogCaptureFixture
) -> None:
    """AU10: the passwords sent never come back in an answer, an audit entry, or the log,
    whether the attempt succeeded or failed."""
    caplog.set_level(logging.DEBUG)
    signin.sign_in(signin.client, email(signin, "a_ana"))
    answers = [
        signin.client.post("/api/sessions/current/reauth", json={"password": "wrong secret words"}),
        signin.client.post("/api/sessions/current/reauth", json={"password": PASSWORD}),
        signin.client.put(
            "/api/me/password",
            json={"current_password": PASSWORD, "new_password": "short secret"},
        ),
        signin.client.put(
            "/api/me/password",
            json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
        ),
    ]
    with signin.session_for(signin.company_a) as db:
        entries = [str(e.details) for e in db.scalars(select(AuditEvent))]
    everything = [r.text for r in answers] + entries + [caplog.text]
    for secret in ("wrong secret words", PASSWORD, "short secret", NEW_PASSWORD, "argon2"):
        assert not any(secret in text for text in everything), secret


def test_reentry_and_password_change_refuse_forged_requests(signin: SignInSetup) -> None:
    """AU6 for the two new endpoints: a request from another site carries the cookie but
    not the CSRF token, and changes nothing."""
    signin.sign_in(signin.client, email(signin, "a_ana"))
    token = signin.client.headers.pop("X-CSRF-Token")
    try:
        forged_put = signin.client.put(
            "/api/me/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}
        )
        forged_reauth = signin.client.post(
            "/api/sessions/current/reauth", json={"password": PASSWORD}
        )
    finally:
        signin.client.headers["X-CSRF-Token"] = token
    assert forged_put.status_code == forged_reauth.status_code == 403
    with signin.session_for(signin.company_a) as db:
        row = db.scalars(
            select(UserSession).where(UserSession.user_id == signin.people["a_ana"])
        ).one()
    assert row.reauth_at is None
    # The password is unchanged: the old one still signs in.
    assert signin.sign_in(signin.new_client(), email(signin, "a_ana")) == 201
