"""Sign-in and sessions against the attacks in the threat model (authentication.md).

AU3 (I3): the sign-in form must not reveal which emails have accounts.
AU4 (S2, S3): the cookie is locked down, and a token from before sign-in never becomes a
signed-in session.
AU5 (S2): sessions end after 1 hour idle and 30 days at most.
Plus: a session only ever works for its own company, and the one read across companies
(cross_company_read) is used by sign-in alone.
"""

import pathlib
import re
import time
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.audit.models import AuditEvent
from app.auth import sessions
from app.auth.models import UserSession
from app.auth.sessions import COOKIE_NAME, IDLE_TIMEOUT, MAX_LENGTH, SIGN_IN_FAILED
from app.db.base import utcnow
from app.modules.org.models import User
from app.tenancy.filter import UnsafeQueryError, cross_company_read
from tests.session_data import PASSWORD, SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here


# --- AU3: one answer for every failure -------------------------------------------------


def attempts(setup: SignInSetup) -> dict[str, tuple[str, str]]:
    """Every way a sign-in can fail: (email, password)."""
    return {
        "unknown email": ("nobody@northwind.example", PASSWORD),
        "wrong password": (email(setup, "a_ana"), "a wrong but long password"),
        "no password yet": (email(setup, "a_newbie"), PASSWORD),
        "deactivated": (email(setup, "a_gone"), PASSWORD),
        "locked (correct password)": (email(setup, "a_locked"), PASSWORD),
    }


def test_every_failed_sign_in_gets_exactly_the_same_answer(signin: SignInSetup) -> None:
    answers = []
    for address, password in attempts(signin).values():
        response = signin.new_client().post(
            "/api/sessions", json={"email": address, "password": password}
        )
        assert "set-cookie" not in response.headers
        answers.append((response.status_code, response.text))
    # One status and one body, word for word, whatever the reason.
    assert len(set(answers)) == 1
    status, body = answers[0]
    assert status == 401 and SIGN_IN_FAILED in body


def test_every_failed_sign_in_does_the_same_work(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Timing: exactly one Argon2id check in every case, including an unknown email or an
    # account without a password (checked against a dummy hash), so the time taken does
    # not tell an attacker which emails exist.
    calls: list[str] = []
    real_verify = sessions.verify_password

    def counting_verify(stored_hash: str, password: str) -> bool:
        calls.append(stored_hash[:9])
        return real_verify(stored_hash, password)

    monkeypatch.setattr(sessions, "verify_password", counting_verify)
    for case, (address, password) in attempts(signin).items():
        calls.clear()
        signin.new_client().post("/api/sessions", json={"email": address, "password": password})
        assert calls == ["$argon2id"], case


def test_every_failed_sign_in_takes_at_least_the_same_minimum_time(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The extra work for an existing account (its audit entry) is hidden behind a fixed
    # minimum, so response times do not tell existing emails from unknown ones.
    monkeypatch.setattr(sessions, "FAILED_SIGN_IN_SECONDS", 0.3)
    for case, (address, password) in attempts(signin).items():
        started = time.monotonic()
        signin.new_client().post("/api/sessions", json={"email": address, "password": password})
        assert time.monotonic() - started >= 0.3, case


def test_failed_sign_ins_never_log_the_password(signin: SignInSetup) -> None:
    for address, password in attempts(signin).values():
        signin.new_client().post("/api/sessions", json={"email": address, "password": password})
    with signin.session_for(None) as db:
        stored = [str(e.details) for e in db.scalars(select(AuditEvent))]
    assert stored and not any(PASSWORD in text or "wrong but long" in text for text in stored)


# --- AU4: the cookie, and no planted sessions ------------------------------------------


def test_the_cookie_has_every_protective_attribute(signin: SignInSetup) -> None:
    response = signin.client.post(
        "/api/sessions", json={"email": email(signin, "a_ana"), "password": PASSWORD}
    )
    cookie = response.headers["set-cookie"]
    parts = [part.strip().lower() for part in cookie.split(";")]

    assert cookie.startswith(f"{COOKIE_NAME}=")
    assert "secure" in parts  # HTTPS only
    assert "httponly" in parts  # out of reach of JavaScript (XSS)
    assert "samesite=strict" in parts  # not sent by other sites (CSRF)
    assert "path=/" in parts  # required by __Host-
    assert not any(part.startswith("domain=") for part in parts)  # this host only
    max_age = int(next(p for p in parts if p.startswith("max-age=")).split("=")[1])
    assert MAX_LENGTH.total_seconds() - 60 <= max_age <= MAX_LENGTH.total_seconds()


def test_each_sign_in_gets_a_new_unguessable_token(signin: SignInSetup) -> None:
    tokens = set()
    for _ in range(3):
        client = signin.new_client()
        signin.sign_in(client, email(signin, "a_ana"))
        tokens.add(client.cookies.get(COOKIE_NAME))
    assert len(tokens) == 3
    assert all(token and re.fullmatch(r"[A-Za-z0-9_-]{43}", token) for token in tokens)


def test_a_planted_token_never_becomes_a_signed_in_session(signin: SignInSetup) -> None:
    # Session fixation: an attacker gets a browser to carry a token they know, waits for
    # the victim to sign in, then uses the token. Sign-in always issues a fresh token, and
    # the planted one is never accepted.
    planted = "A" * 43
    response = signin.new_client().post(
        "/api/sessions",
        json={"email": email(signin, "a_ana"), "password": PASSWORD},
        headers={"Cookie": f"{COOKIE_NAME}={planted}"},
    )
    issued = response.cookies.get(COOKIE_NAME)
    assert response.status_code == 201 and issued and issued != planted

    attacker = signin.new_client()
    assert (
        attacker.get(
            "/api/sessions/current", headers={"Cookie": f"{COOKIE_NAME}={planted}"}
        ).status_code
        == 401
    )


def test_signing_in_again_ends_the_browsers_previous_session(signin: SignInSetup) -> None:
    # A copy of the old token (taken before the new sign-in) must stop working.
    signin.sign_in(signin.client, email(signin, "a_ana"))
    old = signin.client.cookies.get(COOKIE_NAME)
    signin.sign_in(signin.client, email(signin, "a_ana"))

    copy = signin.new_client()
    stale = copy.get("/api/sessions/current", headers={"Cookie": f"{COOKIE_NAME}={old}"})
    assert stale.status_code == 401
    assert signin.client.get("/api/sessions/current").status_code == 200


@pytest.mark.parametrize(
    "cookie", ["", "short", "A" * 42 + "!", "A" * 44, "=" * 43, "A" * 42 + "*"]
)
def test_malformed_cookies_are_simply_not_signed_in(signin: SignInSetup, cookie: str) -> None:
    signin.client.cookies.set(COOKIE_NAME, cookie)
    assert signin.client.get("/api/sessions/current").status_code == 401


# --- AU5: timeouts ---------------------------------------------------------------------


def fast_forward(monkeypatch: pytest.MonkeyPatch, by: timedelta) -> None:
    """Pretend `by` has passed, for the session rules."""
    now = utcnow() + by
    monkeypatch.setattr(sessions, "utcnow", lambda: now)


def test_a_session_ends_after_an_hour_without_requests(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    fast_forward(monkeypatch, IDLE_TIMEOUT + timedelta(seconds=1))

    assert signin.client.get("/api/sessions/current").status_code == 401
    # The row is gone, so the token can never work again.
    with signin.session_for(signin.company_a) as db:
        assert db.scalars(select(UserSession)).all() == []


def test_activity_keeps_a_session_alive_but_never_past_30_days(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))

    def active_until(elapsed: timedelta) -> int:
        """Jump ahead as if the person had been active all along, then make a request."""
        fast_forward(monkeypatch, elapsed)
        with signin.session_for(signin.company_a) as db:
            db.execute(update(UserSession).values(last_seen_at=sessions.utcnow()))
            db.commit()
        return signin.client.get("/api/sessions/current").status_code

    # Active every day: still signed in a minute before the 30 days are up...
    assert active_until(MAX_LENGTH - timedelta(minutes=1)) == 200
    # ...and signed out at 30 days, however active.
    assert active_until(MAX_LENGTH) == 401


def test_signing_in_clears_away_the_persons_ended_sessions(
    signin: SignInSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A browser that never comes back leaves its row behind; the next sign-in of the same
    # person removes it (data-model.md: expired rows are deleted).
    signin.sign_in(signin.new_client(), email(signin, "a_ana"))
    fast_forward(monkeypatch, IDLE_TIMEOUT + timedelta(minutes=1))
    signin.sign_in(signin.client, email(signin, "a_ana"))

    with signin.session_for(signin.company_a) as db:
        assert len(db.scalars(select(UserSession)).all()) == 1


def test_deactivating_a_person_ends_their_session(signin: SignInSetup) -> None:
    signin.sign_in(signin.client, email(signin, "a_ana"))
    with signin.session_for(signin.company_a) as db:
        db.get(User, signin.people["a_ana"]).deactivated_at = utcnow()  # type: ignore[union-attr]
        db.commit()
    assert signin.client.get("/api/sessions/current").status_code == 401


# --- Companies -------------------------------------------------------------------------


def test_a_session_works_only_for_its_own_company(signin: SignInSetup) -> None:
    # The company comes from the session row, never from the request: company B's person
    # sees company B, and nothing the request says can change that.
    signin.sign_in(signin.client, email(signin, "b_ana"))
    response = signin.client.get(
        "/api/sessions/current",
        params={"company_id": str(signin.company_a)},
        headers={"X-Company-Id": str(signin.company_a)},
    )
    assert response.json()["company"]["id"] == str(signin.company_b)


def test_signing_out_everywhere_cannot_reach_another_companys_sessions(
    signin: SignInSetup,
) -> None:
    other = signin.new_client()
    signin.sign_in(other, email(signin, "a_ana"))
    signin.sign_in(signin.client, email(signin, "b_ana"))
    signin.client.delete("/api/sessions")
    assert other.get("/api/sessions/current").status_code == 200


def test_the_cross_company_read_is_only_a_select_before_a_company_is_set(
    signin: SignInSetup,
) -> None:
    # Marked as a cross-company read, an UPDATE is still refused...
    with signin.session_for(None) as db, pytest.raises(UnsafeQueryError):
        db.execute(cross_company_read(update(User).values(display_name="x")))
    # ...and so is a SELECT in a session that already works for a company.
    with signin.session_for(signin.company_a) as db, pytest.raises(UnsafeQueryError):
        db.execute(cross_company_read(select(User.email)))
    # Without the mark, reading people without a company is refused as before.
    with signin.session_for(None) as db, pytest.raises(Exception, match="company"):
        db.execute(select(User.email))


def test_only_sign_in_uses_the_cross_company_read() -> None:
    # Layer 3 of tenancy.md for this exception: any new use must be added here on purpose.
    app_dir = pathlib.Path(__file__).resolve().parents[2] / "app"
    users = sorted(
        str(path.relative_to(app_dir)).replace("\\", "/")
        for path in app_dir.rglob("*.py")
        if "cross_company_read(" in path.read_text(encoding="utf-8")
        or "tenancy_cross_company_read" in path.read_text(encoding="utf-8")
    )
    assert users == ["auth/sessions.py", "tenancy/filter.py"]


def test_no_answer_contains_a_password_hash_or_token_hash(signin: SignInSetup) -> None:
    created = signin.client.post(
        "/api/sessions", json={"email": email(signin, "a_ana"), "password": PASSWORD}
    )
    current = signin.client.get("/api/sessions/current")
    for body in (created.text, current.text):
        assert "argon2" not in body and "hash" not in body and PASSWORD not in body
    assert str(uuid.UUID(created.json()["user"]["id"])) == str(signin.people["a_ana"])
