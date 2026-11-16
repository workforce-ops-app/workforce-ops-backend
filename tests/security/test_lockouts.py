"""Lockouts and rate limits against password guessing (S1) and flooding (D1): test AU2,
and the 429 limits, through the real sign-in.

Each test is the attacker's view: what the guesser gets back, whether their guesses are
still tried, and whether the real person can get back in.
"""

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.audit.models import AuditEvent
from app.db.base import utcnow
from app.modules.org.models import User
from tests.session_data import BASE_URL, PASSWORD, SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here


@pytest.fixture(autouse=True)
def one_minute(signin: SignInSetup) -> None:
    """Every request in a test falls in the same minute of the rate limits. Real sign-ins
    take about half a second each (Argon2id), so a test with many of them could otherwise
    cross into the next minute, where every count starts again."""
    limits = signin.client.app.state.limits  # type: ignore[attr-defined]
    for limit in (limits.sign_in_per_address, limits.requests_per_session):
        limit.clock = lambda: 6_000_030.0  # half a minute into some minute


def _ana(setup: SignInSetup) -> User:
    with setup.session_for(setup.company_a) as db:
        found = db.get(User, setup.people["a_ana"])
        assert found is not None
        db.expunge(found)
        return found


def _set(setup: SignInSetup, **values: object) -> None:
    """Change ana's account directly (for example to move a lock into the past)."""
    with setup.session_for(setup.company_a) as db:
        found = db.get(User, setup.people["a_ana"])
        assert found is not None
        for name, value in values.items():
            setattr(found, name, value)
        db.commit()


def _from(setup: SignInSetup, address: str) -> TestClient:
    """A browser at another address."""
    return TestClient(
        setup.client.app, base_url=BASE_URL, headers={"Origin": BASE_URL}, client=(address, 50000)
    )


WRONG = "a wrong guess at it"


def _guess(setup: SignInSetup, times: int, password: str = WRONG) -> list[int]:
    """Wrong passwords for ana, each from its own address (so the address limit stays out
    of the way and only the lockout is tested)."""
    return [
        setup.sign_in(_from(setup, f"198.51.100.{n}"), email(setup, "a_ana"), password)
        for n in range(times)
    ]


# --- AU2: lockouts ---------------------------------------------------------------------


def test_five_wrong_passwords_lock_the_account_for_15_minutes(signin: SignInSetup) -> None:
    assert _guess(signin, 5) == [401] * 5
    ana = _ana(signin)
    assert ana.failed_sign_ins == 5 and ana.locked_until is not None
    assert timedelta(minutes=14) < ana.locked_until - utcnow() <= timedelta(minutes=15)
    with signin.session_for(signin.company_a) as db:
        locked = db.scalars(select(AuditEvent).where(AuditEvent.action == "auth.locked")).one()
    assert locked.details == {"failures": 5, "minutes": 15}


def test_while_locked_even_the_right_password_gets_the_usual_answer(signin: SignInSetup) -> None:
    _guess(signin, 5)
    refused = _from(signin, "203.0.113.1").post(
        "/api/sessions", json={"email": email(signin, "a_ana"), "password": PASSWORD}
    )
    unknown = _from(signin, "203.0.113.2").post(
        "/api/sessions", json={"email": "nobody@northwind.example", "password": PASSWORD}
    )
    # The same answer as an unknown email: a lock never says the account exists.
    assert refused.status_code == unknown.status_code == 401
    assert refused.json() == unknown.json()
    # Guesses during the lock are not tried, so they do not count either.
    assert _ana(signin).failed_sign_ins == 5


def test_the_locks_grow_and_never_pass_an_hour(signin: SignInSetup) -> None:
    for expected_total, minutes in ((5, 15), (10, 30), (15, 60), (16, 60), (17, 60)):
        # Move any lock into the past, as if it had run out, then guess until the next step.
        _set(signin, locked_until=utcnow() - timedelta(seconds=1))
        _guess(signin, expected_total - _ana(signin).failed_sign_ins)
        ana = _ana(signin)
        assert ana.failed_sign_ins == expected_total
        assert ana.locked_until is not None
        left = ana.locked_until - utcnow()
        assert timedelta(minutes=minutes - 1) < left <= timedelta(minutes=minutes), expected_total


def test_the_right_password_after_a_lock_resets_the_count(signin: SignInSetup) -> None:
    _guess(signin, 5)
    _set(signin, locked_until=utcnow() - timedelta(seconds=1))  # the lock has run out
    assert signin.sign_in(_from(signin, "203.0.113.3"), email(signin, "a_ana")) == 201
    ana = _ana(signin)
    assert ana.failed_sign_ins == 0 and ana.locked_until is None


def test_a_day_without_failures_starts_the_count_again(signin: SignInSetup) -> None:
    _guess(signin, 4)
    # The last failure was over a day ago.
    with signin.session_for(signin.company_a) as db:
        found = db.get(User, signin.people["a_ana"])
        assert found is not None
        db.execute(
            User.__table__.update()
            .where(User.id == found.id)
            .values(updated_at=utcnow() - timedelta(hours=25))
        )
        db.commit()
    _guess(signin, 1)
    ana = _ana(signin)
    # Counted from 1 again, so the 5th failure in a row is still to come: not locked.
    assert ana.failed_sign_ins == 1 and ana.locked_until is None


def test_wrong_reentries_count_toward_the_same_lockout(signin: SignInSetup) -> None:
    """Someone holding a session cannot keep guessing through re-entry instead of sign-in."""
    assert signin.sign_in(signin.client, email(signin, "a_ana")) == 201
    for _ in range(5):
        response = signin.client.post("/api/sessions/current/reauth", json={"password": "guess"})
        assert response.status_code == 403
    assert _ana(signin).locked_until is not None
    # Locked: even the right password is not tried at re-entry, nor at sign-in.
    response = signin.client.post("/api/sessions/current/reauth", json={"password": PASSWORD})
    assert response.status_code == 403 and "Too many" in response.json()["detail"]
    assert signin.sign_in(_from(signin, "203.0.113.4"), email(signin, "a_ana")) == 401


# --- Rate limits -----------------------------------------------------------------------


def test_twenty_sign_in_attempts_a_minute_from_one_address(signin: SignInSetup) -> None:
    browser = _from(signin, "192.0.2.10")
    body = {"email": "nobody@northwind.example", "password": "whatever it is"}
    answers = [browser.post("/api/sessions", json=body) for _ in range(21)]
    assert [a.status_code for a in answers[:20]] == [401] * 20
    limited = answers[20]
    assert limited.status_code == 429
    assert 1 <= int(limited.headers["Retry-After"]) <= 60
    # Limited before any password is checked: even the right one waits.
    right = browser.post(
        "/api/sessions", json={"email": email(signin, "a_ana"), "password": PASSWORD}
    )
    assert right.status_code == 429
    # Another address is not affected.
    assert signin.sign_in(_from(signin, "192.0.2.11"), email(signin, "a_ana")) == 201


def test_a_made_up_forwarded_header_does_not_escape_the_limit(signin: SignInSetup) -> None:
    """The address is the sender's (or, behind nginx, the one nginx adds, as uvicorn
    reads it); a header the browser writes itself changes nothing."""
    browser = _from(signin, "192.0.2.20")
    body = {"email": "nobody@northwind.example", "password": "whatever it is"}
    statuses = [
        browser.post(
            "/api/sessions", json=body, headers={"X-Forwarded-For": f"10.9.8.{n}"}
        ).status_code
        for n in range(21)
    ]
    assert statuses[-1] == 429


def test_the_limit_answer_is_the_same_for_every_email(signin: SignInSetup) -> None:
    """A 429 does not depend on which account was tried, so it reveals nothing about them."""
    first, second = _from(signin, "192.0.2.30"), _from(signin, "192.0.2.31")
    for browser, address in ((first, email(signin, "a_ana")), (second, "nobody@summit.example")):
        for _ in range(20):
            browser.post("/api/sessions", json={"email": address, "password": "a wrong one"})
    a = first.post("/api/sessions", json={"email": email(signin, "a_ana"), "password": "x"})
    b = second.post("/api/sessions", json={"email": "nobody@summit.example", "password": "x"})
    assert a.status_code == b.status_code == 429 and a.json() == b.json()


def test_a_session_may_make_300_requests_a_minute(signin: SignInSetup) -> None:
    assert signin.sign_in(signin.client, email(signin, "a_ana")) == 201
    statuses = [signin.client.get("/api/sessions/current").status_code for _ in range(301)]
    assert statuses[:300] == [200] * 300 and statuses[300] == 429
    # Another session of the same person has its own count.
    other = _from(signin, "192.0.2.40")
    assert signin.sign_in(other, email(signin, "a_ana")) == 201
    assert other.get("/api/sessions/current").status_code == 200
