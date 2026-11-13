"""Setup and reset links against the attacks in the threat model: test AU7 (S5, E3), the
sessions a reset ends (AU8), and what a link never reveals (AU10).

Every request goes through the real app: the session, the CSRF check, the company filter,
and authorize(). Each test is the attacker's view: someone reusing, guessing, or holding a
cancelled or expired link, or an administrator creating one for someone they are not above.

People (tests/shift_data.py), plus "admin" here: an Administrator of company A (so they
hold user.manage everywhere in it) who is above chef only, through one reporting line.
"""

import uuid
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.audit import Actor
from app.audit.models import AuditEvent
from app.auth.links import LINK_NOT_VALID
from app.auth.models import OneTimeToken, UserSession
from app.auth.passwords import hash_password
from app.authz.models import ReportingLine, Role
from app.authz.roles import assign_role
from app.db.base import utcnow
from app.modules.org.models import User
from tests.shift_data import BASE_URL, PASSWORD, ShiftSetup, shifts

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here

NEW_PASSWORD = "a brand new long passphrase"


@pytest.fixture
def links(shifts: ShiftSetup) -> Iterator[ShiftSetup]:
    """The shift setup, plus an Administrator who is above chef and nobody else."""
    with shifts.db() as db:
        admin = User(
            email="admin@northwind.example",
            display_name="Admin",
            department_id=shifts.ids["front"],
            password_hash=hash_password(PASSWORD),
        )
        db.add(admin)
        db.flush()
        role = db.scalars(select(Role).where(Role.built_in == "administrator")).one()
        assign_role(db, Actor.system(), user_id=admin.id, role=role, scope_type="company")
        db.add(ReportingLine(manager_id=admin.id, employee_id=shifts.ids["chef"]))
        db.commit()
        shifts.ids["admin"] = admin.id
    yield shifts


def _create(setup: ShiftSetup, who: str, person: str, purpose: str = "setup") -> Any:
    """The answer when `who` asks for a link for `person` (a key in setup.ids)."""
    return setup.browser(who).post(f"/api/users/{setup.ids[person]}/{purpose}-link")


def _token(setup: ShiftSetup, who: str, person: str, purpose: str = "setup") -> str:
    """Create a link and return the token from its address (the part after #token=)."""
    response = _create(setup, who, person, purpose)
    assert response.status_code == 201, response.text
    return response.json()["link"].split("#token=", 1)[1]


def _anonymous(setup: ShiftSetup) -> TestClient:
    """A browser nobody is signed in on, as the person opening the link uses."""
    return TestClient(setup.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]


def _redeem(setup: ShiftSetup, token: str, password: str = NEW_PASSWORD) -> int:
    response = _anonymous(setup).post(
        "/api/password-links/redeem", json={"token": token, "new_password": password}
    )
    return response.status_code


def _signs_in(setup: ShiftSetup, name: str, password: str) -> bool:
    response = _anonymous(setup).post(
        "/api/sessions", json={"email": f"{name}@northwind.example", "password": password}
    )
    return response.status_code == 201


# --- AU7: a link works once, for its person, for 48 hours --------------------------------


def test_a_setup_link_lets_the_new_person_choose_a_password(links: ShiftSetup) -> None:
    response = _create(links, "owner", "newbie")
    assert response.status_code == 201
    body = response.json()
    # The address is the application's own page, with the token after the "#", so the
    # browser never sends the token to a server in the address.
    assert body["link"].startswith(f"{BASE_URL}/set-password.html#token=")
    assert body["purpose"] == "setup"
    token = body["link"].split("#token=", 1)[1]

    assert _redeem(links, token) == 204
    assert _signs_in(links, "newbie", NEW_PASSWORD)


def test_a_link_works_only_once(links: ShiftSetup) -> None:
    token = _token(links, "owner", "newbie")
    assert _redeem(links, token) == 204
    # A copy of the link (a shared screen, a forwarded text) cannot set it again.
    assert _redeem(links, token, "someone elses chosen passphrase") == 400
    assert _signs_in(links, "newbie", NEW_PASSWORD)


def test_a_link_stops_working_after_48_hours(links: ShiftSetup) -> None:
    token = _token(links, "owner", "newbie")
    with links.db() as db:
        link = db.scalars(select(OneTimeToken)).one()
        # Created with 48 hours to go...
        assert timedelta(hours=47) < link.expires_at - utcnow() <= timedelta(hours=48)
        # ...and now they have passed.
        link.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert _redeem(links, token) == 400
    assert not _signs_in(links, "newbie", NEW_PASSWORD)


def test_a_newer_link_cancels_the_older_one(links: ShiftSetup) -> None:
    older = _token(links, "owner", "newbie")
    newer = _token(links, "owner", "newbie")
    assert _redeem(links, older) == 400
    assert _redeem(links, newer) == 204
    with links.db() as db:
        created = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "auth.link_created")
        ).all()
    assert [entry.details["links_cancelled"] for entry in created] == [0, 1]


def test_every_link_that_does_not_work_gets_the_same_answer(links: ShiftSetup) -> None:
    """Unknown, malformed, used, and cancelled links: one answer, so nothing is learned
    about which links exist or what happened to them."""
    used = _token(links, "owner", "newbie")
    assert _redeem(links, used) == 204
    cancelled = _token(links, "owner", "dana", "reset")
    _token(links, "owner", "dana", "reset")
    answers = [
        _anonymous(links).post(
            "/api/password-links/redeem", json={"token": token, "new_password": NEW_PASSWORD}
        )
        for token in (used, cancelled, "A" * 43, "not a token", "")
    ]
    assert {(a.status_code, a.json()["detail"]) for a in answers} == {(400, LINK_NOT_VALID)}


def test_a_password_that_breaks_the_rules_does_not_use_up_the_link(links: ShiftSetup) -> None:
    token = _token(links, "owner", "newbie")
    response = _anonymous(links).post(
        "/api/password-links/redeem", json={"token": token, "new_password": "too short"}
    )
    assert response.status_code == 422 and "15 characters" in response.json()["detail"]
    # The person can try again with a better one.
    assert _redeem(links, token) == 204


# --- AU7, E3: only someone above the person, and never for yourself ---------------------


def test_nobody_creates_a_link_for_themselves(links: ShiftSetup) -> None:
    """Someone who took over an administrator's session must not be able to reset the
    administrator's password (and so keep the account)."""
    assert _create(links, "owner", "owner", "reset").status_code == 403
    assert _create(links, "admin", "admin", "reset").status_code == 403


def test_an_administrator_creates_links_only_for_people_below_them(links: ShiftSetup) -> None:
    # Above chef through the reporting line: allowed.
    assert _create(links, "admin", "chef", "reset").status_code == 201
    # Not above ana, newbie, or the owner, although user.manage covers the whole company.
    for person, purpose in (("ana", "reset"), ("newbie", "setup"), ("owner", "reset")):
        assert _create(links, "admin", person, purpose).status_code == 403
    with links.db() as db:
        for_people = set(db.scalars(select(OneTimeToken.user_id)))
    assert for_people == {links.ids["chef"]}


def test_without_user_manage_no_link_is_created(links: ShiftSetup) -> None:
    # Chef manages the Kitchen but holds no user.manage.
    assert _create(links, "chef", "ana", "reset").status_code == 403
    assert _create(links, "chef", "newbie").status_code == 403
    # Not signed in at all.
    response = _anonymous(links).post(f"/api/users/{links.ids['newbie']}/setup-link")
    assert response.status_code == 401


def test_another_companys_person_does_not_exist(links: ShiftSetup) -> None:
    assert _create(links, "owner", "b_ana", "reset").status_code == 404
    response = links.browser("owner").post(f"/api/users/{uuid.uuid4()}/setup-link")
    assert response.status_code == 404
    with links.db(links.company_b) as db:
        assert db.scalars(select(OneTimeToken)).all() == []


def test_the_kind_of_link_must_fit_the_account(links: ShiftSetup) -> None:
    # A setup link is for an account without a password, a reset link for one with a
    # password; a deactivated account gets neither.
    assert _create(links, "owner", "ana", "setup").status_code == 409
    assert _create(links, "owner", "newbie", "reset").status_code == 409
    assert _create(links, "owner", "gone", "reset").status_code == 409


def test_a_link_stops_working_when_the_person_is_deactivated(links: ShiftSetup) -> None:
    token = _token(links, "owner", "ana", "reset")
    with links.db() as db:
        ana = db.get(User, links.ids["ana"])
        assert ana is not None
        ana.deactivated_at = utcnow()
        db.commit()
    assert _redeem(links, token) == 400


# --- AU8: a reset ends every session; it also clears a lockout --------------------------


def test_a_reset_signs_the_person_out_everywhere(links: ShiftSetup) -> None:
    ana = links.browser("ana")
    assert ana.get("/api/sessions/current").status_code == 200
    token = _token(links, "owner", "ana", "reset")
    assert _redeem(links, token) == 204
    # The browser still holding ana's old session is signed out, and the old password
    # no longer works; the new one does.
    assert ana.get("/api/sessions/current").status_code == 401
    assert not _signs_in(links, "ana", PASSWORD)
    assert _signs_in(links, "ana", NEW_PASSWORD)
    with links.db() as db:
        used = db.scalars(select(AuditEvent).where(AuditEvent.action == "auth.link_used")).one()
    assert used.details["sessions_ended"] == 1 and used.details["purpose"] == "reset"


def test_a_reset_clears_a_lockout(links: ShiftSetup) -> None:
    with links.db() as db:
        ana = db.get(User, links.ids["ana"])
        assert ana is not None
        ana.failed_sign_ins, ana.locked_until = 7, utcnow() + timedelta(minutes=30)
        db.commit()
    assert _redeem(links, _token(links, "owner", "ana", "reset")) == 204
    with links.db() as db:
        ana = db.get(User, links.ids["ana"])
        assert ana is not None and ana.failed_sign_ins == 0 and ana.locked_until is None
    assert _signs_in(links, "ana", NEW_PASSWORD)


# --- AU10: the token exists only in the one answer ----------------------------------------


def test_the_token_is_never_stored_or_audited(links: ShiftSetup) -> None:
    token = _token(links, "owner", "newbie")
    with links.db() as db:
        stored = db.scalars(select(OneTimeToken)).one()
    # Only the hash is kept, and it is not the token's text.
    assert len(stored.token_hash) == 32 and token.encode() not in stored.token_hash
    assert _redeem(links, token) == 204
    with links.db() as db:
        entries = db.scalars(select(AuditEvent)).all()
        sessions = db.scalars(select(UserSession)).all()
    for entry in entries:
        text = str(entry.details)
        assert token not in text and stored.token_hash.hex() not in text
        assert NEW_PASSWORD not in text
    assert all(token.encode() not in s.token_hash for s in sessions)
    actions = [entry.action for entry in entries]
    assert "auth.link_created" in actions and "auth.link_used" in actions
