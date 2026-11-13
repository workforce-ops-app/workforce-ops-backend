"""Verifying the audit log on demand, from the attacker's view (threats R1, T2, P4; rule
AZ5 for who may ask).

POST /api/audit/verify checks the signed-in person's own company's chain. These tests
show who may run it, that it can only ever check one's own company, what the answer
gives away, and that a failure leaves a trace.
"""

import uuid

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.audit.models import AuditEvent
from app.modules.audit_log.service import CHAIN_BROKEN
from app.modules.security.models import PlatformSecurityEvent, SecurityEvent
from tests.shift_data import ShiftSetup, shifts

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here

URL = "/api/audit/verify"


def _verified(setup: ShiftSetup, company_id: uuid.UUID) -> list[AuditEvent]:
    """The company's audit.verified entries, oldest first."""
    with Session(setup.engine) as db:
        return list(
            db.scalars(
                select(AuditEvent)
                .where(AuditEvent.chain_id == company_id, AuditEvent.action == "audit.verified")
                .order_by(AuditEvent.seq)
            )
        )


def _break(setup: ShiftSetup, company_id: uuid.UUID, seq: int = 2) -> None:
    """Edit one entry directly in the database."""
    with Session(setup.engine) as db:
        db.execute(
            update(AuditEvent)
            .where(AuditEvent.chain_id == company_id, AuditEvent.seq == seq)
            .values(details={"edited": True})
        )
        db.commit()


def test_an_owner_checks_the_companys_chain(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")
    answer = owner.post(URL)
    assert answer.status_code == 200
    body = answer.json()
    assert body["ok"] is True and body["first_bad_seq"] is None and body["problem"] is None
    # Every entry so far (the seed's roles and assignments, the sign-ins) was checked.
    assert body["checked"] == body["last_seq"] > 0
    # The check is recorded in the chain it checked, naming who ran it.
    [entry] = _verified(shifts, shifts.company_a)
    assert entry.actor_id == shifts.ids["owner"] and entry.details["ok"] is True


def test_the_answer_holds_only_the_result(shifts: ShiftSetup) -> None:
    """No signatures, keys, or entry contents: a result anyone allowed may see."""
    body = shifts.browser("owner").post(URL).json()
    assert set(body) == {"ok", "checked", "last_seq", "first_bad_seq", "problem"}


def test_without_audit_verify_the_answer_is_403_and_nothing_is_recorded(
    shifts: ShiftSetup,
) -> None:
    # A manager and an employee hold no audit.verify.
    for name in ("chef", "ana"):
        assert shifts.browser(name).post(URL).status_code == 403
    assert _verified(shifts, shifts.company_a) == []


def test_not_signed_in_is_401(shifts: ShiftSetup) -> None:
    from fastapi.testclient import TestClient

    stranger = TestClient(
        shifts.app, base_url="https://testserver", headers={"Origin": "https://testserver"}
    )  # type: ignore[arg-type]
    assert stranger.post(URL).status_code == 401


def test_a_check_needs_the_csrf_token(shifts: ShiftSetup) -> None:
    """It writes an audit entry, so a page on another site must not be able to start it."""
    owner = shifts.browser("owner")
    token = owner.headers.pop("X-CSRF-Token")
    try:
        assert owner.post(URL).status_code == 403
    finally:
        owner.headers["X-CSRF-Token"] = token
    assert _verified(shifts, shifts.company_a) == []


def test_a_broken_chain_is_reported_with_the_first_bad_entry(shifts: ShiftSetup) -> None:
    _break(shifts, shifts.company_a, seq=2)
    body = shifts.browser("owner").post(URL).json()
    assert body["ok"] is False and body["first_bad_seq"] == 2 and body["checked"] == 1
    # A security event in the company's own events, naming who found it.
    with shifts.db(shifts.company_a) as db:
        [event] = db.scalars(select(SecurityEvent).where(SecurityEvent.kind == CHAIN_BROKEN))
        assert event.user_id == shifts.ids["owner"]
        assert event.excerpt == "first bad entry 2"
    # Only in this company's events, and not as a platform event.
    with shifts.db(shifts.company_b) as db:
        assert list(db.scalars(select(SecurityEvent))) == []
    with Session(shifts.engine) as db:
        assert list(db.scalars(select(PlatformSecurityEvent))) == []


def test_only_the_own_company_is_ever_checked(shifts: ShiftSetup) -> None:
    """Company B's chain is broken; company A's owner cannot reach it in any way, and
    A's answer says nothing about it."""
    _break(shifts, shifts.company_b, seq=1)
    owner = shifts.browser("owner")
    # Whatever names B in the request is ignored: the chain is the session's company.
    for attempt in (
        owner.post(URL),
        owner.post(f"{URL}?chain_id={shifts.company_b}"),
        owner.post(URL, json={"chain_id": str(shifts.company_b)}),
    ):
        assert attempt.status_code == 200 and attempt.json()["ok"] is True
    # The checks went into A's chain only; B's chain got nothing.
    assert len(_verified(shifts, shifts.company_a)) == 3
    assert _verified(shifts, shifts.company_b) == []


def test_a_cut_off_chain_names_the_entry_the_head_expected(shifts: ShiftSetup) -> None:
    owner = shifts.browser("owner")  # signed in first: signing in adds entries too
    with Session(shifts.engine) as db:
        last = max(
            e.seq
            for e in db.scalars(select(AuditEvent).where(AuditEvent.chain_id == shifts.company_a))
        )
        db.execute(
            delete(AuditEvent).where(
                AuditEvent.chain_id == shifts.company_a, AuditEvent.seq > last - 2
            )
        )
        db.commit()
    body = owner.post(URL).json()
    assert body["ok"] is False and body["first_bad_seq"] == last
    assert body["checked"] == last - 2
