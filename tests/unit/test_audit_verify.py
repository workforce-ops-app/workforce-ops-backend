"""Verifying an audit chain (app/audit/verify.py) and the nightly check of every chain
(app/modules/audit_log/service.py). Threats R1, T2, P4; audit-log.md, verification.

Each test changes the database the way someone with direct access could (editing,
removing, inserting, or cutting off entries) and checks that verification notices, and
names the right entry.
"""

import hashlib
import hmac
import json
import logging
import uuid
from pathlib import Path

import pytest
from sqlalchemy import delete, select, update

from app.audit import Actor, AuditError, record
from app.audit.models import PLATFORM_CHAIN_ID, AuditChainHead, AuditEvent
from app.audit.signing import canonical_json
from app.audit.verify import available_keys, verify_chain
from app.core.config import get_settings
from app.modules.audit_log.service import CHAIN_BROKEN, verify_every_chain
from app.modules.security.models import PlatformSecurityEvent
from tests.audit_data import TEST_KEY, TEST_KEY_ID, AuditSetup, audit, use_key

__all__ = ["audit"]  # the fixture, imported so pytest finds it here

USER = uuid.uuid4()


def write(setup: AuditSetup, company_id: uuid.UUID | None, count: int = 3) -> None:
    """Add `count` entries to a company's chain (or the platform's, for None)."""
    with setup.session_for(company_id) as session:
        actor = Actor.user(USER) if company_id is not None else Actor.system()
        for n in range(count):
            record(session, actor=actor, action="shift.created", details={"n": n})
        session.commit()


def check(setup: AuditSetup, chain_id: uuid.UUID):  # type: ignore[no-untyped-def]
    with setup.session_for(None) as session:
        return verify_chain(session, chain_id, available_keys())


def tamper(setup: AuditSetup, *statements: object) -> None:
    """Change the tables directly, as someone with database access could."""
    with setup.session_for(None) as session:
        for statement in statements:
            session.execute(statement)  # type: ignore[call-overload]
        session.commit()


def entry(chain_id: uuid.UUID, seq: int):  # type: ignore[no-untyped-def]
    return (AuditEvent.chain_id == chain_id) & (AuditEvent.seq == seq)


# --- What an untouched chain gives ------------------------------------------------------


def test_an_untouched_chain_checks_out(audit: AuditSetup) -> None:
    write(audit, audit.company_a)
    result = check(audit, audit.company_a)
    assert (result.ok, result.checked, result.last_seq) == (True, 3, 3)
    assert result.first_bad_seq is None and result.problem is None


def test_a_chain_with_nothing_recorded_yet_checks_out(audit: AuditSetup) -> None:
    result = check(audit, audit.company_a)
    assert (result.ok, result.checked, result.last_seq) == (True, 0, 0)


# --- Edited, removed, inserted ----------------------------------------------------------


def test_an_edited_entry_is_named(audit: AuditSetup) -> None:
    write(audit, audit.company_a)
    tamper(
        audit,
        update(AuditEvent).where(entry(audit.company_a, 2)).values(details={"n": "never"}),
    )
    result = check(audit, audit.company_a)
    assert not result.ok and result.first_bad_seq == 2 and result.checked == 1
    assert "changed" in (result.problem or "")


def test_a_changed_actor_is_detected_too(audit: AuditSetup) -> None:
    """Every signed field counts, not only details: here, who did it."""
    write(audit, audit.company_a)
    tamper(audit, update(AuditEvent).where(entry(audit.company_a, 1)).values(actor_id=uuid.uuid4()))
    assert check(audit, audit.company_a).first_bad_seq == 1


def test_a_removed_entry_is_named(audit: AuditSetup) -> None:
    write(audit, audit.company_a)
    tamper(audit, delete(AuditEvent).where(entry(audit.company_a, 2)))
    result = check(audit, audit.company_a)
    assert not result.ok and result.first_bad_seq == 2
    assert result.problem == "entry 2 is missing"


def test_an_inserted_entry_is_named(audit: AuditSetup) -> None:
    """Someone moves entries 2 and 3 up by one and puts their own entry at 2, linked to
    entry 1 and "signed" with what they can compute without the key."""
    write(audit, audit.company_a)
    with audit.session_for(None) as session:
        # One at a time from the top, so no two entries ever share a number.
        for seq in (3, 2):
            session.execute(
                update(AuditEvent).where(entry(audit.company_a, seq)).values(seq=seq + 1)
            )
        first = session.scalars(select(AuditEvent).where(entry(audit.company_a, 1))).one()
        forged = AuditEvent(
            id=uuid.uuid4(),
            chain_id=audit.company_a,
            seq=2,
            company_id=audit.company_a,
            actor_type="user",
            actor_id=USER,
            action="role.permission_added",
            occurred_at=first.occurred_at,
            details={},
            key_id=TEST_KEY_ID,
            prev_signature=first.signature,
        )
        forged.signature = hmac.new(
            b"guessed-key", canonical_json(forged) + first.signature, hashlib.sha256
        ).digest()
        session.add(forged)
        session.execute(
            update(AuditChainHead)
            .where(AuditChainHead.chain_id == audit.company_a)
            .values(last_seq=4)
        )
        session.commit()
    result = check(audit, audit.company_a)
    assert not result.ok and result.first_bad_seq == 2 and result.checked == 1


# --- The end of the chain ---------------------------------------------------------------


def test_removing_the_newest_entries_is_detected_by_the_head(audit: AuditSetup) -> None:
    """Entries 1 to 3 still check out one by one; only the head knows there were 5."""
    write(audit, audit.company_a, count=5)
    tamper(
        audit,
        delete(AuditEvent).where(AuditEvent.chain_id == audit.company_a, AuditEvent.seq > 3),
    )
    result = check(audit, audit.company_a)
    assert not result.ok and result.checked == 3
    # The seq the head expected to find.
    assert result.first_bad_seq == 5 and result.last_seq == 5
    assert result.problem == "the chain ends at entry 3, but its head expects 5"


def test_a_head_pointing_at_another_signature_is_detected(audit: AuditSetup) -> None:
    write(audit, audit.company_a)
    tamper(
        audit,
        update(AuditChainHead)
        .where(AuditChainHead.chain_id == audit.company_a)
        .values(last_signature=bytes(range(32))),
    )
    result = check(audit, audit.company_a)
    assert not result.ok and result.first_bad_seq == 3


def test_an_entry_past_the_head_is_detected(audit: AuditSetup) -> None:
    """The head moved back by one (as if entry 3 never happened), the entry left in place."""
    write(audit, audit.company_a)
    with audit.session_for(None) as session:
        second = session.scalars(select(AuditEvent).where(entry(audit.company_a, 2))).one()
        session.execute(
            update(AuditChainHead)
            .where(AuditChainHead.chain_id == audit.company_a)
            .values(last_seq=2, last_signature=second.signature)
        )
        session.commit()
    result = check(audit, audit.company_a)
    assert not result.ok and result.first_bad_seq == 3


def test_entries_without_a_head_are_detected(audit: AuditSetup) -> None:
    write(audit, audit.company_a)
    # The head's foreign key is not enforced on SQLite by default; MySQL would refuse
    # this, but verification must not rely on it.
    tamper(audit, delete(AuditChainHead).where(AuditChainHead.chain_id == audit.company_a))
    result = check(audit, audit.company_a)
    assert not result.ok and result.first_bad_seq == 1


# --- Keys -------------------------------------------------------------------------------


def test_entries_signed_with_an_older_key_still_check_out(
    audit: AuditSetup, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(audit, audit.company_a, count=2)
    # The key is rotated: a new key and ID, the old one kept for checking only.
    monkeypatch.setenv("AUDIT_SIGNING_KEY", "a-new-key-after-rotation-0123456789-abc")
    monkeypatch.setenv("AUDIT_KEY_ID", "test-2")
    monkeypatch.setenv("AUDIT_PREVIOUS_KEYS", json.dumps({TEST_KEY_ID: TEST_KEY}))
    get_settings.cache_clear()
    write(audit, audit.company_a, count=1)  # entry 3, signed with the new key
    result = check(audit, audit.company_a)
    assert result.ok and result.checked == 3

    # Without the old key, the first old entry cannot be checked: a failure, not a pass.
    monkeypatch.delenv("AUDIT_PREVIOUS_KEYS")
    get_settings.cache_clear()
    result = check(audit, audit.company_a)
    assert not result.ok and result.first_bad_seq == 1
    assert "not available" in (result.problem or "")
    # Named by ID only; the key itself never appears.
    assert TEST_KEY not in (result.problem or "")


def test_no_key_means_no_check(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    use_key(monkeypatch, tmp_path, None)
    with pytest.raises(AuditError):
        available_keys()
    get_settings.cache_clear()


# --- One chain at a time ----------------------------------------------------------------


def test_one_companys_damage_does_not_show_in_anothers_check(audit: AuditSetup) -> None:
    write(audit, audit.company_a)
    write(audit, audit.company_b)
    tamper(audit, delete(AuditEvent).where(entry(audit.company_b, 2)))
    assert check(audit, audit.company_a).ok
    assert check(audit, audit.company_b).first_bad_seq == 2


# --- The nightly check ------------------------------------------------------------------


def test_the_nightly_check_covers_every_chain_and_copies_the_heads(
    audit: AuditSetup, caplog: pytest.LogCaptureFixture
) -> None:
    PlatformSecurityEvent.__table__.create(audit.engine)  # type: ignore[attr-defined]
    write(audit, audit.company_a)
    write(audit, audit.company_b)
    write(audit, None, count=1)
    tamper(audit, delete(AuditEvent).where(entry(audit.company_b, 3)))
    with audit.session_for(None) as session:
        heads = {h.chain_id: h.last_signature for h in session.scalars(select(AuditChainHead))}

    with caplog.at_level(logging.INFO, logger="app.modules.audit_log.service"):
        results = {r.chain_id: r for r in verify_every_chain(audit.engine)}

    assert set(results) == {audit.company_a, audit.company_b, PLATFORM_CHAIN_ID}
    assert results[audit.company_a].ok and results[PLATFORM_CHAIN_ID].ok
    assert results[audit.company_b].first_bad_seq == 3

    # Every chain's head, as it was, is in the log (the outside copy).
    copies = {
        r.fields["chain_id"]: r.fields  # type: ignore[attr-defined]
        for r in caplog.records
        if r.getMessage() == "audit chain head"
    }
    for chain_id, signature in heads.items():
        assert copies[str(chain_id)]["last_signature"] == signature.hex()
    # The failure is logged, with the chain and the entry.
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert [r.fields["chain_id"] for r in errors] == [str(audit.company_b)]  # type: ignore[attr-defined]

    # Each check is recorded in the chain it checked, by the system.
    for chain_id in results:
        events = audit.events(chain_id)
        last = events[-1]
        assert last.action == "audit.verified" and last.actor_type == "system"
        assert last.details["nightly"] is True
        assert last.details["ok"] is (chain_id != audit.company_b)

    # The failure is a platform security event that names no company.
    with audit.session_for(None) as session:
        rows = list(session.scalars(select(PlatformSecurityEvent)))
    assert [row.kind for row in rows] == [CHAIN_BROKEN]
    assert str(audit.company_b) not in (rows[0].excerpt or "")


def test_the_next_nights_check_still_finds_the_damage(audit: AuditSetup) -> None:
    """Recording a check adds to a broken chain, but never repairs it."""
    PlatformSecurityEvent.__table__.create(audit.engine)  # type: ignore[attr-defined]
    write(audit, audit.company_a)
    tamper(audit, update(AuditEvent).where(entry(audit.company_a, 1)).values(action="x.y"))
    verify_every_chain(audit.engine)
    again = {r.chain_id: r for r in verify_every_chain(audit.engine)}
    assert again[audit.company_a].first_bad_seq == 1
