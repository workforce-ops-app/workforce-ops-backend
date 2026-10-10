"""The audit log against tampering, forgery, leaked secrets, and crossing companies.

Threats R1 (an action nobody can be held to) and T2 (editing the database directly),
decision 0018. Until T2 (#43) gives the application insert-only rights, the
application's database user can still change rows; these tests show that every such
change is detectable, and that a valid-looking entry cannot be made without the key.
"""

import hashlib
import hmac
import uuid

import pytest
from sqlalchemy import update

from app.audit import Actor, AuditError, record
from app.audit.models import AuditEvent
from app.audit.signing import canonical_json, sign
from tests.audit_data import TEST_KEY, AuditSetup, audit

__all__ = ["audit"]  # the fixture, imported so pytest finds it here

USER = uuid.uuid4()


def chain_is_intact(events: list[AuditEvent]) -> bool:
    """What verification (#58) will check: numbering, links, and every signature."""
    previous = bytes(32)
    for number, event in enumerate(events, start=1):
        if event.seq != number or event.prev_signature != previous:
            return False
        if event.signature != sign(TEST_KEY.encode(), event, event.prev_signature):
            return False
        previous = event.signature
    return True


def write(setup: AuditSetup, company_id: uuid.UUID, actions: list[str]) -> None:
    with setup.session_for(company_id) as session:
        for action in actions:
            record(session, actor=Actor.user(USER), action=action, details={"shift": "9-5"})
        session.commit()


def test_an_untouched_chain_checks_out(audit: AuditSetup) -> None:
    write(audit, audit.company_a, ["shift.created", "shift.assigned", "shift.cancelled"])
    assert chain_is_intact(audit.events(audit.company_a))


def test_editing_an_entry_in_the_database_is_detected(audit: AuditSetup) -> None:
    write(audit, audit.company_a, ["shift.created", "shift.assigned", "shift.cancelled"])
    # Someone with database access rewrites what happened in entry 2.
    with audit.session_for(None) as session:
        session.execute(
            update(AuditEvent)
            .where(AuditEvent.chain_id == audit.company_a, AuditEvent.seq == 2)
            .values(details={"shift": "never assigned"})
        )
        session.commit()
    assert not chain_is_intact(audit.events(audit.company_a))


def test_removing_an_entry_is_detected(audit: AuditSetup) -> None:
    write(audit, audit.company_a, ["shift.created", "shift.assigned", "shift.cancelled"])
    events = audit.events(audit.company_a)
    # Entry 2 left out: numbering and the link from entry 3 both break.
    assert not chain_is_intact([events[0], events[2]])


def test_a_plain_hash_cannot_repair_an_edited_chain(audit: AuditSetup) -> None:
    # Why a secret key: an attacker edits entry 2 and recomputes the "signatures" of
    # entries 2 and 3 with what they can compute without the key (a plain SHA-256, or an
    # HMAC with a guessed key). The chain still fails, because only the real key signs.
    write(audit, audit.company_a, ["shift.created", "shift.assigned", "shift.cancelled"])
    events = audit.events(audit.company_a)
    events[1].details = {"shift": "never assigned"}

    for forge in (
        lambda e, prev: hashlib.sha256(canonical_json(e) + prev).digest(),
        lambda e, prev: hmac.new(b"guessed-key", canonical_json(e) + prev, "sha256").digest(),
    ):
        events[1].signature = forge(events[1], events[1].prev_signature)
        events[2].prev_signature = events[1].signature
        events[2].signature = forge(events[2], events[2].prev_signature)
        assert not chain_is_intact(events)


def test_a_company_cannot_write_into_another_companys_chain(audit: AuditSetup) -> None:
    # The chain comes from the session's company; record() takes no company or chain from
    # the caller at all, so company A's actions always land in A's own chain.
    with audit.session_for(audit.company_a) as session:
        event = record(session, actor=Actor.user(USER), action="shift.created")
        session.commit()
        assert (event.chain_id, event.company_id) == (audit.company_a, audit.company_a)
    assert audit.events(audit.company_b) == []
    with pytest.raises(TypeError):
        record(  # type: ignore[call-arg]
            audit.session_for(audit.company_a),
            actor=Actor.user(USER),
            action="shift.created",
            company_id=audit.company_b,
        )


@pytest.mark.parametrize(
    "details",
    [
        {"password": "hunter2"},
        {"new_password_hash": "$argon2id$..."},
        {"reset": {"Token": "abc"}},
        {"changes": [{"api_secret": "x"}]},
    ],
)
def test_no_entry_can_contain_a_password_token_or_hash(
    audit: AuditSetup, details: dict[str, object]
) -> None:
    # Checked at every depth and in any case; refused before anything is written.
    with audit.session_for(audit.company_a) as session, pytest.raises(AuditError, match="never"):
        record(session, actor=Actor.user(USER), action="user.updated", details=details)
    assert audit.events(audit.company_a) == []
