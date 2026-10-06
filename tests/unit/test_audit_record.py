"""Writing audit entries (app/audit/record.py): numbering, links, signatures, transactions.

The attacks (forging, tampering, logging secrets, writing into another company's chain)
are in tests/security/test_audit_log.py.
"""

import hashlib
import hmac
import uuid
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.audit import Actor, AuditError, record
from app.audit.models import NO_SIGNATURE, PLATFORM_CHAIN_ID, AuditChainHead, AuditEvent
from app.audit.signing import canonical_json
from app.core.config import Settings
from app.db.base import Base
from app.modules.org.models import Company
from tests.audit_data import TABLES, TEST_KEY, TEST_KEY_ID, AuditSetup, audit, use_key

__all__ = ["audit"]  # the fixture, imported so pytest finds it here

USER = uuid.uuid4()


def write(setup: AuditSetup, company_id: uuid.UUID | None, count: int) -> None:
    """Record `count` entries in one company's session (or the platform's), and commit."""
    actor = Actor.user(USER) if company_id is not None else Actor.system()
    with setup.session_for(company_id) as session:
        for number in range(count):
            record(session, actor=actor, action="test.happened", details={"n": number})
        session.commit()


def test_entries_are_numbered_and_linked(audit: AuditSetup) -> None:
    write(audit, audit.company_a, 3)
    events = audit.events(audit.company_a)

    # Numbered 1, 2, 3 with no gaps.
    assert [e.seq for e in events] == [1, 2, 3]
    # The first links to "no signature yet"; each later one to the entry before it.
    assert events[0].prev_signature == NO_SIGNATURE
    assert events[1].prev_signature == events[0].signature
    assert events[2].prev_signature == events[1].signature


def test_each_signature_is_hmac_sha256_over_the_entry_and_the_previous_link(
    audit: AuditSetup,
) -> None:
    write(audit, audit.company_a, 2)

    # Recomputed from the stored rows, exactly as verification (#58) will do it.
    for event in audit.events(audit.company_a):
        expected = hmac.new(
            TEST_KEY.encode(), canonical_json(event) + event.prev_signature, hashlib.sha256
        ).digest()
        assert event.signature == expected
        assert event.key_id == TEST_KEY_ID


def test_the_head_points_at_the_newest_entry(audit: AuditSetup) -> None:
    write(audit, audit.company_a, 2)
    with audit.session_for(None) as platform:
        head = platform.get(AuditChainHead, audit.company_a)
    assert head is not None
    newest = audit.events(audit.company_a)[-1]
    assert (head.last_seq, head.last_signature) == (2, newest.signature)
    assert head.company_id == audit.company_a


def test_each_company_has_its_own_chain_and_platform_code_uses_the_platform_chain(
    audit: AuditSetup,
) -> None:
    write(audit, audit.company_a, 2)
    write(audit, audit.company_b, 1)
    write(audit, None, 1)

    # Every chain starts at 1, independently of the others.
    assert [e.seq for e in audit.events(audit.company_a)] == [1, 2]
    assert [e.seq for e in audit.events(audit.company_b)] == [1]
    platform = audit.events(PLATFORM_CHAIN_ID)
    assert [(e.seq, e.company_id, e.actor_type, e.actor_id) for e in platform] == [
        (1, None, "system", None)
    ]


def test_canonical_json_is_fixed_and_sorted(audit: AuditSetup) -> None:
    with audit.session_for(audit.company_a) as session:
        event = record(
            session,
            actor=Actor.user(USER),
            action="test.happened",
            details={"zeta": 1, "alpha": "é"},
        )
        text = canonical_json(event).decode("utf-8")
    # Sorted keys at every level, no spaces, letters as UTF-8, and a timestamp with
    # microseconds and a Z.
    assert '"details":{"alpha":"é","zeta":1}' in text
    assert " " not in text
    assert text.startswith('{"action":"test.happened","actor_id":')
    assert event.occurred_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ") in text


def test_an_action_that_fails_leaves_no_entry(audit: AuditSetup) -> None:
    # The action and its entry are in one transaction: when the action fails (here the
    # transaction is rolled back), the entry goes with it, and the head is unchanged.
    write(audit, audit.company_a, 1)
    with audit.session_for(audit.company_a) as session:
        session.get(Company, audit.company_a).name = "Renamed"  # type: ignore[union-attr]
        record(session, actor=Actor.user(USER), action="company.renamed")
        session.rollback()

    assert [e.seq for e in audit.events(audit.company_a)] == [1]
    with audit.session_for(None) as platform:
        assert platform.get(AuditChainHead, audit.company_a).last_seq == 1  # type: ignore[union-attr]
        assert platform.get(Company, audit.company_a).name == "Northwind Cafe"  # type: ignore[union-attr]


def test_record_never_commits(audit: AuditSetup) -> None:
    # Closing the session without commit keeps nothing: committing is the caller's job.
    with audit.session_for(audit.company_a) as session:
        record(session, actor=Actor.user(USER), action="test.happened")
    with audit.session_for(None) as platform:
        assert platform.scalar(select(func.count(AuditEvent.id))) == 0


def test_without_a_signing_key_nothing_is_written(
    audit: AuditSetup, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    use_key(monkeypatch, tmp_path, None)
    with audit.session_for(audit.company_a) as session, pytest.raises(AuditError, match="KEY"):
        record(session, actor=Actor.user(USER), action="test.happened")


@pytest.mark.parametrize("action", ["", "nodot", "Shift.Assigned", "shift.", "shift..x"])
def test_actions_must_be_dotted_lowercase_names(audit: AuditSetup, action: str) -> None:
    with audit.session_for(audit.company_a) as session, pytest.raises(AuditError):
        record(session, actor=Actor.user(USER), action=action)


@pytest.mark.parametrize(
    "details",
    [{"amount": 1.5}, {"list": [0.1]}, {"when": object()}, {"big": 2**64}, {"small": -(2**63) - 1}],
)
def test_details_take_only_values_that_sign_the_same_way_later(
    audit: AuditSetup, details: dict[str, object]
) -> None:
    # A decimal number might come back from the database written differently (1.0 as 1),
    # which would change the signed bytes.
    with audit.session_for(audit.company_a) as session, pytest.raises(AuditError):
        record(session, actor=Actor.user(USER), action="test.happened", details=details)


def test_the_entry_keeps_what_was_signed_even_if_the_caller_changes_its_details(
    audit: AuditSetup,
) -> None:
    details = {"changes": {"name": "before"}}
    with audit.session_for(audit.company_a) as session:
        event = record(session, actor=Actor.user(USER), action="test.happened", details=details)
        details["changes"]["name"] = "changed afterwards"
        assert event.details == {"changes": {"name": "before"}}


def test_a_session_with_an_old_copy_of_the_head_still_numbers_correctly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Two real connections (a database file): session `stale` reads the head, another
    # session adds an entry meanwhile, then `stale` records. It must number after the
    # newest entry (3), not reuse 2 from its old copy of the head.
    use_key(monkeypatch, tmp_path, TEST_KEY)
    engine = create_engine(f"sqlite:///{(tmp_path / 'audit.db').as_posix()}")
    Base.metadata.create_all(engine, tables=TABLES)
    with Session(engine) as platform:
        company = Company(name="Northwind Cafe", timezone="America/Chicago")
        platform.add(company)
        platform.commit()
        company_id = company.id
    setup = AuditSetup(engine, company_id, company_id)
    write(setup, company_id, 1)

    with setup.session_for(company_id) as stale:
        # Kept in a variable: the session only remembers objects something still uses.
        old_head = stale.get(AuditChainHead, company_id)
        assert old_head is not None and old_head.last_seq == 1
        write(setup, company_id, 1)
        seq = record(stale, actor=Actor.user(USER), action="test.happened").seq
        stale.commit()
    assert seq == 3
    assert [e.seq for e in setup.events(company_id)] == [1, 2, 3]
    engine.dispose()


def test_actors_follow_the_rules() -> None:
    # The system has no ID; everyone else needs one; nothing else can act.
    with pytest.raises(AuditError):
        Actor("system", uuid.uuid4())
    with pytest.raises(AuditError):
        Actor("user")
    with pytest.raises(AuditError):
        Actor("admin", uuid.uuid4())


def test_a_persons_action_needs_a_company_session(audit: AuditSetup) -> None:
    # A person always belongs to a company; their action never goes to the platform chain.
    with audit.session_for(None) as session, pytest.raises(AuditError, match="company"):
        record(session, actor=Actor.user(USER), action="test.happened")


def test_the_signing_key_must_be_long_enough() -> None:
    with pytest.raises(ValidationError):
        Settings(database_url="sqlite://", audit_signing_key="too-short")  # type: ignore[arg-type]
