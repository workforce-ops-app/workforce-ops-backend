"""The reporting chain against misuse (authorization.md, the reporting chain; threats E3, E4;
rules AZ5, AZ6).

Being above someone decides WHOM a person permission may act on. Each test tries to act on
someone the chain does not put below you: a peer, a superior, someone whose line has
ended, someone in another company, or someone only reachable through a loop. The people
come from tests/authz_data.py; each test adds the reporting lines it needs.
"""

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.audit import Actor
from app.audit.models import AuditEvent
from app.authz.chain import ReportingLineError, add_reporting_line, is_above_in_chain, people_below
from app.authz.check import Forbidden, authorize, scope_filter
from app.authz.models import ReportingLine
from app.authz.scope import ScopeColumns
from app.db.base import utcnow
from app.modules.org.models import User
from tests.authz_data import Org, org

__all__ = ["org"]  # the fixture, imported so pytest finds it here


def lines(org: Org, *pairs: tuple[str, str]) -> None:
    """Add reporting lines in company A, each (manager, employee), through the service."""
    with org.a() as db:
        for manager, employee in pairs:
            add_reporting_line(
                db, Actor.system(), manager_id=org.ids[manager], employee_id=org.ids[employee]
            )
        db.commit()


def allowed(org: Org, who: str, code: str, target: str) -> bool:
    """Whether authorize() lets this person of company A act on that one."""
    with org.a() as db:
        try:
            authorize(db, org.user(db, who), code, org.user(db, target))
        except Forbidden:
            return False
        return True


def above(org: Org, who: str, target: str) -> bool:
    with org.a() as db:
        return is_above_in_chain(db, org.ids[who], org.ids[target])


# --- Who is above whom -------------------------------------------------------------------


def test_a_direct_manager_may_act_on_their_report(org: Org) -> None:
    # Chef manages the Kitchen and may review time off there; Ana is in the Kitchen. Without
    # a line chef is refused (test_authorization.py); with one, chef is above her.
    assert not allowed(org, "chef", "time_off.review", "ana")
    lines(org, ("chef", "ana"))
    assert allowed(org, "chef", "time_off.review", "ana")


def test_the_chain_reaches_more_than_one_level(org: Org) -> None:
    # admin -> chef -> ana: the administrator is above Ana through chef.
    lines(org, ("admin", "chef"), ("chef", "ana"))
    assert above(org, "admin", "ana")
    assert allowed(org, "admin", "user.manage", "ana")


def test_peers_are_not_above_each_other(org: Org) -> None:
    # Chef and lead both report to the administrator: neither is above the other (E3).
    lines(org, ("admin", "chef"), ("admin", "lead"))
    assert not above(org, "chef", "lead")
    assert not above(org, "lead", "chef")


def test_nobody_is_above_their_own_manager(org: Org) -> None:
    lines(org, ("admin", "chef"), ("chef", "ana"))
    assert not above(org, "chef", "admin")
    assert not above(org, "ana", "admin")
    assert not allowed(org, "chef", "time_off.review", "admin")


def test_someone_with_two_managers_is_below_both(org: Org) -> None:
    lines(org, ("lead", "ben"), ("mentor", "ben"))
    assert above(org, "lead", "ben")
    assert above(org, "mentor", "ben")


def test_being_above_grants_nothing_by_itself(org: Org) -> None:
    # Ana is above Ben here, but holds no person permission at all.
    lines(org, ("ana", "ben"))
    assert above(org, "ana", "ben")
    assert not allowed(org, "ana", "time_off.review", "ben")
    assert not allowed(org, "ana", "user.manage", "ben")


def test_being_above_does_not_widen_the_scope(org: Org) -> None:
    # The lead manages the Weekend Crew only. Being above Ana (Kitchen, not on the crew)
    # does not let the lead review her time off: scope AND position are both needed.
    lines(org, ("lead", "ana"))
    assert above(org, "lead", "ana")
    assert not allowed(org, "lead", "time_off.review", "ana")


def test_an_ended_line_no_longer_counts(org: Org) -> None:
    lines(org, ("chef", "ana"))
    with org.a() as db:
        line = db.scalars(select(ReportingLine)).one()
        line.ended_at = utcnow()
        db.commit()
    assert not above(org, "chef", "ana")
    assert not allowed(org, "chef", "time_off.review", "ana")


def test_a_deactivated_manager_is_above_nobody_but_keeps_the_chain(org: Org) -> None:
    # admin -> chef -> ana, then chef is deactivated. Chef may do nothing any more, but the
    # administrator is still above Ana, so she is not cut off from everyone but the Owner.
    lines(org, ("admin", "chef"), ("chef", "ana"))
    with org.a() as db:
        org.user(db, "chef").deactivated_at = utcnow()
        db.commit()
    assert not allowed(org, "chef", "time_off.review", "ana")
    assert allowed(org, "admin", "user.manage", "ana")


# --- Adding lines: the data rules ---------------------------------------------------------


def test_nobody_reports_to_themselves(org: Org) -> None:
    with org.a() as db, pytest.raises(ReportingLineError):
        add_reporting_line(
            db, Actor.system(), manager_id=org.ids["ana"], employee_id=org.ids["ana"]
        )


def test_the_database_also_refuses_a_line_to_yourself(org: Org) -> None:
    # Even past the service: the CHECK constraint on the table itself.
    with org.a() as db:
        db.add(ReportingLine(manager_id=org.ids["ana"], employee_id=org.ids["ana"]))
        with pytest.raises(IntegrityError):
            db.flush()


def test_a_line_that_would_make_a_loop_is_refused(org: Org) -> None:
    # admin -> chef -> ana; Ana may not become the administrator's manager (E4).
    lines(org, ("admin", "chef"), ("chef", "ana"))
    with org.a() as db, pytest.raises(ReportingLineError):
        add_reporting_line(
            db, Actor.system(), manager_id=org.ids["ana"], employee_id=org.ids["admin"]
        )


def test_the_same_current_line_cannot_be_added_twice(org: Org) -> None:
    lines(org, ("chef", "ana"))
    with org.a() as db, pytest.raises(ReportingLineError):
        add_reporting_line(
            db, Actor.system(), manager_id=org.ids["chef"], employee_id=org.ids["ana"]
        )


def test_adding_a_line_writes_an_audit_entry(org: Org) -> None:
    lines(org, ("chef", "ana"))
    with org.a() as db:
        entry = db.scalars(
            select(AuditEvent).where(AuditEvent.action == "reporting_line.added")
        ).one()
        assert entry.details == {
            "manager_id": str(org.ids["chef"]),
            "employee_id": str(org.ids["ana"]),
        }


def test_a_loop_that_slipped_in_still_ends_the_walk(org: Org) -> None:
    # Two lines added straight to the database, past the loop check: chef <-> ana. The walk
    # must still end (UNION drops people already found) and never count you above yourself.
    with org.a() as db:
        db.add(ReportingLine(manager_id=org.ids["chef"], employee_id=org.ids["ana"]))
        db.add(ReportingLine(manager_id=org.ids["ana"], employee_id=org.ids["chef"]))
        db.commit()
        assert people_below(db, org.ids["chef"]) == {org.ids["ana"]}
    assert not allowed(org, "chef", "user.manage", "chef")


# --- Companies ---------------------------------------------------------------------------


def test_a_chain_never_reaches_into_another_company(org: Org) -> None:
    # The lines are in company A. Asked from a session for company B, the same people are
    # nowhere in the chain: the company filter limits every step of the walk.
    lines(org, ("admin", "chef"), ("chef", "ana"))
    with org.session(org.company_b) as db:
        assert not is_above_in_chain(db, org.ids["admin"], org.ids["ana"])
        assert people_below(db, org.ids["admin"]) == set()


# Lines that join people of two companies are refused by the database itself:
# tests/security/test_org_company_links.py.


# --- Lists: the scope filter matches authorize() ------------------------------------------


def visible(org: Org, who: str, code: str) -> set[str]:
    with org.a() as db:
        user = org.user(db, who)
        condition = scope_filter(db, user, code, ScopeColumns(User.department_id, User.id))
        return set(db.scalars(select(User.display_name).where(condition)))


def test_a_manager_lists_only_the_people_below_them(org: Org) -> None:
    lines(org, ("admin", "chef"), ("chef", "ana"), ("admin", "lead"))
    # Company-wide scope, so everyone below: chef, ana (through chef), and lead.
    assert visible(org, "admin", "user.manage") == {"chef", "ana", "lead"}
    # Kitchen scope, and only Ana is below chef.
    assert visible(org, "chef", "time_off.review") == {"ana"}


@pytest.mark.parametrize("code", ["user.manage", "time_off.review", "role.assign"])
def test_the_list_filter_agrees_with_authorize_along_the_chain(org: Org, code: str) -> None:
    # A chain with two levels, two managers for one person, and a peer, so every kind of
    # pair occurs; a list must never show someone a direct request would refuse.
    lines(
        org,
        ("admin", "chef"),
        ("chef", "ana"),
        ("admin", "lead"),
        ("lead", "ben"),
        ("mentor", "ben"),
    )
    names = ["owner", "admin", "chef", "lead", "ana", "ben", "relic", "mentor"]
    for who in names:
        listed = visible(org, who, code)
        for name in names:
            assert (name in listed) == allowed(org, who, code, name), (who, name)


def test_unknown_people_are_below_nobody(org: Org) -> None:
    with org.a() as db:
        assert not is_above_in_chain(db, org.ids["admin"], uuid.uuid4())
