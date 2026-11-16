"""Company settings from the attacker's view: weakening a rule (AZ10, threat E7) and
reaching another company's settings (tenancy).

Each test asks what someone trying to loosen the rules actually gets: the value in force
afterwards, and whether anything was saved or recorded.
"""

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import Actor
from app.auth.passwords import PasswordRejected, check_password
from app.settings.models import CompanySetting
from app.settings.registry import SettingRejected, get_setting_def
from app.settings.service import (
    PASSWORD_MIN_LENGTH,
    TIME_OFF_REQUIRED_APPROVALS,
    change_setting,
    password_min_length,
    setting_value,
)
from tests.audit_data import AuditSetup
from tests.settings_data import companies

__all__ = ["companies"]  # the fixture, imported so pytest finds it here


@pytest.mark.parametrize(
    ("name", "weaker"),
    [
        (PASSWORD_MIN_LENGTH, 14),  # below the platform's 15
        (PASSWORD_MIN_LENGTH, 8),
        (PASSWORD_MIN_LENGTH, 0),
        (PASSWORD_MIN_LENGTH, -1),
        (TIME_OFF_REQUIRED_APPROVALS, 0),  # requests would go through unreviewed
    ],
)
def test_a_setting_cannot_be_made_weaker_than_the_platform(
    companies: AuditSetup, name: str, weaker: int
) -> None:
    with companies.session_for(companies.company_a) as db:
        with pytest.raises(SettingRejected, match="only be made stricter"):
            change_setting(db, name, weaker, actor=Actor.system())
        db.commit()
    # Nothing saved, nothing recorded, and the platform's rule still applies.
    with companies.session_for(companies.company_a) as db:
        assert db.scalars(select(CompanySetting)).all() == []
        assert setting_value(db, name) == get_setting_def(name).default
    assert companies.events(companies.company_a) == []


@pytest.mark.parametrize("value", [65, 129, 10**9])
def test_a_setting_cannot_go_past_the_platform_limit(companies: AuditSetup, value: int) -> None:
    """A minimum longer than 64 would lock people out of setting any password at all."""
    with (
        companies.session_for(companies.company_a) as db,
        pytest.raises(SettingRejected, match="limit of 64"),
    ):
        change_setting(db, PASSWORD_MIN_LENGTH, value, actor=Actor.system())


@pytest.mark.parametrize("value", ["8", 8.5, True, None])
def test_a_value_of_another_type_is_refused(companies: AuditSetup, value: object) -> None:
    with (
        companies.session_for(companies.company_a) as db,
        pytest.raises(SettingRejected, match="whole number"),
    ):
        change_setting(db, PASSWORD_MIN_LENGTH, value, actor=Actor.system())


@pytest.mark.parametrize("stored", [8, "8", None, {"min": 8}, 1000])
def test_a_weak_value_written_straight_into_the_table_is_ignored(
    companies: AuditSetup, stored: object
) -> None:
    """Someone with database access writes a weaker value around the application: the
    rule stays the platform's (the stored value is checked on every read too)."""
    with companies.session_for(companies.company_a) as db:
        db.add(CompanySetting(module="auth", setting_key="password_min_length", value=stored))
        db.commit()
    with companies.session_for(companies.company_a) as db:
        assert password_min_length(db) == 15
        # So a short password is still refused in this company.
        with pytest.raises(PasswordRejected, match="at least 15"):
            check_password(
                "short password",
                company_name="Northwind Cafe",
                email="ana@northwind.example",
                display_name="Ana",
                min_length=password_min_length(db),
            )


def test_one_companys_setting_never_applies_to_another(companies: AuditSetup) -> None:
    with companies.session_for(companies.company_a) as db:
        change_setting(db, PASSWORD_MIN_LENGTH, 30, actor=Actor.system())
        db.commit()
    with companies.session_for(companies.company_b) as db:
        # Company B neither sees A's row nor gets A's value.
        assert db.scalars(select(CompanySetting)).all() == []
        assert password_min_length(db) == 15
        # And B changing its own setting leaves A's alone.
        change_setting(db, PASSWORD_MIN_LENGTH, 20, actor=Actor.system())
        db.commit()
    with companies.session_for(companies.company_a) as db:
        assert password_min_length(db) == 30
    # Each change is in its own company's audit chain only.
    assert [e.details["new"] for e in companies.events(companies.company_a)] == [30]
    assert [e.details["new"] for e in companies.events(companies.company_b)] == [20]


def test_platform_code_cannot_read_a_setting(companies: AuditSetup) -> None:
    """Without a company the filter is off, so "the" setting would be any company's."""
    with companies.session_for(companies.company_a) as db:
        change_setting(db, PASSWORD_MIN_LENGTH, 30, actor=Actor.system())
        db.commit()
    with Session(companies.engine) as platform:
        with pytest.raises(RuntimeError, match="one company"):
            password_min_length(platform)
        with pytest.raises(RuntimeError, match="one company"):
            change_setting(platform, PASSWORD_MIN_LENGTH, 40, actor=Actor.system())


def test_the_company_minimum_applies_to_new_passwords(companies: AuditSetup) -> None:
    with companies.session_for(companies.company_a) as db:
        change_setting(db, PASSWORD_MIN_LENGTH, 30, actor=Actor.system())
        db.commit()
        minimum = password_min_length(db)
    rules = {"company_name": "Northwind Cafe", "email": "ana@n.example", "display_name": "Ana"}
    # 26 characters: fine on the platform's 15, refused under the company's 30.
    check_password("a calm river bends at dusk", **rules)
    with pytest.raises(PasswordRejected, match="at least 30"):
        check_password("a calm river bends at dusk", **rules, min_length=minimum)


@pytest.mark.parametrize(("passed", "applied"), [(0, 15), (8, 15), (64, 64), (500, 64)])
def test_check_password_keeps_any_minimum_within_the_platform_rules(
    passed: int, applied: int
) -> None:
    """Even a wrong number passed straight to check_password cannot weaken the rule, nor
    ask for more than the platform's highest minimum."""
    rules = {"company_name": "Northwind Cafe", "email": "ana@n.example", "display_name": "Ana"}
    with pytest.raises(PasswordRejected, match=f"at least {applied} characters"):
        check_password("x" * (applied - 1), **rules, min_length=passed)
    check_password("a calm river bends at dusk " + "y" * (applied - 26), **rules, min_length=passed)
