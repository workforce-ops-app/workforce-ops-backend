"""Company settings (app/settings): the registry's rules, defaults, and changes.

SQLite in memory with the companies, audit, and company_settings tables. The attacker's
view (weakening a setting, reading another company's) is in
tests/security/test_company_settings.py.
"""

import pytest
from sqlalchemy import select

from app.audit import Actor
from app.audit.models import AuditEvent
from app.auth.passwords import MAX_MIN_LENGTH, MIN_LENGTH
from app.settings import registry
from app.settings.models import CompanySetting
from app.settings.registry import SettingDef, SettingRejected, Stricter, check_declaration
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


# --- The registry ----------------------------------------------------------------------


def test_the_first_settings_and_their_platform_rules() -> None:
    found = {
        name: (s.default, s.limit, s.stricter.value) for name, s in registry.all_settings().items()
    }
    assert found == {
        # Decision 0025: 15 by default, a company may ask for up to 64.
        "auth.password_min_length": (MIN_LENGTH, MAX_MIN_LENGTH, "higher"),
        # time-off.md: 1 by default; more approvals are stricter.
        "time_off.required_approvals": (1, 5, "higher"),
    }
    assert (MIN_LENGTH, MAX_MIN_LENGTH) == (15, 64)


def test_modules_declare_their_own_settings() -> None:
    # The time-off setting comes from app/modules/time_off/settings.py.
    assert registry.get_setting_def(TIME_OFF_REQUIRED_APPROVALS).module == "time_off"


def test_an_unknown_setting_is_a_bug() -> None:
    with pytest.raises(LookupError, match="unknown setting"):
        registry.get_setting_def("auth.no_such_setting")


@pytest.mark.parametrize(
    ("declaration", "problem"),
    [
        # A limit on the weaker side would let a company go below the platform.
        (SettingDef("x", 10, 5, Stricter.HIGHER, "", "m"), "below its default"),
        (SettingDef("x", 10, 20, Stricter.LOWER, "", "m"), "above its default"),
        (SettingDef("Bad-Name", 1, 2, Stricter.HIGHER, "", "m"), "lowercase"),
        (SettingDef("x", 1, 2, Stricter.HIGHER, "", "m" * 51), "up to 50"),
        (SettingDef("x" * 81, 1, 2, Stricter.HIGHER, "", "m"), "up to 80"),
    ],
)
def test_declarations_must_follow_the_rules(declaration: SettingDef, problem: str) -> None:
    with pytest.raises(ValueError, match=problem):
        check_declaration(declaration)


def test_a_setting_declared_twice_stops_the_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    twice = SettingDef("x", 1, 2, Stricter.HIGHER, "", "m")
    monkeypatch.setattr(registry, "_declared", lambda: [twice, twice])
    registry.all_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="declared twice"):
            registry.all_settings()
    finally:
        monkeypatch.undo()
        registry.all_settings.cache_clear()


@pytest.mark.parametrize("value", [15, 20, 64])
def test_values_from_the_default_to_the_limit_are_allowed(value: int) -> None:
    assert registry.get_setting_def(PASSWORD_MIN_LENGTH).check(value) == value


@pytest.mark.parametrize("value", ["20", 20.0, True, None, [20], {"value": 20}])
def test_values_must_have_the_declared_type(value: object) -> None:
    with pytest.raises(SettingRejected, match="whole number"):
        registry.get_setting_def(PASSWORD_MIN_LENGTH).check(value)


def test_the_lower_direction_works_the_other_way_round() -> None:
    # For a later setting such as idle sign-out: shorter is stricter.
    idle = SettingDef("idle_minutes", 60, 5, Stricter.LOWER, "", "auth")
    assert idle.check(5) == 5 and idle.check(60) == 60
    with pytest.raises(SettingRejected, match="only be made stricter"):
        idle.check(61)
    with pytest.raises(SettingRejected, match="limit of 5"):
        idle.check(4)


# --- Reading and changing --------------------------------------------------------------


def test_without_a_row_the_default_applies(companies: AuditSetup) -> None:
    with companies.session_for(companies.company_a) as db:
        assert setting_value(db, TIME_OFF_REQUIRED_APPROVALS) == 1
        assert password_min_length(db) == 15
        # Reading writes nothing: no row appears for a default.
        assert db.scalars(select(CompanySetting)).all() == []


def test_a_change_is_saved_read_back_and_audited(companies: AuditSetup) -> None:
    with companies.session_for(companies.company_a) as db:
        assert change_setting(db, PASSWORD_MIN_LENGTH, 20, actor=Actor.system()) == 20
        db.commit()
    with companies.session_for(companies.company_a) as db:
        assert password_min_length(db) == 20
        # A second change updates the same row and records the value it replaced.
        change_setting(db, PASSWORD_MIN_LENGTH, 24, actor=Actor.system())
        db.commit()
        assert len(db.scalars(select(CompanySetting)).all()) == 1
    entries = companies.events(companies.company_a)
    assert [(e.action, e.details) for e in entries] == [
        ("settings.changed", {"setting": "auth.password_min_length", "old": 15, "new": 20}),
        ("settings.changed", {"setting": "auth.password_min_length", "old": 20, "new": 24}),
    ]


def test_change_setting_never_commits(companies: AuditSetup) -> None:
    with companies.session_for(companies.company_a) as db:
        change_setting(db, PASSWORD_MIN_LENGTH, 20, actor=Actor.system())
        db.rollback()
    with companies.session_for(companies.company_a) as db:
        assert password_min_length(db) == 15
        assert db.scalars(select(AuditEvent)).all() == []
