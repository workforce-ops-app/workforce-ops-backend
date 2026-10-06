"""The permission registry, the starting roles, assignments, and effective permissions.

The rules of authorize() against misuse (deny by default, scopes, people, companies) are in
tests/security/test_authorization.py.
"""

import pytest
from sqlalchemy import select

from app.audit import Actor
from app.audit.models import AuditEvent
from app.authz import registry
from app.authz.check import effective_permissions
from app.authz.models import Permission, Role, RolePermission
from app.authz.registry import Kind, PermissionDef, all_permissions, sync_permissions
from app.authz.roles import RoleError, assign_role
from tests.authz_data import Org, org

__all__ = ["org"]  # the fixture, imported so pytest finds it here

# The core permissions and their kinds, as on the authorization page.
CORE = {
    "schedule.view_self": "self",
    "schedule.view": "record",
    "schedule.edit": "record",
    "time_off.request": "self",
    "time_off.cancel_self": "self",
    "time_off.view": "record",
    "time_off.review": "person",
    "user.view": "record",
    "user.manage": "person",
    "account.change_self": "self",
    "org.manage": "company",
    "role.view": "company",
    "role.manage": "company",
    "role.assign": "person",
    "reporting_line.manage": "person",
    "settings.manage": "company",
    "audit.view": "company",
    "audit.verify": "company",
    "company.transfer_ownership": "company",
}


def test_the_registry_has_every_core_permission_with_its_kind() -> None:
    assert {code: p.kind.value for code, p in all_permissions().items()} == CORE


@pytest.mark.parametrize(
    "bad",
    [
        PermissionDef("Schedule.Edit", Kind.RECORD, "uppercase"),
        PermissionDef("schedule", Kind.RECORD, "no action"),
        PermissionDef("shift.view_self", Kind.RECORD, "named _self but not a self permission"),
    ],
)
def test_badly_named_permissions_are_refused(
    monkeypatch: pytest.MonkeyPatch, bad: PermissionDef
) -> None:
    monkeypatch.setattr(registry, "_declared", lambda: [bad])
    registry.all_permissions.cache_clear()
    try:
        with pytest.raises(ValueError):
            registry.all_permissions()
    finally:
        registry.all_permissions.cache_clear()


def test_a_permission_declared_twice_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    twice = PermissionDef("schedule.edit", Kind.RECORD, "again")
    monkeypatch.setattr(registry, "_declared", lambda: [twice, twice])
    registry.all_permissions.cache_clear()
    try:
        with pytest.raises(ValueError, match="twice"):
            registry.all_permissions()
    finally:
        registry.all_permissions.cache_clear()


def test_the_permissions_table_follows_the_registry(org: Org) -> None:
    with org.a() as db:
        stored = {p.code: p.module for p in db.scalars(select(Permission))}
        assert set(stored) == set(CORE)
        assert stored["schedule.edit"] == "schedules" and stored["role.view"] == "authz"
        # Running it again changes nothing.
        sync_permissions(db)
        assert len(db.scalars(select(Permission)).all()) == len(CORE)


def test_the_starting_roles_grant_what_the_authorization_page_says(org: Org) -> None:
    with org.a() as db:
        granted = {
            role.built_in: set(
                db.scalars(
                    select(RolePermission.permission_code).where(RolePermission.role_id == role.id)
                )
            )
            for role in db.scalars(select(Role).where(Role.built_in.is_not(None)))
        }
    assert granted["owner"] == set(CORE)
    assert granted["administrator"] == set(CORE) - {"company.transfer_ownership"}
    assert granted["manager"] == {
        "schedule.view_self",
        "schedule.view",
        "schedule.edit",
        "time_off.request",
        "time_off.cancel_self",
        "time_off.view",
        "time_off.review",
        "user.view",
        "account.change_self",
        "role.view",
    }
    assert granted["employee"] == {
        "schedule.view_self",
        "schedule.view",
        "time_off.request",
        "time_off.cancel_self",
        "account.change_self",
    }


def test_effective_permissions_combine_every_active_role(org: Org) -> None:
    with org.a() as db:
        assert effective_permissions(db, org.user(db, "owner")) == sorted(CORE)
        assert "schedule.edit" in effective_permissions(db, org.user(db, "chef"))
        assert effective_permissions(db, org.user(db, "ana")) == sorted(
            [
                "schedule.view_self",
                "schedule.view",
                "time_off.request",
                "time_off.cancel_self",
                "account.change_self",
            ]
        )
        # Deactivated people and archived roles grant nothing.
        assert effective_permissions(db, org.user(db, "gone")) == []
        assert effective_permissions(db, org.user(db, "relic")) == []


def test_role_changes_are_audited(org: Org) -> None:
    with org.a() as db:
        actions = [
            e.action
            for e in db.scalars(select(AuditEvent).where(AuditEvent.chain_id == org.company_a))
        ]
    assert actions.count("role.created") == 4
    # One per assign_role() call in the fixture: owner 2, admin 2, chef 2, lead 2, ana,
    # ben, mentor, and gone 1 each.
    assert actions.count("role_assignment.added") == 12


@pytest.mark.parametrize(
    ("role", "scope_type", "scope", "message"),
    [
        ("owner", "department", "kitchen", "whole company"),
        ("manager", "company", "kitchen", "scope ID"),
        ("manager", "department", None, "scope ID"),
        ("manager", "region", "kitchen", "unknown scope"),
    ],
)
def test_assignments_follow_the_scope_rules(
    org: Org, role: str, scope_type: str, scope: str | None, message: str
) -> None:
    with org.a() as db, pytest.raises(RoleError, match=message):
        assign_role(
            db,
            Actor.system(),
            user_id=org.ids["ana"],
            role=db.get(Role, org.ids[f"role_{role}"]),  # type: ignore[arg-type]
            scope_type=scope_type,
            scope_id=org.ids[scope] if scope else None,
        )


def test_a_duplicate_assignment_is_refused(org: Org) -> None:
    with org.a() as db:
        employee = db.get(Role, org.ids["role_employee"])
        assert employee is not None
        with pytest.raises(RoleError, match="already"):
            assign_role(
                db,
                Actor.system(),
                user_id=org.ids["ana"],
                role=employee,
                scope_type="department",
                scope_id=org.ids["kitchen"],
            )
