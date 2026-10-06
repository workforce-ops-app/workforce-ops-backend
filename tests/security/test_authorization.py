"""authorize() and the list filter against misuse (authorization.md; threats E2, E3, E8).

Each test is someone trying to do more than their roles allow: without any role, outside
their scope, on themselves, on another company, with a role that was archived, or after
being deactivated. Everything is denied unless a rule allows it.
"""

import uuid

import pytest
from sqlalchemy import select

from app.authz import registry
from app.authz.check import Forbidden, NotFound, authorize, effective_permissions, scope_filter
from app.authz.models import RoleAssignment
from app.authz.registry import Kind, PermissionDef
from app.authz.scope import ScopeColumns
from app.modules.org.models import User
from tests.authz_data import Note, Org, org

__all__ = ["org"]  # the fixture, imported so pytest finds it here


def allowed(org: Org, who: str, code: str, target: object | None = None) -> bool:
    """Whether authorize() lets this person of company A do this."""
    with org.a() as db:
        try:
            authorize(db, org.user(db, who), code, target)
        except Forbidden:
            return False
        return True


def note(org: Org, department: str, employee: str | None = None) -> Note:
    return Note(org.company_a, org.ids[department], org.ids[employee] if employee else None)


def person(org: Org, name: str) -> User:
    """A person of company A, loaded and detached, to pass as a target."""
    with org.a() as db:
        found = org.user(db, name)
        db.expunge(found)
        return found


# --- Deny by default -------------------------------------------------------------------


def test_someone_without_any_role_may_do_nothing(org: Org) -> None:
    for code in ("schedule.view_self", "schedule.view", "user.view", "settings.manage"):
        assert not allowed(org, "relic", code)


def test_an_archived_role_grants_nothing(org: Org) -> None:
    # relic's only role (schedule.edit, company-wide) was archived.
    assert not allowed(org, "relic", "schedule.edit", note(org, "kitchen"))


def test_a_deactivated_person_may_do_nothing_even_as_owner(org: Org) -> None:
    assert not allowed(org, "gone", "settings.manage")
    assert not allowed(org, "gone", "schedule.view", note(org, "front"))


def test_the_owner_holds_permissions_added_after_the_roles_were_created(
    org: Org, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A later module adds a permission; existing companies' roles were created before it.
    # The owner holds it at once; nobody else does until a role grants it.
    added = PermissionDef("announcement.create", Kind.COMPANY, "Post announcements", "news")
    monkeypatch.setitem(registry.all_permissions(), added.code, added)
    assert allowed(org, "owner", "announcement.create")
    assert not allowed(org, "admin", "announcement.create")
    with org.a() as db:
        assert "announcement.create" in effective_permissions(db, org.user(db, "owner"))


def test_an_unknown_permission_is_a_bug_not_a_yes(org: Org) -> None:
    with org.a() as db, pytest.raises(LookupError):
        authorize(db, org.user(db, "owner"), "schedule.everything")


def test_a_role_change_takes_effect_at_once(org: Org) -> None:
    # Permissions are read on every check: removing chef's Manager assignment ends their
    # right to edit Kitchen at the very next check.
    assert allowed(org, "chef", "schedule.edit", note(org, "kitchen"))
    with org.a() as db:
        for assignment in db.scalars(
            select(RoleAssignment).where(RoleAssignment.user_id == org.ids["chef"])
        ):
            if assignment.role_id == org.ids["role_manager"]:
                db.delete(assignment)
        db.commit()
    assert not allowed(org, "chef", "schedule.edit", note(org, "kitchen"))


# --- Record permissions: the assignment's scope must cover the record ------------------


def test_a_department_manager_acts_in_their_department_only(org: Org) -> None:
    assert allowed(org, "chef", "schedule.edit", note(org, "kitchen"))
    assert not allowed(org, "chef", "schedule.edit", note(org, "front"))


def test_department_scope_covers_the_records_of_its_people(org: Org) -> None:
    # Ana's home is Kitchen: her record in Front is still Kitchen's business.
    assert allowed(org, "chef", "schedule.edit", note(org, "front", "ana"))


def test_a_team_manager_covers_the_teams_members_only(org: Org) -> None:
    # Ben is on the Weekend Crew; Ana is not.
    assert allowed(org, "lead", "schedule.edit", note(org, "front", "ben"))
    assert not allowed(org, "lead", "schedule.edit", note(org, "kitchen", "ana"))
    assert not allowed(org, "lead", "schedule.edit", note(org, "kitchen"))


def test_an_employee_scoped_role_covers_that_one_person_only(org: Org) -> None:
    # Mentor holds Manager for Ben alone: Ben's records, nothing else in any department.
    assert allowed(org, "mentor", "schedule.edit", note(org, "kitchen", "ben"))
    assert not allowed(org, "mentor", "schedule.edit", note(org, "kitchen", "ana"))
    assert not allowed(org, "mentor", "schedule.edit", note(org, "kitchen"))


def test_a_record_without_a_scope_resolver_is_a_bug_not_a_yes(org: Org) -> None:
    with org.a() as db, pytest.raises(LookupError):
        authorize(db, org.user(db, "admin"), "schedule.edit", object())


def test_employees_see_their_own_departments_schedule_but_cannot_edit(org: Org) -> None:
    assert allowed(org, "ana", "schedule.view", note(org, "kitchen"))
    assert not allowed(org, "ana", "schedule.view", note(org, "front"))
    assert not allowed(org, "ana", "schedule.edit", note(org, "kitchen"))


def test_a_company_wide_role_covers_every_department(org: Org) -> None:
    assert allowed(org, "admin", "schedule.edit", note(org, "kitchen"))
    assert allowed(org, "admin", "schedule.edit", note(org, "front", "ben"))


# --- Self permissions: only your own ---------------------------------------------------


def test_self_permissions_cover_only_your_own_records(org: Org) -> None:
    assert allowed(org, "ana", "schedule.view_self", note(org, "kitchen", "ana"))
    assert not allowed(org, "ana", "schedule.view_self", note(org, "kitchen", "chef"))
    assert not allowed(org, "ana", "schedule.view_self", note(org, "kitchen"))  # open shift


# --- Company permissions: a company-wide assignment ------------------------------------


def test_company_permissions_need_a_company_wide_assignment(org: Org) -> None:
    assert allowed(org, "admin", "settings.manage")
    assert allowed(org, "owner", "company.transfer_ownership")
    # Administrators hold everything except the owner-only permission.
    assert not allowed(org, "admin", "company.transfer_ownership")
    # A manager holds role.view, but only for a department: not enough for a company
    # permission.
    assert not allowed(org, "chef", "role.view")


# --- Person permissions: someone else, in scope, and above them ------------------------


def test_nobody_acts_on_themselves_with_a_person_permission(org: Org) -> None:
    # Not even the owner: nobody changes their own access or reviews their own requests.
    assert not allowed(org, "owner", "user.manage", person(org, "owner"))
    assert not allowed(org, "owner", "role.assign", person(org, "owner"))


def test_the_owner_is_above_everyone(org: Org) -> None:
    assert allowed(org, "owner", "user.manage", person(org, "ana"))
    assert allowed(org, "owner", "time_off.review", person(org, "admin"))


def test_holding_the_permission_is_not_enough_without_being_above(org: Org) -> None:
    # Chef may review time off in Kitchen and Ana is in Kitchen, but chef is not above her
    # (no reporting lines until Z2), and an administrator is not above anyone either.
    assert not allowed(org, "chef", "time_off.review", person(org, "ana"))
    assert not allowed(org, "admin", "user.manage", person(org, "ana"))


def test_person_permissions_need_a_person_as_target(org: Org) -> None:
    assert not allowed(org, "owner", "user.manage", note(org, "kitchen", "ana"))


# --- Companies --------------------------------------------------------------------------


def test_another_companys_target_does_not_exist(org: Org) -> None:
    # Even the owner, even with company-wide roles: another company's record is a 404, the
    # same answer as a record that does not exist.
    other = Note(org.company_b, uuid.uuid4(), None)
    with org.a() as db, pytest.raises(NotFound):
        authorize(db, org.user(db, "owner"), "schedule.edit", other)


def test_roles_of_one_company_never_count_in_another(org: Org) -> None:
    # Company B's owner, checked in a session for B, holds nothing over A's records.
    with org.session(org.company_b) as db:
        b_owner = org.user(db, "b_owner")
        with pytest.raises(NotFound):
            authorize(db, b_owner, "schedule.edit", note(org, "kitchen"))


# --- Lists: the scope filter matches authorize() row by row ----------------------------


def visible(org: Org, who: str, code: str) -> set[str]:
    """The people of company A this person may list with the permission."""
    with org.a() as db:
        user = org.user(db, who)
        condition = scope_filter(db, user, code, ScopeColumns(User.department_id, User.id))
        return set(db.scalars(select(User.display_name).where(condition)))


def test_the_list_filter_shows_exactly_the_rows_in_scope(org: Org) -> None:
    everyone = {"owner", "admin", "chef", "lead", "ana", "ben", "gone", "relic", "mentor"}
    assert visible(org, "admin", "user.view") == everyone
    assert visible(org, "chef", "user.view") == {"chef", "ana", "mentor"}  # Kitchen's people
    assert visible(org, "lead", "user.view") == {"ben"}  # the Weekend Crew
    assert visible(org, "mentor", "user.view") == {"ben"}  # one person
    assert visible(org, "ana", "user.view") == set()  # employees cannot list people
    assert visible(org, "relic", "user.view") == set()


@pytest.mark.parametrize("code", ["user.view", "user.manage", "time_off.review"])
def test_the_list_filter_agrees_with_authorize_for_every_pair(org: Org, code: str) -> None:
    # The same rules in two forms (one record at a time, and a database condition) must
    # never disagree, or a list could show what a direct request refuses. Checked for a
    # record permission and two person permissions (above them, never yourself).
    names = ["owner", "admin", "chef", "lead", "ana", "ben", "relic", "mentor"]
    for who in names:
        listed = visible(org, who, code)
        for name in names:
            assert (name in listed) == allowed(org, who, code, person(org, name)), (who, name)


def test_a_company_permission_lists_everything_or_nothing(org: Org) -> None:
    # role.view is a company permission: the admin (company-wide) sees every row; the chef
    # holds it only for Kitchen, which is not enough, so sees none (as authorize() says).
    assert len(visible(org, "admin", "role.view")) == 9
    assert visible(org, "chef", "role.view") == set()


def test_a_self_permission_lists_only_your_own_row(org: Org) -> None:
    assert visible(org, "ana", "schedule.view_self") == {"ana"}
    assert visible(org, "relic", "schedule.view_self") == set()
