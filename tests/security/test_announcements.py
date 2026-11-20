"""Announcements against the threats on the announcements page (E11, T5, T2, I1, T3, I7,
I9, D2), and the scope tests for the list filter's team column.

Every request here goes through the real app: the session, the CSRF check, the company
filter, and authorize(). Each test is someone reaching for announcements they should not
post, change, or see, or for who has read them. The scope tests compare the managed list
with authorize() for every pair of an assignment and an audience.
"""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.authz.check import Forbidden, authorize
from app.authz.scope import Grant, ScopeColumns, condition_for
from app.db.base import utcnow
from app.modules.announcements import repository
from app.modules.announcements import scope as _scope  # noqa: F401  (registers the resolver)
from app.modules.announcements.models import Announcement, AnnouncementRead
from app.modules.org.models import Department, Team, TeamMember, User
from app.modules.org.repository import encode_cursor
from app.modules.schedules.models import Shift
from tests.announcement_data import announcements, audience_body, post
from tests.shift_data import BASE_URL, ShiftSetup, shifts

__all__ = ["announcements", "shifts"]  # the fixtures, imported so pytest finds them here


def every_endpoint(client: TestClient, announcement_id: object) -> dict[str, int]:
    """The status of every endpoint that names one announcement."""
    url = f"/api/announcements/{announcement_id}"
    return {
        "edit": client.patch(url, json={"title": "Mine now"}).status_code,
        "archive": client.post(f"{url}/archive").status_code,
    }


def try_post(setup: ShiftSetup, who: str, audience: str, **fields: object) -> int:
    """The status of posting to an audience (it is not required to succeed)."""
    body = audience_body(setup, audience) | {"title": "T", "body": "B"} | fields
    return setup.browser(who).post("/api/announcements", json=body).status_code


def saved_titles(setup: ShiftSetup) -> set[str]:
    with setup.db() as db:
        return set(db.scalars(select(Announcement.title)))


# --- I1, T3: other companies -----------------------------------------------------------


def test_another_companys_announcement_does_not_exist_on_any_endpoint(
    announcements: ShiftSetup,
) -> None:
    theirs = post(announcements, "b_chef", "b_kitchen")
    # Even company A's owner gets exactly the answer for an ID that does not exist.
    owner = announcements.browser("owner")
    assert every_endpoint(owner, theirs["id"]) == {"edit": 404, "archive": 404}
    assert every_endpoint(owner, uuid.uuid4()) == {"edit": 404, "archive": 404}
    # And it never appears in a list, archived ones included.
    for params in ({}, {"include_archived": "true"}):
        listed = owner.get("/api/announcements/managed", params=params).json()["items"]
        assert theirs["id"] not in {item["id"] for item in listed}
    # Nothing changed for them.
    with announcements.db(announcements.company_b) as db:
        saved = db.get(Announcement, uuid.UUID(theirs["id"]))
        assert saved is not None and saved.title == "Heads up" and saved.archived_at is None


@pytest.mark.parametrize("audience", ["b_kitchen", "b_crew"])
def test_another_companys_department_or_team_cannot_be_the_audience(
    announcements: ShiftSetup, audience: str
) -> None:
    owner = announcements.browser("owner")
    kind = "department" if audience == "b_kitchen" else "team"
    foreign = owner.post(
        "/api/announcements",
        json=audience_body(announcements, audience) | {"title": "T", "body": "B"},
    )
    missing = owner.post(
        "/api/announcements",
        json={"audience_type": kind, f"{kind}_id": str(uuid.uuid4()), "title": "T", "body": "B"},
    )
    # The same answer as one that does not exist: no hint that it exists elsewhere.
    assert foreign.status_code == missing.status_code == 422
    assert foreign.json()["detail"] == missing.json()["detail"]
    assert saved_titles(announcements) == set()


# --- E11: posting outside your scope ---------------------------------------------------


@pytest.mark.parametrize(
    ("who", "audience"),
    [
        # A team manager: not their department, not the company, not another team.
        ("lead", "kitchen"),
        ("lead", "company"),
        ("lead", "patio"),
        ("lead", "front"),
        # A department manager: not another department, its teams, or the company.
        ("chef", "front"),
        ("chef", "patio"),
        ("chef", "company"),
        ("manny", "kitchen"),
        ("manny", "crew"),
        ("manny", "company"),
    ],
)
def test_a_manager_cannot_post_outside_their_scope(
    announcements: ShiftSetup, who: str, audience: str
) -> None:
    assert try_post(announcements, who, audience) == 403
    assert saved_titles(announcements) == set()  # nothing was saved


@pytest.mark.parametrize(
    ("who", "audience"),
    [
        ("lead", "crew"),
        ("chef", "kitchen"),
        ("chef", "crew"),  # a department covers its teams
        ("manny", "patio"),
        ("owner", "company"),
        ("owner", "front"),
        ("owner", "crew"),
    ],
)
def test_a_manager_can_post_inside_their_scope(
    announcements: ShiftSetup, who: str, audience: str
) -> None:
    assert try_post(announcements, who, audience) == 201


@pytest.mark.parametrize("audience", ["company", "kitchen", "crew"])
def test_employees_cannot_post_at_all(announcements: ShiftSetup, audience: str) -> None:
    # Ana is an Employee of Kitchen; Ben is on the Weekend Crew. Neither may post, even to
    # their own department or team.
    assert try_post(announcements, "ana", audience) == 403
    assert try_post(announcements, "ben", audience) == 403
    assert saved_titles(announcements) == set()


def test_employees_cannot_manage_announcements_either(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    ana = announcements.browser("ana")
    assert every_endpoint(ana, created["id"]) == {"edit": 403, "archive": 403}
    assert ana.get("/api/announcements/managed").status_code == 403


def test_a_manager_cannot_edit_or_archive_outside_their_scope(announcements: ShiftSetup) -> None:
    kitchen = post(announcements, "chef", "kitchen")
    company = post(announcements, "owner", "company")
    patio = post(announcements, "pat", "patio")
    # The crew lead covers neither the Kitchen department nor the company...
    assert every_endpoint(announcements.browser("lead"), kitchen["id"]) == {
        "edit": 403,
        "archive": 403,
    }
    # ...and the Kitchen manager neither the company nor another department's team.
    for item in (company, patio):
        assert every_endpoint(announcements.browser("chef"), item["id"]) == {
            "edit": 403,
            "archive": 403,
        }
    with announcements.db() as db:
        for item in (kitchen, company, patio):
            saved = db.get(Announcement, uuid.UUID(item["id"]))
            assert saved is not None and saved.title == "Heads up" and saved.archived_at is None


def test_signed_out_and_forged_requests_are_refused(announcements: ShiftSetup) -> None:
    stranger = TestClient(announcements.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]
    assert stranger.get("/api/announcements/managed").status_code == 401
    # A signed-in manager's browser, but the request comes without the CSRF token.
    chef = announcements.browser("chef")
    token = chef.headers.pop("X-CSRF-Token")
    assert try_post(announcements, "chef", "kitchen") == 403
    chef.headers["X-CSRF-Token"] = token
    assert saved_titles(announcements) == set()


# --- T2: the author, audience, and dates cannot be set ---------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        {"author_id": "00000000-0000-0000-0000-000000000001"},
        {"company_id": "00000000-0000-0000-0000-000000000000"},
        {"id": "00000000-0000-0000-0000-000000000002"},
        {"created_at": "2020-01-01T00:00:00Z"},
        {"posted_at": "2020-01-01T00:00:00Z"},
        {"edited_at": "2020-01-01T00:00:00Z"},
        {"archived_at": "2020-01-01T00:00:00Z"},
        {"archived": True},
        {"read_count": 99},
    ],
)
def test_fields_outside_the_rules_cannot_be_set_when_posting(
    announcements: ShiftSetup, extra: dict
) -> None:
    assert try_post(announcements, "chef", "kitchen", **extra) == 422
    assert saved_titles(announcements) == set()


@pytest.mark.parametrize(
    "extra",
    [
        {"audience_type": "company"},
        {"department_id": "front"},
        {"team_id": "crew"},
        {"author_id": "ana"},
        {"company_id": "b_kitchen"},
        {"created_at": "2020-01-01T00:00:00Z"},
        {"edited_at": None},
        {"archived_at": "2020-01-01T00:00:00Z"},
    ],
)
def test_the_audience_author_and_dates_cannot_be_changed(
    announcements: ShiftSetup, extra: dict
) -> None:
    created = post(announcements, "chef", "kitchen")
    body = {"title": "Changed"} | {
        k: (str(announcements.ids[v]) if v in announcements.ids else v) for k, v in extra.items()
    }
    response = announcements.browser("chef").patch(f"/api/announcements/{created['id']}", json=body)
    assert response.status_code == 422
    # The attacker's view: nothing changed, not even the title sent alongside.
    with announcements.db() as db:
        saved = db.get(Announcement, uuid.UUID(created["id"]))
        assert saved is not None
        assert (saved.title, saved.audience_type, saved.department_id, saved.author_id) == (
            "Heads up",
            "department",
            announcements.ids["kitchen"],
            announcements.ids["chef"],
        )
        assert saved.edited_at is None and saved.archived_at is None


# --- T5, I7: text is data, never markup or a template ----------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "<script>alert(1)</script>",
        '<img src=x onerror="alert(1)"> & "quotes"',
        "{0.__class__}",
        "{{7*7}} ${7*7} %s %(x)s",
        "**bold** and a lone ** and <b>tags</b>",
    ],
)
def test_text_is_stored_and_returned_exactly_as_typed(announcements: ShiftSetup, text: str) -> None:
    created = post(announcements, "chef", "kitchen", title=text[:120], body=text)
    assert (created["title"], created["body"]) == (text[:120], text)
    with announcements.db() as db:
        saved = db.get(Announcement, uuid.UUID(created["id"]))
        assert saved is not None and (saved.title, saved.body) == (text[:120], text)
    # The managed list and an edit return it unchanged too.
    [listed] = announcements.browser("chef").get("/api/announcements/managed").json()["items"]
    assert listed["body"] == text
    url = f"/api/announcements/{created['id']}"
    assert (
        announcements.browser("chef").patch(url, json={"title": text[:120]}).json()["body"] == text
    )


# --- Archived scopes and archived announcements ----------------------------------------


def archive(setup: ShiftSetup, model: type, key: str) -> None:
    """Archive a department or team directly (the organization endpoints have their own
    tests; here only the effect on announcements matters)."""
    with setup.db() as db:
        row = db.get(model, setup.ids[key])
        assert row is not None
        row.archived_at = utcnow()
        db.commit()


def test_an_archived_team_takes_no_new_announcements(announcements: ShiftSetup) -> None:
    archive(announcements, Team, "crew")
    # Even the owner, whose scope covers everything, is refused (409).
    assert try_post(announcements, "owner", "crew") == 409
    # The crew's lead and the Kitchen manager no longer cover it at all (403).
    assert try_post(announcements, "lead", "crew") == 403
    assert try_post(announcements, "chef", "crew") == 403
    assert saved_titles(announcements) == set()


def test_an_archived_department_takes_no_new_announcements(announcements: ShiftSetup) -> None:
    # A department is only archived once it is empty, so a new one is used here.
    with announcements.db() as db:
        old = Department(name="Old Wing", archived_at=utcnow())
        db.add(old)
        db.commit()
        announcements.ids["old"] = old.id
    body = {"audience_type": "department", "department_id": str(announcements.ids["old"])}
    response = announcements.browser("owner").post(
        "/api/announcements", json=body | {"title": "T", "body": "B"}
    )
    assert response.status_code == 409
    assert saved_titles(announcements) == set()


def test_an_archived_announcement_cannot_be_edited(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    chef = announcements.browser("chef")
    url = f"/api/announcements/{created['id']}"
    assert chef.post(f"{url}/archive").status_code == 200
    assert chef.patch(url, json={"body": "Rewritten history"}).status_code == 409
    with announcements.db() as db:
        saved = db.get(Announcement, uuid.UUID(created["id"]))
        assert saved is not None and saved.body == "Inventory on Friday."
        assert saved.edited_at is None


# --- D2: huge requests -----------------------------------------------------------------


@pytest.mark.parametrize(
    "params", [{"limit": "201"}, {"limit": "0"}, {"cursor": "not-a-cursor"}, {"cursor": "x" * 201}]
)
def test_oversized_or_malformed_list_requests_are_refused(
    announcements: ShiftSetup, params: dict
) -> None:
    response = announcements.browser("chef").get("/api/announcements/managed", params=params)
    assert response.status_code == 422


def test_an_oversized_text_is_refused(announcements: ShiftSetup) -> None:
    assert try_post(announcements, "chef", "kitchen", body="x" * 100_000) == 422
    assert try_post(announcements, "chef", "kitchen", title="x" * 10_000) == 422
    assert saved_titles(announcements) == set()


# --- Scope tests: the managed list agrees with authorize() -----------------------------

# Every kind of assignment: company-wide, each department, each team.
MANAGERS = ["owner", "chef", "manny", "lead", "pat"]
# Every kind of audience: the company, each department, a team in each department (so for
# every department or team manager, one is a team of another department).
AUDIENCES = ["company", "kitchen", "front", "crew", "patio"]


def managed_ids(setup: ShiftSetup, who: str) -> set[str]:
    """The IDs the managed list shows this person, every page, archived ones included."""
    found: set[str] = set()
    params: dict[str, str] = {"include_archived": "true", "limit": "2"}
    while True:
        page = setup.browser(who).get("/api/announcements/managed", params=params)
        # A manager whose only assignment is for an archived team or department holds
        # announcement.create nowhere any more: the list is refused (403), so it shows
        # nothing.
        if page.status_code == 403:
            return found
        assert page.status_code == 200, page.text
        found |= {item["id"] for item in page.json()["items"]}
        if page.json()["next_cursor"] is None:
            return found
        params["cursor"] = page.json()["next_cursor"]


def allowed(setup: ShiftSetup, who: str, announcement_id: str) -> bool:
    """Whether authorize() lets this person manage this announcement."""
    with setup.db() as db:
        user = db.get(User, setup.ids[who])
        item = db.get(Announcement, uuid.UUID(announcement_id))
        assert user is not None and item is not None
        try:
            authorize(db, user, "announcement.create", item)
        except Forbidden:
            return False
        return True


def assert_list_agrees(setup: ShiftSetup, posted: dict[str, str]) -> dict[str, set[str]]:
    """For every manager and announcement: listed exactly when authorize() allows it.
    Returns what each manager's list shows, by audience name."""
    shown: dict[str, set[str]] = {}
    for who in MANAGERS:
        listed = managed_ids(setup, who)
        for audience, announcement_id in posted.items():
            assert (announcement_id in listed) == allowed(setup, who, announcement_id), (
                who,
                audience,
            )
        shown[who] = {audience for audience, i in posted.items() if i in listed}
    return shown


def test_the_managed_list_agrees_with_authorize_for_every_pair(announcements: ShiftSetup) -> None:
    posted = {audience: post(announcements, "owner", audience)["id"] for audience in AUDIENCES}
    shown = assert_list_agrees(announcements, posted)
    # And what that means, spelled out: a department assignment lists its own department
    # and its teams; a team assignment lists its team only, neither its department nor
    # another team; only the company-wide assignment lists the company audience.
    assert shown == {
        "owner": set(AUDIENCES),
        "chef": {"kitchen", "crew"},
        "manny": {"front", "patio"},
        "lead": {"crew"},
        "pat": {"patio"},
    }


def test_an_archived_teams_announcements_are_listed_below_company_scope_for_nobody(
    announcements: ShiftSetup,
) -> None:
    posted = {audience: post(announcements, "owner", audience)["id"] for audience in AUDIENCES}
    archive(announcements, Team, "crew")
    shown = assert_list_agrees(announcements, posted)
    # The crew's announcement: only the owner still manages it. The Kitchen manager no
    # longer reaches it through the department, and the lead's assignment is for an
    # archived team, so it grants nothing at all.
    assert {who for who, audiences in shown.items() if "crew" in audiences} == {"owner"}
    assert shown["chef"] == {"kitchen"}
    assert shown["pat"] == {"patio"}


def test_an_archived_departments_announcements_are_listed_below_company_scope_for_nobody(
    announcements: ShiftSetup,
) -> None:
    posted = {audience: post(announcements, "owner", audience)["id"] for audience in AUDIENCES}
    # Front is archived (with its team first, as the organization rules require).
    archive(announcements, Team, "patio")
    archive(announcements, Department, "front")
    shown = assert_list_agrees(announcements, posted)
    assert {who for who, audiences in shown.items() if audiences & {"front", "patio"}} == {"owner"}


def test_the_team_column_leaves_existing_lists_as_they_were(announcements: ShiftSetup) -> None:
    """Tables without a team column (people, shifts) get exactly the conditions they had
    before the team column existed."""
    with announcements.db() as db:
        kitchen = Grant("department", announcements.ids["kitchen"], None, None)
        crew = Grant("team", None, announcements.ids["crew"], None)
        members = list(
            db.scalars(
                select(TeamMember.user_id).where(TeamMember.team_id == announcements.ids["crew"])
            )
        )
        home = list(
            db.scalars(select(User.id).where(User.department_id == announcements.ids["kitchen"]))
        )
        for columns in (
            ScopeColumns(department=User.department_id, employee=User.id),
            ScopeColumns(department=Shift.department_id, employee=Shift.employee_id),
        ):
            # A team assignment: the team's members, and nothing else.
            assert str(condition_for(db, crew, columns)) == str(columns.employee.in_(members))
            # A department assignment: the department, or its people.
            expected = (columns.department == kitchen.department_id) | columns.employee.in_(home)
            assert str(condition_for(db, kitchen, columns)) == str(expected)
        # Without an employee column, a team assignment matches nothing (as before).
        nothing = condition_for(db, crew, ScopeColumns(department=Shift.department_id))
        assert str(nothing) == "false"


# --- I9: reading announcements meant for others, or who read what (AN2) ----------------


def every_reading_endpoint(client: TestClient, announcement_id: object) -> dict[str, int]:
    """The status of every reading endpoint that names one announcement."""
    url = f"/api/announcements/{announcement_id}"
    return {
        "view": client.get(url).status_code,
        "read": client.post(f"{url}/read").status_code,
        "reads": client.get(f"{url}/reads").status_code,
    }


NOT_FOUND = {"view": 404, "read": 404, "reads": 404}


def listed_ids(setup: ShiftSetup, who: str) -> set[str]:
    """The IDs on every page of the person's own list."""
    found: set[str] = set()
    params: dict[str, str] = {"limit": "2"}
    while True:
        page = setup.browser(who).get("/api/announcements", params=params)
        assert page.status_code == 200, page.text
        found |= {item["id"] for item in page.json()["items"]}
        if page.json()["next_cursor"] is None:
            return found
        params["cursor"] = page.json()["next_cursor"]


def saved_marks(setup: ShiftSetup, company: uuid.UUID | None = None) -> set[tuple[str, str]]:
    """Every read mark saved for a company, as (announcement ID, person ID)."""
    with setup.db(company) as db:
        rows = db.execute(select(AnnouncementRead.announcement_id, AnnouncementRead.user_id))
        return {(str(a), str(u)) for a, u in rows}


def read_list_people(setup: ShiftSetup, who: str, announcement_id: str) -> set[str]:
    """The IDs on the first page of the read list (every test audience fits on it)."""
    response = setup.browser(who).get(f"/api/announcements/{announcement_id}/reads")
    assert response.status_code == 200, response.text
    return {item["id"] for item in response.json()["items"]}


def test_another_companys_announcement_is_not_found_on_any_reading_endpoint(
    announcements: ShiftSetup,
) -> None:
    theirs = post(announcements, "b_chef", "b_kitchen")
    # Even company A's owner, whose scope covers all of company A, gets exactly the answer
    # for an ID that does not exist.
    owner = announcements.browser("owner")
    assert every_reading_endpoint(owner, theirs["id"]) == NOT_FOUND
    assert every_reading_endpoint(owner, uuid.uuid4()) == NOT_FOUND
    assert theirs["id"] not in listed_ids(announcements, "owner")
    # And the other way round: company A's company-wide announcement is not company B's.
    ours = post(announcements, "owner", "company")
    assert every_reading_endpoint(announcements.browser("b_ana"), ours["id"]) == NOT_FOUND
    assert listed_ids(announcements, "b_ana") == {theirs["id"]}
    # No read mark was saved anywhere.
    assert saved_marks(announcements) == set()
    assert saved_marks(announcements, announcements.company_b) == set()


def test_a_person_outside_the_audience_cannot_see_mark_or_list_it(
    announcements: ShiftSetup,
) -> None:
    kitchen = post(announcements, "chef", "kitchen")
    crew = post(announcements, "lead", "crew")
    # Dana is an Employee of Front: neither is meant for her.
    for item in (kitchen, crew):
        assert item["id"] not in listed_ids(announcements, "dana")
        assert every_reading_endpoint(announcements.browser("dana"), item["id"]) == NOT_FOUND
    # A manager outside the audience whose scope does not cover it either: the Front
    # manager and Kitchen's announcement, the Patio manager and the crew's.
    assert every_reading_endpoint(announcements.browser("manny"), kitchen["id"]) == NOT_FOUND
    assert every_reading_endpoint(announcements.browser("pat"), crew["id"]) == NOT_FOUND
    # Nothing was marked, and the read counts did not move.
    assert saved_marks(announcements) == set()
    counted = {
        i["id"]: i["read_count"]
        for i in announcements.browser("owner").get("/api/announcements/managed").json()["items"]
    }
    assert counted == {kitchen["id"]: 0, crew["id"]: 0}


def test_employees_cannot_see_who_has_read_it(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    # Ana is in the audience, so the announcement exists for her, but she does not hold
    # announcement.create: 403, and no names.
    response = announcements.browser("ana").get(f"/api/announcements/{created['id']}/reads")
    assert response.status_code == 403
    assert "items" not in response.json()


def test_a_manager_outside_the_audience_cannot_mark_it_read(announcements: ShiftSetup) -> None:
    # The owner manages Kitchen's announcement (and may see it and its read list) but is
    # not in its audience (home Front), so cannot mark it read.
    created = post(announcements, "chef", "kitchen")
    assert every_reading_endpoint(announcements.browser("owner"), created["id"]) == {
        "view": 200,
        "read": 404,
        "reads": 200,
    }
    assert created["id"] not in listed_ids(announcements, "owner")
    assert saved_marks(announcements) == set()


def test_deactivated_people_are_in_no_audience(announcements: ShiftSetup) -> None:
    created = post(announcements, "owner", "company")
    # Dana signs in and reads; then she is deactivated.
    assert (
        announcements.browser("dana").post(f"/api/announcements/{created['id']}/read").status_code
        == 204
    )
    owner = announcements.browser("owner")
    assert owner.post(f"/api/users/{announcements.ids['dana']}/deactivate").status_code == 200
    # Her session ended with it: nothing more for her...
    assert announcements.browser("dana").get("/api/announcements").status_code == 401
    # ...and she, and Gone (deactivated from the start), are in no audience: not on the
    # read list, not counted, her old mark not counted either.
    people = read_list_people(announcements, "owner", created["id"])
    assert str(announcements.ids["dana"]) not in people
    assert str(announcements.ids["gone"]) not in people
    item = owner.get(f"/api/announcements/{created['id']}").json()
    assert (item["read_count"], item["audience_count"]) == (0, 9)
    with announcements.db() as db:
        assert not repository.in_audience(db, uuid.UUID(created["id"]), announcements.ids["dana"])
        assert not repository.in_audience(db, uuid.UUID(created["id"]), announcements.ids["gone"])


def test_a_person_removed_from_a_team_stops_seeing_its_announcements(
    announcements: ShiftSetup,
) -> None:
    created = post(announcements, "lead", "crew")
    ben = announcements.browser("ben")
    assert created["id"] in listed_ids(announcements, "ben")
    assert ben.post(f"/api/announcements/{created['id']}/read").status_code == 204
    # The owner takes Ben off the crew.
    url = f"/api/teams/{announcements.ids['crew']}/members/{announcements.ids['ben']}"
    assert announcements.browser("owner").delete(url).status_code == 204
    # From then on it is not his: not listed, 404 to see or mark it, and he is not on its
    # read list or in its counts any more.
    assert created["id"] not in listed_ids(announcements, "ben")
    assert every_reading_endpoint(ben, created["id"]) == NOT_FOUND
    assert read_list_people(announcements, "lead", created["id"]) == set()
    item = announcements.browser("lead").get(f"/api/announcements/{created['id']}").json()
    assert (item["read_count"], item["audience_count"]) == (0, 0)


def test_an_archived_team_reaches_nobody(announcements: ShiftSetup) -> None:
    created = post(announcements, "lead", "crew")
    archive(announcements, Team, "crew")
    # Ben is still on its member list (kept for history), but it no longer reaches him.
    assert created["id"] not in listed_ids(announcements, "ben")
    assert every_reading_endpoint(announcements.browser("ben"), created["id"]) == NOT_FOUND
    assert read_list_people(announcements, "owner", created["id"]) == set()


def test_an_archived_department_reaches_nobody(announcements: ShiftSetup) -> None:
    """The organization rules only archive a department once nobody's home is there; the
    audience rules hold even if one were archived with its people still in it."""
    created = post(announcements, "chef", "kitchen")
    archive(announcements, Team, "crew")
    archive(announcements, Department, "kitchen")
    for who in ("ana", "cara"):
        assert created["id"] not in listed_ids(announcements, who)
        assert every_reading_endpoint(announcements.browser(who), created["id"]) == NOT_FOUND
    assert read_list_people(announcements, "owner", created["id"]) == set()
    item = announcements.browser("owner").get(f"/api/announcements/{created['id']}").json()
    assert item["audience_count"] == 0


def test_archived_announcements_disappear_for_readers(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    assert created["id"] in listed_ids(announcements, "ana")
    assert (
        announcements.browser("chef")
        .post(f"/api/announcements/{created['id']}/archive")
        .status_code
        == 200
    )
    assert created["id"] not in listed_ids(announcements, "ana")
    assert every_reading_endpoint(announcements.browser("ana"), created["id"]) == NOT_FOUND
    assert saved_marks(announcements) == set()


@pytest.mark.parametrize(
    "params", [{"limit": "201"}, {"limit": "0"}, {"cursor": "not-a-cursor"}, {"cursor": "x" * 201}]
)
def test_oversized_or_malformed_read_list_requests_are_refused(
    announcements: ShiftSetup, params: dict
) -> None:
    created = post(announcements, "owner", "company")
    url = f"/api/announcements/{created['id']}/reads"
    assert announcements.browser("owner").get(url, params=params).status_code == 422
    # The reader's list has the same limits.
    assert announcements.browser("ana").get("/api/announcements", params=params).status_code == 422


def test_the_read_list_answers_at_most_200_people_per_page(announcements: ShiftSetup) -> None:
    with announcements.db() as db:
        db.add_all(
            User(
                email=f"extra{n}@northwind.example",
                display_name=f"Extra {n:03}",
                department_id=announcements.ids["kitchen"],
            )
            for n in range(205)
        )
        db.commit()
    created = post(announcements, "chef", "kitchen")
    url = f"/api/announcements/{created['id']}/reads"
    page = announcements.browser("chef").get(url, params={"limit": "200"}).json()
    assert len(page["items"]) == 200 and page["next_cursor"] is not None
    # The default page is 50.
    assert len(announcements.browser("chef").get(url).json()["items"]) == 50


def test_a_read_list_cursor_outside_the_audience_is_refused(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    url = f"/api/announcements/{created['id']}/reads"
    chef = announcements.browser("chef")
    # A bookmark to someone in the audience works...
    assert (
        chef.get(url, params={"cursor": encode_cursor(announcements.ids["ana"])}).status_code == 200
    )
    # ...but not to someone outside it (Front's Dana), a deactivated person, another
    # company's person, or nobody: the same 422 for each, so a cursor cannot be used to
    # learn where they sort.
    for outsider in ("dana", "gone", "b_ana"):
        response = chef.get(url, params={"cursor": encode_cursor(announcements.ids[outsider])})
        assert response.status_code == 422, outsider
    assert chef.get(url, params={"cursor": encode_cursor(uuid.uuid4())}).status_code == 422


def test_read_marks_cannot_cross_companies(announcements: ShiftSetup) -> None:
    ours = post(announcements, "owner", "company")
    # Through the API: company B's people cannot mark company A's announcement.
    assert (
        announcements.browser("b_ana").post(f"/api/announcements/{ours['id']}/read").status_code
        == 404
    )
    # In the database (tenancy layer 2): a mark in company B for company A's announcement,
    # or a mark in company A by company B's person, is refused by the company-aware keys.
    with announcements.engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys = ON")
    try:
        for company, person in (
            (announcements.company_b, announcements.ids["b_ana"]),
            (announcements.company_a, announcements.ids["b_ana"]),
        ):
            with announcements.db(company) as db:
                db.add(
                    AnnouncementRead(
                        announcement_id=uuid.UUID(ours["id"]), user_id=person, read_at=utcnow()
                    )
                )
                with pytest.raises(IntegrityError):
                    db.commit()
    finally:
        with announcements.engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys = OFF")
    assert saved_marks(announcements) == set()
    assert saved_marks(announcements, announcements.company_b) == set()


def test_the_reader_list_never_loads_other_audiences(announcements: ShiftSetup) -> None:
    """The audience filter is in the database: in a company with many audiences, the query
    for one reader returns only that reader's rows, not everything for the code to sort
    out afterwards."""
    with announcements.db() as db:
        # Twenty more departments, each with a team, and an announcement for each.
        for n in range(20):
            dept = Department(name=f"Wing {n}")
            db.add(dept)
            db.flush()
            crew = Team(name=f"Crew {n}", department_id=dept.id)
            db.add(crew)
            db.flush()
            for audience in ({"department_id": dept.id}, {"team_id": crew.id}):
                db.add(
                    Announcement(
                        author_id=announcements.ids["owner"],
                        audience_type="department" if "department_id" in audience else "team",
                        title="Not for Ana",
                        body="B",
                        **audience,
                    )
                )
        db.commit()
    mine = {post(announcements, "owner", a, title="For Ana")["id"] for a in ("company", "kitchen")}
    post(announcements, "owner", "front", title="Not for Ana")
    post(announcements, "owner", "crew", title="Not for Ana")
    with announcements.db() as db:
        ana = db.get(User, announcements.ids["ana"])
        assert ana is not None
        total = db.scalar(select(func.count(Announcement.id)))
        # The rows the database sends back for Ana, with room for every announcement.
        rows = repository.list_for_reader(
            db,
            reader_id=ana.id,
            department_id=ana.department_id,
            team_ids=repository.active_team_ids(db, ana.id),
            after=None,
            limit=1000,
        )
    assert total == 44
    assert {str(row[0].id) for row in rows} == mine
    assert len(rows) == 2
