"""Posting and managing announcements through the API: the agreed answer, the text rules,
editing, archiving, the managed list with its paging and read counts, and the audit log.

The attacks (other companies, scopes, employees, forged fields, unsafe text) and the scope
tests for the list filter are in tests/security/test_announcements.py.
"""

import uuid

import pytest
from sqlalchemy import select

from app.audit.models import AuditEvent
from app.authz.roles import _grants_for
from app.db.base import utcnow
from app.modules.announcements.models import Announcement, AnnouncementRead
from app.modules.org.models import Team, TeamMember
from tests.announcement_data import announcements, audience_body, post
from tests.shift_data import ShiftSetup, shifts

__all__ = ["announcements", "shifts"]  # the fixtures, imported so pytest finds them here


def managed(setup: ShiftSetup, who: str, **params: str) -> dict:
    response = setup.browser(who).get("/api/announcements/managed", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def audit(setup: ShiftSetup, action: str) -> list[AuditEvent]:
    with setup.db() as db:
        return list(db.scalars(select(AuditEvent).where(AuditEvent.action == action)))


def test_the_starting_roles_grant_posting_to_owners_administrators_and_managers() -> None:
    for role in ("owner", "administrator", "manager"):
        assert "announcement.create" in _grants_for(role)
    assert "announcement.create" not in _grants_for("employee")


def test_a_posted_announcement_has_the_agreed_shape(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen", title="Deep clean", body="Friday at 3.")

    assert set(created) == {
        "id",
        "audience",
        "title",
        "body",
        "author",
        "posted_at",
        "edited_at",
        "archived",
        "read_count",
        "audience_count",
    }
    assert created["audience"] == {
        "type": "department",
        "department_id": str(announcements.ids["kitchen"]),
        "department_name": "Kitchen",
        "team_id": None,
        "team_name": None,
    }
    assert created["author"] == {"id": str(announcements.ids["chef"]), "display_name": "Chef"}
    assert (created["title"], created["body"]) == ("Deep clean", "Friday at 3.")
    assert created["edited_at"] is None and created["archived"] is False
    assert created["posted_at"].endswith("Z") or created["posted_at"].endswith("+00:00")
    assert created["read_count"] == 0


def test_team_and_company_audiences_carry_their_names(announcements: ShiftSetup) -> None:
    crew = post(announcements, "lead", "crew")
    assert crew["audience"] == {
        "type": "team",
        "department_id": None,
        "department_name": None,
        "team_id": str(announcements.ids["crew"]),
        "team_name": "Weekend Crew",
    }
    company = post(announcements, "owner", "company")
    assert company["audience"]["type"] == "company"
    assert company["audience"]["department_id"] is None and company["audience"]["team_id"] is None


def test_the_audience_count_is_the_people_in_it_now(announcements: ShiftSetup) -> None:
    # Kitchen's people: chef, ana, cara, and newbie (invited, still in it); gone is
    # deactivated, and deactivated people are in no audience.
    assert post(announcements, "chef", "kitchen")["audience_count"] == 4
    # The Weekend Crew: Ben.
    assert post(announcements, "lead", "crew")["audience_count"] == 1
    # The company: every active person of company A (company B's are never counted).
    # owner, chef, lead, ana, cara, ben, dana, newbie, manny, pat.
    assert post(announcements, "owner", "company")["audience_count"] == 10


def test_the_audience_is_worked_out_when_counted_not_when_posted(
    announcements: ShiftSetup,
) -> None:
    created = post(announcements, "lead", "crew")
    assert created["audience_count"] == 1
    # Ana joins the crew afterwards: she is in the audience from then on.
    with announcements.db() as db:
        db.add(TeamMember(team_id=announcements.ids["crew"], user_id=announcements.ids["ana"]))
        db.commit()
    [item] = managed(announcements, "lead")["items"]
    assert item["audience_count"] == 2


def test_read_counts_count_the_people_in_the_audience_who_read_it(
    announcements: ShiftSetup,
) -> None:
    created = post(announcements, "chef", "kitchen")
    with announcements.db() as db:
        for name in ("ana", "cara"):
            db.add(
                AnnouncementRead(
                    announcement_id=uuid.UUID(created["id"]),
                    user_id=announcements.ids[name],
                    read_at=utcnow(),
                )
            )
        db.commit()
    [item] = managed(announcements, "chef")["items"]
    assert (item["read_count"], item["audience_count"]) == (2, 4)


def test_text_is_trimmed_but_line_breaks_are_kept(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen", title="  Hello  ", body="\n Line 1\nLine 2 \n")
    assert created["title"] == "Hello"
    assert created["body"] == "Line 1\nLine 2"


@pytest.mark.parametrize(
    ("field", "value", "status"),
    [
        ("title", "x" * 120, 201),
        ("title", "x" * 121, 422),
        ("title", "   ", 422),
        ("title", "", 422),
        ("body", "x" * 4000, 201),
        ("body", "x" * 4001, 422),
        ("body", " \n ", 422),
    ],
)
def test_title_and_body_lengths(
    announcements: ShiftSetup, field: str, value: str, status: int
) -> None:
    body = audience_body(announcements, "kitchen") | {"title": "T", "body": "B"} | {field: value}
    response = announcements.browser("chef").post("/api/announcements", json=body)
    assert response.status_code == status, response.text


@pytest.mark.parametrize(
    "audience",
    [
        {"audience_type": "company", "department_id": "kitchen"},
        {"audience_type": "company", "team_id": "crew"},
        {"audience_type": "department"},
        {"audience_type": "department", "department_id": "kitchen", "team_id": "crew"},
        {"audience_type": "department", "team_id": "crew"},
        {"audience_type": "team"},
        {"audience_type": "team", "team_id": "crew", "department_id": "kitchen"},
        {"audience_type": "everyone"},
    ],
)
def test_the_audience_needs_exactly_the_id_its_type_needs(
    announcements: ShiftSetup, audience: dict
) -> None:
    body = {k: str(announcements.ids.get(v, v)) for k, v in audience.items()}
    response = announcements.browser("owner").post(
        "/api/announcements", json=body | {"title": "T", "body": "B"}
    )
    assert response.status_code == 422, response.text


def test_an_unknown_department_or_team_is_refused(announcements: ShiftSetup) -> None:
    owner = announcements.browser("owner")
    for kind in ("department", "team"):
        body = {"audience_type": kind, f"{kind}_id": str(uuid.uuid4()), "title": "T", "body": "B"}
        assert owner.post("/api/announcements", json=body).status_code == 422


def test_editing_changes_only_the_fields_sent_and_marks_it_edited(
    announcements: ShiftSetup,
) -> None:
    created = post(announcements, "chef", "kitchen", title="Old", body="Old body")
    response = announcements.browser("chef").patch(
        f"/api/announcements/{created['id']}", json={"title": " New "}
    )
    assert response.status_code == 200, response.text
    edited = response.json()
    assert (edited["title"], edited["body"]) == ("New", "Old body")
    assert edited["edited_at"] is not None
    # The audience and the author stay as they were.
    assert edited["audience"] == created["audience"] and edited["author"] == created["author"]
    # The audit entry names the field, never the text.
    [entry] = audit(announcements, "announcement.edited")
    assert entry.details == {"fields": ["title"]}
    assert entry.target_id == uuid.UUID(created["id"])


def test_anyone_whose_scope_covers_it_may_edit_not_only_the_author(
    announcements: ShiftSetup,
) -> None:
    # The lead posts to the crew; the Kitchen manager covers the crew's department.
    created = post(announcements, "lead", "crew")
    response = announcements.browser("chef").patch(
        f"/api/announcements/{created['id']}", json={"body": "Corrected."}
    )
    assert response.status_code == 200
    assert response.json()["author"]["id"] == str(announcements.ids["lead"])


def test_an_empty_edit_changes_nothing(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    response = announcements.browser("chef").patch(f"/api/announcements/{created['id']}", json={})
    assert response.status_code == 200
    assert response.json()["edited_at"] is None
    assert audit(announcements, "announcement.edited") == []


@pytest.mark.parametrize("change", [{"title": None}, {"body": None}, {"title": "  "}])
def test_an_edit_cannot_empty_the_text(announcements: ShiftSetup, change: dict) -> None:
    created = post(announcements, "chef", "kitchen")
    url = f"/api/announcements/{created['id']}"
    assert announcements.browser("chef").patch(url, json=change).status_code == 422


def test_editing_keeps_who_has_read_it(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    with announcements.db() as db:
        db.add(
            AnnouncementRead(
                announcement_id=uuid.UUID(created["id"]),
                user_id=announcements.ids["ana"],
                read_at=utcnow(),
            )
        )
        db.commit()
    url = f"/api/announcements/{created['id']}"
    edited = announcements.browser("chef").patch(url, json={"body": "Now with details."})
    assert edited.json()["read_count"] == 1


def test_archiving_keeps_the_announcement_and_ends_changes(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen")
    chef = announcements.browser("chef")
    url = f"/api/announcements/{created['id']}"
    archived = chef.post(f"{url}/archive")
    assert archived.status_code == 200 and archived.json()["archived"] is True
    # Archived announcements cannot be edited, or archived again (409)...
    assert chef.patch(url, json={"title": "Too late"}).status_code == 409
    assert chef.post(f"{url}/archive").status_code == 409
    # ...and are never deleted.
    with announcements.db() as db:
        saved = db.get(Announcement, uuid.UUID(created["id"]))
        assert saved is not None and saved.title == "Heads up" and saved.archived_at is not None
    [entry] = audit(announcements, "announcement.archived")
    assert entry.target_id == uuid.UUID(created["id"])


def test_posting_is_audited_with_the_audience_but_not_the_text(announcements: ShiftSetup) -> None:
    created = post(announcements, "chef", "kitchen", title="Secret plans", body="Tell nobody.")
    company = post(announcements, "owner", "company")
    entries = {str(e.target_id): e for e in audit(announcements, "announcement.posted")}
    assert entries[created["id"]].details == {
        "audience_type": "department",
        "audience_id": str(announcements.ids["kitchen"]),
    }
    assert entries[created["id"]].actor_id == announcements.ids["chef"]
    assert entries[company["id"]].details == {"audience_type": "company", "audience_id": None}
    assert "Secret" not in str(entries[created["id"]].details)


def test_the_managed_list_is_newest_first_and_paged(announcements: ShiftSetup) -> None:
    ids = [post(announcements, "chef", "kitchen", title=f"No. {n}")["id"] for n in range(5)]
    first = managed(announcements, "chef", limit="2")
    assert [i["id"] for i in first["items"]] == [ids[4], ids[3]]
    second = managed(announcements, "chef", limit="2", cursor=first["next_cursor"])
    assert [i["id"] for i in second["items"]] == [ids[2], ids[1]]
    last = managed(announcements, "chef", limit="2", cursor=second["next_cursor"])
    assert [i["id"] for i in last["items"]] == [ids[0]]
    assert last["next_cursor"] is None


def test_archived_announcements_are_listed_only_when_asked_for(announcements: ShiftSetup) -> None:
    kept = post(announcements, "chef", "kitchen")
    gone = post(announcements, "chef", "kitchen")
    announcements.browser("chef").post(f"/api/announcements/{gone['id']}/archive")
    assert [i["id"] for i in managed(announcements, "chef")["items"]] == [kept["id"]]
    listed = managed(announcements, "chef", include_archived="true")["items"]
    assert {i["id"]: i["archived"] for i in listed} == {kept["id"]: False, gone["id"]: True}


def test_an_archived_teams_audience_is_empty(announcements: ShiftSetup) -> None:
    created = post(announcements, "lead", "crew")
    with announcements.db() as db:
        crew = db.get(Team, announcements.ids["crew"])
        assert crew is not None
        crew.archived_at = utcnow()
        db.commit()
    # Archived scopes cover nothing: the owner still manages it, but nobody is in it.
    [item] = [i for i in managed(announcements, "owner")["items"] if i["id"] == created["id"]]
    assert item["audience_count"] == 0
