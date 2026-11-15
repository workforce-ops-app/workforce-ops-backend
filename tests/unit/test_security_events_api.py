"""The security page's endpoints (docs/features/detection.md, "Backend").

The list, its filters and pages, and the summary, as the owner and the administrator.
Other companies, managers, employees, and the platform table are in
tests/security/test_security_events_api.py.
"""

from app.authz.roles import _grants_for
from tests.security_event_data import XSS_EXCERPT, events
from tests.shift_data import ShiftSetup, shifts

__all__ = ["events", "shifts"]  # the fixtures, imported so pytest finds them here


def test_the_starting_roles_grant_security_view_to_owner_and_administrator_only() -> None:
    assert "security.view" in _grants_for("owner")
    assert "security.view" in _grants_for("administrator")
    assert "security.view" not in _grants_for("manager")
    assert "security.view" not in _grants_for("employee")


def test_the_owner_lists_the_companys_events_newest_first(events: ShiftSetup) -> None:
    page = events.browser("owner").get("/api/security-events")
    assert page.status_code == 200
    items = page.json()["items"]
    assert [e["kind"] for e in items] == [
        "detection.xss",
        "detection.summary",
        "detection.sql_injection",
        "detection.path_traversal",
    ]
    first = items[0]
    assert first | {"id": None, "occurred_at": None} == {
        "id": None,
        "kind": "detection.xss",
        "pattern_id": "XSS-02",
        "field": "body.note",
        "method": "PATCH",
        "route": "/api/shifts/{shift_id}",
        "user_id": str(events.ids["ana"]),
        "user_name": "Ana",
        "client_address": "203.0.113.7",
        "request_id": "req-1",
        "excerpt": XSS_EXCERPT,
        "count": 1,
        "occurred_at": None,
    }
    # Times are sent in UTC with their zone.
    assert first["occurred_at"].endswith("Z") or first["occurred_at"].endswith("+00:00")
    assert page.json()["next_cursor"] is None


def test_an_administrator_sees_them_through_the_starting_role(events: ShiftSetup) -> None:
    admin = events.browser("admin")
    assert len(admin.get("/api/security-events").json()["items"]) == 4
    assert admin.get("/api/security-events/summary").status_code == 200


def test_the_list_is_filtered_by_kind_person_and_days(events: ShiftSetup) -> None:
    owner = events.browser("owner")

    def kinds(**params: object) -> list[str]:
        response = owner.get("/api/security-events", params=params)
        assert response.status_code == 200, response.text
        return [e["kind"] for e in response.json()["items"]]

    assert kinds(kind="detection.sql_injection") == ["detection.sql_injection"]
    assert kinds(user_id=events.ids["chef"]) == ["detection.sql_injection"]
    assert kinds(user_id=events.ids["ana"], kind="detection.xss") == ["detection.xss"]
    # Days are the company's (America/Chicago), both included. The last 20 days hold the
    # first three; 10 days ago alone holds the SQL injection.
    from datetime import UTC, datetime, timedelta
    from zoneinfo import ZoneInfo

    today = datetime.now(UTC).astimezone(ZoneInfo("America/Chicago")).date()
    assert len(kinds(**{"from": today - timedelta(days=20)})) == 3
    ten = today - timedelta(days=10)
    # The event is "10 days ago" in UTC; in Chicago it can fall on the day before.
    around = kinds(**{"from": ten - timedelta(days=1), "to": ten + timedelta(days=1)})
    assert around == ["detection.sql_injection"]
    assert kinds(**{"to": today - timedelta(days=30)}) == ["detection.path_traversal"]


def test_the_list_pages_with_a_cursor(events: ShiftSetup) -> None:
    owner = events.browser("owner")
    first = owner.get("/api/security-events", params={"limit": 3}).json()
    rest = owner.get(
        "/api/security-events", params={"limit": 3, "cursor": first["next_cursor"]}
    ).json()
    assert [e["kind"] for e in first["items"]][-1] == "detection.sql_injection"
    assert [e["kind"] for e in rest["items"]] == ["detection.path_traversal"]
    assert rest["next_cursor"] is None


def test_bad_filters_are_refused(events: ShiftSetup) -> None:
    owner = events.browser("owner")
    for params in (
        {"kind": "detection.dropped"},  # platform-only: never in a company's events
        {"kind": "anything"},
        {"kind": "x" * 51},
        {"from": "2026-02-10", "to": "2026-02-01"},
        {"from": "yesterday"},
        {"user_id": "not-an-id"},
        {"cursor": "nonsense"},
        {"limit": 201},
        {"limit": 0},
    ):
        assert owner.get("/api/security-events", params=params).status_code == 422, params


def test_the_summary_counts_each_kind_in_both_windows(events: ShiftSetup) -> None:
    response = events.browser("owner").get("/api/security-events/summary")
    assert response.status_code == 200
    counts = {k["kind"]: (k["last_7_days"], k["last_30_days"]) for k in response.json()["kinds"]}
    assert counts == {
        "detection.sql_injection": (0, 1),  # 10 days ago
        "detection.xss": (1, 1),
        "detection.path_traversal": (0, 0),  # 40 days ago: in neither window
        "detection.command_injection": (0, 0),
        "detection.format_string": (0, 0),
        # A summary row stands for the events the rate cap held back: 15, not 1.
        "detection.summary": (15, 15),
    }
