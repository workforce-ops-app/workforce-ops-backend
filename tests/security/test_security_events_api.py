"""The security page's endpoints against their threats (detection.md, "Audit and security").

I1 (another company's events), I2 (managers and employees, who must never see security
events, their own included), T7 (attack text in answers), E8 (calling the API directly
when the page is hidden). Every request goes through the real app, and each test checks
what the attacker gets back.
"""

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.audit.models import AuditEvent
from app.modules.org.repository import encode_cursor
from app.modules.security.models import SecurityEvent
from tests.security_event_data import PLATFORM_EXCERPT, THEIR_EXCERPT, XSS_EXCERPT, events
from tests.shift_data import BASE_URL, ShiftSetup, shifts

__all__ = ["events", "shifts"]  # the fixtures, imported so pytest finds them here

LIST, SUMMARY = "/api/security-events", "/api/security-events/summary"


def _everything(client: TestClient, setup: ShiftSetup) -> str:
    """Every answer the list gives under every filter, as one text to search."""
    params_list: list[dict] = [
        {},
        {"kind": "detection.xss"},
        {"user_id": setup.ids["b_ana"]},
        {"user_id": setup.ids["ana"]},
        {"from": "2000-01-01", "to": "2100-01-01"},
        {"limit": 200},
    ]
    return "".join(client.get(LIST, params=params).text for params in params_list)


def test_another_companys_events_never_appear(events: ShiftSetup) -> None:
    owner = events.browser("owner")
    seen = _everything(owner, events)
    assert THEIR_EXCERPT not in seen and str(events.ids["b_ana"]) not in seen
    # Their person as a filter: an empty page, not their events and not an error.
    theirs = owner.get(LIST, params={"user_id": events.ids["b_ana"]})
    assert theirs.status_code == 200 and theirs.json()["items"] == []
    # Their summary is theirs: our xss count is only our own one event.
    counts = {k["kind"]: k["last_7_days"] for k in owner.get(SUMMARY).json()["kinds"]}
    assert counts["detection.xss"] == 1
    # And the other way round: their owner-level view (b_chef has no security.view, so
    # check from the database) holds only their row.
    with events.db(events.company_b) as db:
        assert [e.excerpt for e in db.scalars(select(SecurityEvent))] == [THEIR_EXCERPT]


def test_a_bookmark_naming_another_companys_event_is_not_valid(events: ShiftSetup) -> None:
    with events.db(events.company_b) as db:
        their_id = db.scalars(select(SecurityEvent.id)).one()
    response = events.browser("owner").get(LIST, params={"cursor": encode_cursor(their_id)})
    assert response.status_code == 422
    assert THEIR_EXCERPT not in response.text


def test_events_of_people_not_signed_in_have_no_endpoint(events: ShiftSetup) -> None:
    owner = events.browser("owner")
    assert PLATFORM_EXCERPT not in _everything(owner, events)
    counts = {k["kind"]: k["last_7_days"] for k in owner.get(SUMMARY).json()["kinds"]}
    assert counts["detection.command_injection"] == 0


def test_managers_and_employees_never_see_security_events(events: ShiftSetup) -> None:
    # ana has events of her own and chef is her manager: both get 403, with nothing in it.
    for name in ("chef", "ana", "b_chef", "b_ana"):
        client = events.browser(name)
        for url in (LIST, SUMMARY, f"{LIST}?user_id={events.ids['ana']}"):
            response = client.get(url)
            assert response.status_code == 403, (name, url)
            assert XSS_EXCERPT not in response.text and "detection." not in response.text
    # The permission is not in their menu either.
    assert (
        "security.view"
        not in events.browser("chef").get("/api/sessions/current").json()["permissions"]
    )


def test_signed_out_requests_get_nothing(events: ShiftSetup) -> None:
    stranger = TestClient(events.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]
    for url in (LIST, SUMMARY):
        response = stranger.get(url)
        assert response.status_code == 401 and "detection." not in response.text


def test_the_excerpt_comes_back_as_plain_text_unchanged(events: ShiftSetup) -> None:
    """T7: the answer is JSON with the excerpt exactly as sent, never HTML, never escaped
    into something else; the page then sets it with textContent."""
    response = events.browser("owner").get(LIST, params={"kind": "detection.xss"})
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["items"][0]["excerpt"] == XSS_EXCERPT


def test_events_cannot_be_changed_or_removed_through_the_api(events: ShiftSetup) -> None:
    owner = events.browser("owner")
    event_id = owner.get(LIST).json()["items"][0]["id"]
    for method, url in (
        ("POST", LIST),
        ("DELETE", LIST),
        ("PATCH", f"{LIST}/{event_id}"),
        ("DELETE", f"{LIST}/{event_id}"),
    ):
        assert owner.request(method, url).status_code in (404, 405), (method, url)
    with events.db() as db:
        assert db.scalar(select(func.count(SecurityEvent.id))) == 4


def test_reading_security_events_is_not_audited(events: ShiftSetup) -> None:
    owner = events.browser("owner")
    with events.db() as db:
        before = db.scalar(select(func.count()).select_from(AuditEvent))
    owner.get(LIST)
    owner.get(SUMMARY)
    with events.db() as db:
        assert db.scalar(select(func.count()).select_from(AuditEvent)) == before
