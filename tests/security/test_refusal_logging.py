"""Every refused request leaves exactly one log line, saying who, what, and where, and
never a secret (#92; audit finding A1; ASVS V16.2.1, V16.3.2, V16.3.3).

app/core/request_context.py writes the line. Each test sends requests through the real
app, as the person or the attacker would, and reads the lines they left.

People (tests/shift_data.py): chef manages Kitchen; Front is another department; the
owner holds everything; b_ people are another company's.
"""

import json
import logging
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from app.auth.models import UserSession
from app.auth.sessions import COOKIE_NAME
from app.core.logging import JsonFormatter
from app.core.request_context import (
    AUTHZ_DENIED,
    CSRF_REFUSED,
    NOT_FOUND,
    REAUTH_REQUIRED,
)
from tests.shift_data import BASE_URL, ShiftSetup, iso, shifts, soon

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


@pytest.fixture
def lines(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    """Every log line from INFO up, captured as the app writes it."""
    caplog.set_level(logging.INFO)
    return caplog


def written(caplog: pytest.LogCaptureFixture, logger: str = "app") -> list[dict]:
    """The application's lines written so far (this logger's and those below it), as the
    JSON log format writes them. The test client's own lines (httpx) are left out: they
    are written by the browser's side, outside any request the app handles."""
    formatter = JsonFormatter()
    return [
        json.loads(formatter.format(record))
        for record in caplog.records
        if record.name == logger or record.name.startswith(f"{logger}.")
    ]


def refusals(caplog: pytest.LogCaptureFixture) -> list[dict]:
    return written(caplog, "app.refusals")


def secrets_of(client: TestClient) -> list[str]:
    """What must never appear in a log line: the session cookie and the CSRF token."""
    found = [client.cookies.get(COOKIE_NAME), client.headers.get("X-CSRF-Token")]
    return [value for value in found if value]


def a_front_shift(shifts: ShiftSetup) -> str:
    """A shift in Front, a department chef does not manage."""
    return shifts.new_shift("owner", department_id=shifts.ids["front"])["id"]


def a_week() -> dict[str, str]:
    return {"from": iso(soon())[:10], "to": iso(soon() + timedelta(days=6))[:10]}


def test_a_refused_change_leaves_one_line_with_who_what_and_where(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    front = a_front_shift(shifts)
    chef = shifts.browser("chef")
    lines.clear()
    marker = "a note that must never be logged"
    assert chef.patch(f"/api/shifts/{front}", json={"notes": marker}).status_code == 403
    [line] = refusals(lines)
    assert line["event"] == AUTHZ_DENIED
    assert line["permission"] == "schedule.edit"
    assert line["status"] == 403
    assert line["method"] == "PATCH"
    assert line["route"] == "/api/shifts/{shift_id}"  # the template, never the raw path
    assert line["user_id"] == str(shifts.ids["chef"])
    assert line["company_id"] == str(shifts.company_a)
    assert line["client_address"] == "testclient"
    assert len(line["request_id"]) == 32
    text = json.dumps(line)
    assert marker not in text and front not in text
    assert not any(secret in text for secret in secrets_of(chef))


def test_another_companys_shift_leaves_a_not_found_line(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    # Their record looks missing (404) on purpose, and the line says only that much: the
    # app cannot tell (and must not) whether it is theirs or does not exist.
    theirs = shifts.new_shift("b_chef", department_id=shifts.ids["b_kitchen"])["id"]
    owner = shifts.browser("owner")
    lines.clear()
    assert owner.get(f"/api/shifts/{theirs}").status_code == 404
    assert owner.get(f"/api/shifts/{uuid.uuid4()}").status_code == 404
    found = refusals(lines)
    assert [line["event"] for line in found] == [NOT_FOUND, NOT_FOUND]
    assert {line["route"] for line in found} == {"/api/shifts/{shift_id}"}
    assert {line["user_id"] for line in found} == {str(shifts.ids["owner"])}
    assert theirs not in json.dumps(found)


def test_a_forged_request_leaves_a_csrf_line(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    chef = shifts.browser("chef")
    lines.clear()
    forged = chef.post("/api/shifts", json={}, headers={"Origin": "https://evil.example"})
    assert forged.status_code == 403
    [line] = refusals(lines)
    assert line["event"] == CSRF_REFUSED
    assert line["method"] == "POST"
    assert line["route"] == "/api/shifts"
    # Refused before any session is checked: the line names no person, and it holds no
    # header (not even the forged Origin) and no secret.
    assert "user_id" not in line
    text = json.dumps(line)
    assert "evil.example" not in text
    assert not any(secret in text for secret in secrets_of(chef))


def test_a_missing_password_reentry_is_named(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    # Adding a reporting line needs the password entered again within 5 minutes; signing
    # in counts, so the session's time is moved back first.
    owner = shifts.browser("owner")
    with shifts.db() as db:
        db.execute(update(UserSession).values(reauth_at=None))
        db.commit()
    lines.clear()
    body = {"manager_id": str(shifts.ids["chef"]), "employee_id": str(shifts.ids["ana"])}
    response = owner.post("/api/reporting-lines", json=body)
    assert response.status_code == 403, response.text
    [line] = refusals(lines)
    assert line["event"] == REAUTH_REQUIRED
    assert line["route"] == "/api/reporting-lines"


def test_answers_that_are_not_refusals_leave_no_line(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    chef = shifts.browser("chef")
    lines.clear()
    assert chef.get("/api/shifts", params=a_week()).status_code == 200
    # A path that matches no route reaches no code: not a refusal (scanners send many).
    assert chef.get("/api/no-such-thing").status_code == 404
    # Not signed in, or a malformed body: answered, but nothing was refused.
    signed_out = TestClient(shifts.app, base_url=BASE_URL)  # type: ignore[arg-type]
    assert signed_out.get("/api/shifts", params=a_week()).status_code == 401
    assert chef.post("/api/shifts", json={}).status_code == 422
    assert refusals(lines) == []


def test_each_line_names_its_own_refusal(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    # Several requests, each refused for its own reason: each line names its own, and one
    # request's note never carries into the next.
    front = a_front_shift(shifts)
    chef = shifts.browser("chef")
    lines.clear()
    chef.patch(f"/api/shifts/{front}", json={"notes": "x"})
    chef.post("/api/shifts", json={}, headers={"Origin": "https://evil.example"})
    chef.get(f"/api/shifts/{uuid.uuid4()}")
    found = refusals(lines)
    assert [line["event"] for line in found] == [AUTHZ_DENIED, CSRF_REFUSED, NOT_FOUND]
    assert len({line["request_id"] for line in found}) == 3
    assert "permission" not in found[1] and "permission" not in found[2]


def test_a_forwarded_address_sent_by_the_client_is_not_believed(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    # Only nginx may set the address (uvicorn's allowed proxies, rule DE8): a client that
    # sends the header itself cannot blame another address (threat S6).
    front = a_front_shift(shifts)
    chef = shifts.browser("chef")
    lines.clear()
    chef.patch(f"/api/shifts/{front}", json={"notes": "x"}, headers={"X-Forwarded-For": "1.2.3.4"})
    [line] = refusals(lines)
    assert line["client_address"] == "testclient"


def test_every_line_of_a_request_carries_its_id_and_person(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    # Any line written while a request runs names the request and, once the session is
    # checked, the person, so any line (a 500's, for example) can be traced to both.
    front = a_front_shift(shifts)
    chef = shifts.browser("chef")
    lines.clear()
    chef.patch(f"/api/shifts/{front}", json={"notes": "x"})
    found = written(lines)
    assert found
    assert all(len(line["request_id"]) == 32 for line in found)
    assert all(line["user_id"] == str(shifts.ids["chef"]) for line in found)
    # Outside a request, no request fields at all.
    lines.clear()
    logging.getLogger("app.test").warning("outside any request")
    [outside] = written(lines)
    assert "request_id" not in outside and "user_id" not in outside


def test_a_security_event_and_the_log_line_share_the_request_id(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    # The detection layer takes the same ID (scope["state"]), so a security event can be
    # matched to its request's log lines (docs/features/detection.md).
    detection = shifts.app.state.detection  # type: ignore[attr-defined]
    front = a_front_shift(shifts)
    chef = shifts.browser("chef")
    while not detection.queue.empty():  # the copies of the requests above
        detection.queue.get_nowait()
    lines.clear()
    chef.patch(f"/api/shifts/{front}", json={"notes": "' OR 1=1 --"})
    [line] = refusals(lines)
    copies = [detection.queue.get_nowait() for _ in range(detection.queue.qsize())]
    # Detection's copy of the values, and the refusal's own: the same request, one ID.
    assert len(copies) == 2
    assert {copy.request_id for copy in copies} == {line["request_id"]}


# --- Refusals as security events (#92) -------------------------------------------------


def queued_refusals(shifts: ShiftSetup) -> list:
    """The refusal copies waiting for the detection worker (it does not run in tests)."""
    detection = shifts.app.state.detection  # type: ignore[attr-defined]
    copies = [detection.queue.get_nowait() for _ in range(detection.queue.qsize())]
    return [copy for copy in copies if copy.refusal is not None]


def test_a_refusal_is_handed_to_detection_with_nothing_that_was_sent(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    front = a_front_shift(shifts)
    chef = shifts.browser("chef")
    queued_refusals(shifts)  # empty the queue
    marker = "a note that must never be stored"
    chef.patch(f"/api/shifts/{front}", json={"notes": marker})
    chef.post("/api/shifts", json={}, headers={"Origin": "https://evil.example"})
    denied, forged = queued_refusals(shifts)
    assert (denied.refusal.kind, denied.refusal.permission) == (AUTHZ_DENIED, "schedule.edit")
    assert denied.identity.user_id == shifts.ids["chef"]
    assert denied.route == "/api/shifts/{shift_id}" and denied.values == []
    # Forged: refused before the session was checked, so a platform event (DE9).
    assert forged.refusal.kind == CSRF_REFUSED and forged.identity is None
    assert marker not in repr([denied, forged]) and "evil.example" not in repr(forged)


def test_being_asked_for_the_password_is_not_an_event(
    shifts: ShiftSetup, lines: pytest.LogCaptureFixture
) -> None:
    # The ordinary first step of every sensitive action: logged, but not on the page.
    owner = shifts.browser("owner")
    with shifts.db() as db:
        db.execute(update(UserSession).values(reauth_at=None))
        db.commit()
    queued_refusals(shifts)
    body = {"manager_id": str(shifts.ids["chef"]), "employee_id": str(shifts.ids["ana"])}
    assert owner.post("/api/reporting-lines", json=body).status_code == 403
    assert [line["event"] for line in refusals(lines)][-1] == REAUTH_REQUIRED
    assert queued_refusals(shifts) == []
