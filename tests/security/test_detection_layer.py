"""The detection layer from the attacker's side (docs/features/detection.md, DT4).

Through the real app, the real sign-in, and the real security event tables. What must
hold:
- DE1: an attack string gets exactly the answer it would get without detection.
- DE3 (threat I8): secrets never enter detection. Attack strings in headers, on the
  sign-in route, and in secret-named fields nested inside objects and lists leave no row
  and no text anywhere: not in either table, not in the log.
- DE11 (threat D5): a full queue never makes a request wait, and the drops are counted.
- DE7 (threat T7): the excerpt is the plain original text, at most 200 characters.
- DE8 (threat S6): the address is the sender's; a header the client writes cannot blame
  another address.
- DE9: an event lands in a company only through a valid session, and only in that
  session's company. A sign-in attempt naming a real company's account writes nothing to
  that company; a request without a session writes only to the platform table.
- DE6: one session cannot fill the table.
"""

import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.base import Base, utcnow
from app.modules.security.models import DROPPED, SUMMARY, PlatformSecurityEvent, SecurityEvent
from app.modules.security.worker import QUEUE_SIZE, DetectionWorker
from app.modules.security.writer import PER_MINUTE, EventWriter
from tests.session_data import BASE_URL, SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here

XSS = "<script>alert(1)</script>"
SQLI = "' OR 1=1 --"


@dataclass
class Clock:
    """The writer's clock, moved by hand so a minute ends when the test says."""

    now: datetime

    def __call__(self) -> datetime:
        return self.now


@dataclass
class Detect:
    setup: SignInSetup
    worker: DetectionWorker
    clock: Clock

    def run(self) -> None:
        """Let the worker handle everything queued (in the test, not a thread)."""
        self.worker.drain()

    def company_rows(self, key: str) -> list[SecurityEvent]:
        company = self.setup.company_a if key == "a" else self.setup.company_b
        with self.setup.session_for(company) as db:
            rows = list(db.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at)))
            db.expunge_all()
            return rows

    def platform_rows(self) -> list[PlatformSecurityEvent]:
        with self.setup.session_for(None) as db:
            rows = list(db.scalars(select(PlatformSecurityEvent)))
            db.expunge_all()
            return rows

    def all_rows(self) -> list[SecurityEvent | PlatformSecurityEvent]:
        return [*self.company_rows("a"), *self.company_rows("b"), *self.platform_rows()]

    def everything_stored(self) -> str:
        """Every value of every row in both tables, as one text to search."""
        columns = ("kind", "pattern_id", "field", "method", "route", "excerpt", "request_id")
        return "\n".join(str(getattr(row, column)) for row in self.all_rows() for column in columns)

    def signed_in(self, key: str = "a_ana") -> TestClient:
        client = self.setup.new_client()
        assert self.setup.sign_in(client, email(self.setup, key)) == 201
        return client


@pytest.fixture
def detect(signin: SignInSetup) -> Iterator[Detect]:
    tables = [SecurityEvent.__table__, PlatformSecurityEvent.__table__]
    Base.metadata.create_all(signin.engine, tables=tables)
    worker: DetectionWorker = signin.client.app.state.detection  # type: ignore[attr-defined]
    clock = Clock(utcnow())
    # The real writer, on the test database, with the test's clock.
    worker.writer = EventWriter(signin.engine, clock=clock)
    yield Detect(signin, worker, clock)


# --- DE1: the answer is never changed --------------------------------------------------------


def test_an_attack_string_gets_the_same_answer(detect: Detect) -> None:
    anonymous = detect.setup.new_client()
    plain = anonymous.get("/api/health?note=see you at 5")
    attack = anonymous.get(f"/api/health?note={XSS}")
    assert (plain.status_code, plain.json()) == (attack.status_code, attack.json())

    ana = detect.signed_in()
    plain = ana.post("/api/departments", json={"name": "Front desk"})
    attack = ana.post("/api/departments", json={"name": SQLI})
    assert plain.status_code == attack.status_code
    assert plain.json() == attack.json()

    detect.run()
    # The attacks were still seen and recorded.
    assert {row.field for row in detect.platform_rows()} == {"query.note"}
    assert {row.field for row in detect.company_rows("a")} == {"body.name"}


# --- DE3: secrets never enter detection --------------------------------------------------


def _app_log(caplog: pytest.LogCaptureFixture) -> str:
    """What the application logged (not the test client's own log of the URLs it sent)."""
    return " | ".join(
        record.getMessage() + str(getattr(record, "fields", ""))
        for record in caplog.records
        if record.name.startswith("app")
    )


def test_headers_are_never_collected(detect: Detect, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    client = detect.setup.new_client()
    client.cookies.set("tracking", f"{XSS}H1")
    client.get(
        "/api/health",
        headers={
            "User-Agent": f"{XSS}H2",
            "Referer": f"https://x.example/{XSS}H3",
            "X-Anything": f"{SQLI}H4",
            "Authorization": f"Bearer {XSS}H5",
        },
    )
    detect.run()
    assert detect.all_rows() == []
    for marker in ("H1", "H2", "H3", "H4", "H5"):
        assert marker not in _app_log(caplog)


def test_sign_in_is_never_inspected(detect: Detect, caplog: pytest.LogCaptureFixture) -> None:
    """Rule 2: not even the email is copied, since it may hold a password typed into the
    wrong field. And an email naming a real company's account can never place an event
    in that company (DE9)."""
    caplog.set_level(logging.DEBUG)
    real = email(detect.setup, "a_ana")
    client = detect.setup.new_client()
    client.post("/api/sessions", json={"email": f"{real}{XSS}", "password": f"{SQLI}P1"})
    client.post("/api/sessions", json={"email": real, "password": f"{XSS}P2"})
    client.post(f"/api/sessions?q={XSS}P3", json={"email": real, "password": "x"})
    # Refused by the CSRF check (no Origin), and still known to be sign-in.
    TestClient(detect.setup.client.app, base_url=BASE_URL).post(
        "/api/sessions", json={"email": real, "password": f"{XSS}P4"}
    )
    assert detect.worker.queue.qsize() == 0  # nothing was even copied
    detect.run()
    assert detect.company_rows("a") == [] and detect.all_rows() == []
    for marker in ("P1", "P2", "P3", "P4"):
        assert marker not in _app_log(caplog)


def test_secret_named_fields_are_left_out_at_any_depth(
    detect: Detect, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    ana = detect.signed_in()
    ana.post(
        f"/api/departments?access_token={XSS}K1&search={XSS}",
        json={
            "name": XSS,
            "settings": {
                "api_key": f"{XSS}K2",
                "inner": [{"newPassword": f"{SQLI}K3"}, {"note": SQLI}],
            },
            "Session-Data": {"anything": "../../etc/passwd K4"},
            "list": [[{"client_secret": [f"{XSS}K5"]}]],
            "csrf": f"{XSS}K6",
        },
    )
    detect.run()
    stored = detect.everything_stored()
    # The ordinary fields were inspected...
    assert {row.field for row in detect.company_rows("a")} == {
        "query.search",
        "body.name",
        "body.settings.inner[1].note",
    }
    # ...and nothing of the secret-named ones is anywhere.
    for marker in ("K1", "K2", "K3", "K4", "K5", "K6"):
        assert marker not in stored
        assert marker not in _app_log(caplog)


# --- DE11: a full queue never slows a request --------------------------------------------


def test_a_full_queue_never_slows_a_request(detect: Detect) -> None:
    client = detect.setup.new_client()

    def timed(count: int) -> float:
        started = time.perf_counter()
        for _ in range(count):
            assert client.get(f"/api/health?q={XSS}").status_code == 200
        return (time.perf_counter() - started) / count

    # The worker is paused (nothing takes from the queue): fill it.
    before = timed(QUEUE_SIZE)
    assert detect.worker.queue.full() and detect.worker.dropped == 0
    # Past the limit, requests answer as fast as before; the copies are dropped and counted.
    after = timed(50)
    assert after < before * 3 + 0.01
    assert detect.worker.dropped == 50

    # A minute later the count is written as one platform row, and nothing else is lost.
    detect.run()
    detect.worker.clock = lambda: time.monotonic() + 61
    detect.worker.run_once()
    [dropped] = [row for row in detect.platform_rows() if row.kind == DROPPED]
    assert dropped.count == 50


# --- DE7: the excerpt is plain text ---------------------------------------------------------


def test_the_excerpt_is_the_original_text(detect: Detect) -> None:
    ana = detect.signed_in()
    attack = '<img src=x onerror="alert(document.cookie)">'
    long_note = "a" * 500 + attack + "b" * 500
    ana.post("/api/departments", json={"name": attack, "note": long_note})
    detect.run()
    excerpts = {row.field: row.excerpt for row in detect.company_rows("a")}
    assert excerpts["body.name"] == attack  # stored exactly as sent, not escaped
    assert len(excerpts["body.note"]) <= 200 and attack in excerpts["body.note"]


# --- DE8 and the facts about the request ------------------------------------------------------


def test_the_address_is_the_senders(detect: Detect) -> None:
    client = TestClient(
        detect.setup.client.app,
        base_url=BASE_URL,
        headers={"Origin": BASE_URL},
        client=("203.0.113.5", 50000),
    )
    client.get(f"/api/health?q={XSS}", headers={"X-Forwarded-For": "198.51.100.7"})
    detect.run()
    [row] = detect.platform_rows()
    assert row.client_address == "203.0.113.5"


def test_a_row_names_the_route_template_and_the_request(detect: Detect) -> None:
    ana = detect.signed_in()
    ana.get(f"/api/shifts/{SQLI}")
    detect.run()
    [row] = detect.company_rows("a")
    assert (row.method, row.route, row.field) == ("GET", "/api/shifts/{shift_id}", "path.shift_id")
    assert row.kind == "detection.sql_injection" and row.request_id and len(row.request_id) == 32


# --- DE9: companies never mix ---------------------------------------------------------


def test_a_signed_in_request_lands_only_in_the_sessions_company(detect: Detect) -> None:
    ana = detect.signed_in("a_ana")
    ana.get(f"/api/sessions/current?q={XSS}")
    detect.run()
    [row] = detect.company_rows("a")
    assert row.user_id == detect.setup.people["a_ana"]
    assert detect.company_rows("b") == [] and detect.platform_rows() == []


def test_a_request_without_a_session_lands_only_in_the_platform_table(detect: Detect) -> None:
    anonymous = detect.setup.new_client()
    # Even naming another company's person or ID in the request places nothing there.
    anonymous.get(f"/api/sessions/current?company_id={detect.setup.company_b}&q={XSS}")
    anonymous.post("/api/departments", json={"name": XSS})  # 401
    detect.run()
    assert detect.company_rows("a") == [] and detect.company_rows("b") == []
    assert len(detect.platform_rows()) == 2


def test_a_session_the_route_never_checked_is_not_trusted(detect: Detect) -> None:
    """The health check does not look at the session, so the layer does not take the
    company from the cookie on its own: the cautious way is the platform table."""
    ana = detect.signed_in()
    ana.get(f"/api/health?q={XSS}")
    detect.run()
    assert detect.company_rows("a") == [] and len(detect.platform_rows()) == 1


# --- DE6: one session cannot fill the table -------------------------------------------


def test_one_session_cannot_fill_the_table(detect: Detect) -> None:
    ana = detect.signed_in()
    for _ in range(PER_MINUTE + 5):
        ana.get(f"/api/sessions/current?q={XSS}")
    detect.run()
    assert len(detect.company_rows("a")) == PER_MINUTE
    detect.clock.now += timedelta(minutes=1)
    detect.worker.run_once()  # the minute has ended: its summary row
    [summary] = [row for row in detect.company_rows("a") if row.kind == SUMMARY]
    assert summary.count == 5
