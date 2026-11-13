"""The detection layer and its worker, piece by piece (docs/features/detection.md, DT4).

The attacker's view of the whole layer, through the real sign-in and real tables, is in
tests/security/test_detection_layer.py. Here: the collection rules, the copy the layer
hands over, the worker's queue and retries, and the SecretStr walk over every route.
"""

import queue
import time
import typing
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient
from pydantic import BaseModel, SecretStr

from app.detection.detector import MAX_TOTAL_CHARS, MAX_VALUE_CHARS, MAX_VALUES
from app.modules.security.layer import (
    MAX_BODY_BYTES,
    MAX_DEPTH,
    Identity,
    RequestCopy,
    collect,
    detection_skip,
    is_secret_name,
    is_skipped,
)
from app.modules.security.worker import MAX_RETRY, DetectionWorker, events_for
from app.modules.security.writer import Event, EventWriteError

XSS = "<script>alert(1)</script>"
NOON = datetime(2026, 11, 12, 12, 0, 0)


def _copies(app: FastAPI) -> list[RequestCopy]:
    """Every copy the layer has handed to the worker so far (the worker is not running in
    unit tests, so they wait in its queue)."""
    worker: DetectionWorker = app.state.detection
    found = []
    while True:
        try:
            item = worker.queue.get_nowait()
        except queue.Empty:
            return found
        if item is not None:
            found.append(item)


# --- Collection rule 3: secret-like names ------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "password",
        "newPassword",
        "current_password",
        "PASSWD",
        "client_secret",
        "access_token",
        "X-CSRF-Token",
        "api_key",
        "Api-Key",
        "authorization",
        "cookie",
        "session_id",
        "SessionToken",
    ],
)
def test_secret_like_names_are_caught(name: str) -> None:
    assert is_secret_name(name)


@pytest.mark.parametrize("name", ["note", "name", "email", "search", "shift_id", "key", "pass"])
def test_ordinary_names_are_not(name: str) -> None:
    assert not is_secret_name(name)


# --- What collect() reads -----------------------------------------------------------------


def test_collect_reads_path_query_and_json_strings_with_their_names() -> None:
    body = b'{"note": "hi", "items": [{"label": "a"}, "b"], "count": 3, "ok": true}'
    values = collect({"shift_id": "s1"}, b"search=x&page=2", body)
    assert values == [
        ("path.shift_id", "s1"),
        ("query.search", "x"),
        ("query.page", "2"),
        ("body.note", "hi"),
        ("body.items[0].label", "a"),
        ("body.items[1]", "b"),
    ]


def test_secret_named_fields_are_left_out_with_everything_inside_them() -> None:
    body = (
        b'{"note": "kept", "auth": {"api_key": "k1", "inner": {"password": "k2"}},'
        b' "list": [{"session_token": {"deep": "k3"}}, {"Cookie": ["k4"]}],'
        b' "credentials": {"clientSecret": "k5"}}'
    )
    values = collect({"invite_token": "k6"}, b"access_token=k7&q=kept2", body)
    assert values == [("query.q", "kept2"), ("body.note", "kept")]
    assert not any(secret in text for _, text in values for secret in ("k1", "k2", "k3"))


def test_query_values_are_decoded_once_as_the_endpoint_sees_them() -> None:
    # %2527 decodes to %27 here; the detector decodes the rest (normalization step 1).
    assert collect({}, b"q=%2527+or", None) == [("query.q", "%27 or")]


def test_a_body_that_is_not_json_has_nothing_to_collect() -> None:
    assert collect({}, b"", b"{not json") == []
    assert collect({}, b"", b"[" * 100_000) == []  # too deep for the parser


def test_the_caps_apply_while_copying() -> None:
    # At most 200 values (DE4).
    many = b"&".join(f"v{n}=x".encode() for n in range(MAX_VALUES + 50))
    assert len(collect({}, many, None)) == MAX_VALUES
    # Each value cut to 2,000 characters.
    [(_, text)] = collect({}, b"q=" + b"a" * 5_000, None)
    assert len(text) == MAX_VALUE_CHARS
    # At most 100,000 characters in all.
    big = b'{"v": [' + b",".join(b'"' + b"b" * 1_900 + b'"' for _ in range(100)) + b"]}"
    values = collect({}, b"", big)
    assert sum(len(text) for _, text in values) == MAX_TOTAL_CHARS


def test_very_deep_json_is_cut_off() -> None:
    deep: str = '"bottom"'
    for _ in range(MAX_DEPTH + 10):
        deep = f'{{"a": {deep}}}'
    assert collect({}, b"", deep.encode()) == []
    shallow = '{"a": {"a": "top"}}'
    assert collect({}, b"", shallow.encode()) == [("body.a.a", "top")]


def test_long_field_names_fit_the_column() -> None:
    [(name, _)] = collect({}, b"q" * 300 + b"=x", None)
    assert len(name) == 100


# --- The copy the middleware hands over ---------------------------------------------------


def test_a_request_is_copied_with_its_route_template(client: TestClient, app: FastAPI) -> None:
    client.get(f"/api/health?note={XSS}")
    [copy] = _copies(app)
    assert copy.values == [("query.note", XSS)]
    assert copy.method == "GET" and copy.route == "/api/health"
    assert copy.identity is None  # no valid session
    assert len(copy.request_id) == 32


def test_requests_without_values_are_not_queued(client: TestClient, app: FastAPI) -> None:
    client.get("/api/health")
    assert _copies(app) == []


def test_an_unknown_route_is_still_copied_without_a_route(client: TestClient, app: FastAPI) -> None:
    client.get(f"/api/nothing-here?q={XSS}")
    [copy] = _copies(app)
    assert copy.route is None and copy.values == [("query.q", XSS)]


def test_only_json_bodies_are_kept(client: TestClient, app: FastAPI) -> None:
    client.post(
        "/api/departments", content=f'{{"name": "{XSS}"}}', headers={"Content-Type": "text/plain"}
    )
    client.post("/api/departments", json={"name": XSS})
    copies = _copies(app)
    assert [copy.values for copy in copies] == [[("body.name", XSS)]]


def test_a_body_over_the_limit_is_not_kept(client: TestClient, app: FastAPI) -> None:
    client.post("/api/departments", json={"name": XSS, "pad": "x" * MAX_BODY_BYTES})
    assert _copies(app) == []


def test_a_body_the_app_never_read_is_not_inspected(client: TestClient, app: FastAPI) -> None:
    """The CSRF check refuses this before the body is read; the layer never reads ahead of
    the endpoint (DE1), so only the query string is copied."""
    refused = TestClient(app)  # no Origin header
    assert refused.post(f"/api/departments?q={XSS}", json={"name": XSS}).status_code == 403
    [copy] = _copies(app)
    assert copy.values == [("query.q", XSS)]


def test_credential_routes_are_not_copied_at_all(client: TestClient, app: FastAPI) -> None:
    client.post(f"/api/sessions?q={XSS}", json={"email": XSS, "password": XSS})
    # Even refused by the CSRF check (no Origin), it is still known to be sign-in.
    TestClient(app).post(f"/api/sessions?q={XSS}", json={"email": XSS, "password": XSS})
    assert _copies(app) == []


def test_a_failure_in_the_layer_never_reaches_the_request(
    client: TestClient, app: FastAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.modules.security import layer

    def broken(*_: object) -> list:
        raise RuntimeError("detection bug")

    monkeypatch.setattr(layer, "collect", broken)
    response = client.get(f"/api/health?q={XSS}")
    assert response.status_code == 200 and response.json() == {"status": "ok"}


# --- detection_skip and the SecretStr walk (collection rule 4) ---------------------------


def _secret_fields(annotation: Any, prefix: str) -> list[str]:
    """The names of every SecretStr field inside a type, at any depth: nested models,
    lists, and optional fields."""
    if annotation is SecretStr:
        return [prefix]
    found: list[str] = []
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        for name, info in annotation.model_fields.items():
            found += _secret_fields(info.annotation, name)
    for argument in typing.get_args(annotation):
        found += _secret_fields(argument, prefix)
    return found


def secret_field_problems(routes: list[Any]) -> list[str]:
    """Every SecretStr field on a route that is not skipped and whose own name rule 3
    does not catch: a credential that would reach detection."""
    problems = []
    for context in iter_route_contexts(routes):  # every route, inside included routers too
        route = context.original_route
        if not isinstance(route, APIRoute) or is_skipped(route):
            continue
        dependant = route.dependant
        params = [*dependant.body_params, *dependant.query_params, *dependant.path_params]
        for param in params:
            for name in _secret_fields(param.field_info.annotation, param.name):
                if not is_secret_name(name):
                    problems.append(f"{route.methods} {route.path}: {name}")
    return problems


def test_every_credential_field_is_kept_out_of_detection(app: FastAPI) -> None:
    """Rule 4: every password or token in a request model is a SecretStr, and each one is
    on a skipped route or has a name rule 3 catches. A new credential field that fails
    this would reach detection unnoticed."""
    assert secret_field_problems(app.router.routes) == []
    # And the walk really sees the credential fields: sign-in has one, and is skipped.
    [sign_in] = [
        c.original_route
        for c in iter_route_contexts(app.router.routes)
        if isinstance(c.original_route, APIRoute)
        and c.original_route.path == "/api/sessions"
        and "POST" in c.original_route.methods
    ]
    assert is_skipped(sign_in)
    assert _secret_fields(sign_in.dependant.body_params[0].field_info.annotation, "body") == [
        "password"
    ]


def test_every_route_that_takes_a_credential_is_skipped(app: FastAPI) -> None:
    """Stricter than rule 4: a route that takes a SecretStr takes a credential, so it is
    a credential route and must be marked detection_skip (rule 2), even when rule 3
    would already catch the field by its name. Rule 2 also keeps out the other fields of
    such a request, such as the email at sign-in."""
    unmarked = []
    for context in iter_route_contexts(app.router.routes):
        route = context.original_route
        if not isinstance(route, APIRoute) or is_skipped(route):
            continue
        dependant = route.dependant
        params = [*dependant.body_params, *dependant.query_params, *dependant.path_params]
        if any(_secret_fields(p.field_info.annotation, p.name) for p in params):
            unmarked.append(f"{sorted(route.methods)} {route.path}")
    assert unmarked == []


def test_the_walk_catches_a_credential_that_would_slip_through() -> None:
    class Inner(BaseModel):
        pin: SecretStr

    class Unsafe(BaseModel):
        note: str
        inner: list[Inner] | None = None
        new_password: SecretStr | None = None  # caught by rule 3 by its name

    router = APIRouter()

    @router.post("/unsafe")
    def unsafe(body: Unsafe) -> None: ...

    @router.post("/skipped")
    @detection_skip
    def skipped(body: Unsafe) -> None: ...

    assert secret_field_problems(router.routes) == ["{'POST'} /unsafe: pin"]


# --- The worker -------------------------------------------------------------------------


def _copy(values: list[tuple[str, str]], identity: Identity | None = None) -> RequestCopy:
    return RequestCopy(
        values=values,
        method="POST",
        route="/api/things",
        client_address="203.0.113.5",
        request_id="r1",
        occurred_at=NOON,
        identity=identity,
    )


@dataclass
class FakeWriter:
    """Records what the worker hands it; can be told to fail."""

    written: list[list[Event]] = field(default_factory=list)
    dropped: list[int] = field(default_factory=list)
    fail_next: int = 0  # how many of the next write() calls fail (saving nothing)
    fail_drops: bool = False
    closed: bool = False
    flushes: int = 0

    def write(self, events: list[Event]) -> None:
        if self.fail_next:
            self.fail_next -= 1
            raise EventWriteError(list(events))
        self.written.append(list(events))

    def record_dropped(self, count: int) -> None:
        if self.fail_drops:
            raise EventWriteError([])
        self.dropped.append(count)

    def flush_due(self) -> None:
        self.flushes += 1

    def close(self) -> None:
        self.closed = True


def _worker(writer: FakeWriter, **options: Any) -> DetectionWorker:
    return DetectionWorker(lambda: writer, **options)  # type: ignore[arg-type,return-value]


def test_events_go_to_the_sessions_company_or_the_platform() -> None:
    who = Identity(uuid.uuid4(), uuid.uuid4(), uuid.uuid4())
    [signed] = events_for(_copy([("body.note", XSS)], who))
    assert (signed.company_id, signed.user_id) == (who.company_id, who.user_id)
    assert signed.source == f"session:{who.session_id}"
    assert signed.kind == "detection.xss" and signed.field == "body.note"
    assert signed.excerpt == XSS and signed.request_id == "r1"
    [anonymous] = events_for(_copy([("body.note", XSS)]))
    assert anonymous.company_id is None and anonymous.user_id is None
    assert anonymous.source == "address:203.0.113.5"
    assert events_for(_copy([("body.note", "see you at 5")])) == []


def test_a_full_queue_drops_and_counts_without_waiting() -> None:
    worker = _worker(FakeWriter(), size=3)
    started = time.perf_counter()
    for _ in range(10):
        worker.submit(_copy([("q", XSS)]))
    assert time.perf_counter() - started < 0.5
    assert worker.queue.qsize() == 3 and worker.dropped == 7


def test_drops_are_written_once_a_minute_and_kept_if_that_fails() -> None:
    writer = FakeWriter(fail_drops=True)
    worker = _worker(writer, size=1)
    for _ in range(3):
        worker.submit(_copy([("q", XSS)]))
    worker.drain()
    assert writer.dropped == []  # not a minute yet
    worker.clock = lambda: time.monotonic() + 61
    worker.run_once()
    assert writer.dropped == [] and worker.dropped == 2  # failed: kept for next time
    writer.fail_drops = False
    worker.clock = lambda: time.monotonic() + 122
    worker.run_once()
    assert writer.dropped == [2] and worker.dropped == 0


def test_unsaved_events_are_written_again_with_the_next_copy() -> None:
    writer = FakeWriter(fail_next=1)
    worker = _worker(writer)
    worker.submit(_copy([("a", XSS)]))
    worker.submit(_copy([("b", "' OR 1=1 --")]))
    worker.drain()
    # The first batch failed; it went again together with the second.
    [batch] = writer.written
    assert [event.field for event in batch][0] == "a"
    assert {event.field for event in batch} == {"a", "b"}


def test_unsaved_events_are_bounded() -> None:
    """A long database outage cannot grow memory without bound: at most MAX_RETRY
    unsaved events are kept, the newest ones."""
    writer = FakeWriter(fail_next=8)
    worker = _worker(writer)
    values = [(f"v{n}", XSS) for n in range(150)]
    for _ in range(8):  # 8 x 150 = 1,200 unsaved events, more than MAX_RETRY
        worker._write(events_for(_copy(values)))
    worker._write(events_for(_copy(values)))  # the database is back
    [batch] = writer.written
    assert len(batch) == MAX_RETRY + 150


def test_stop_handles_the_queue_and_writes_what_is_held() -> None:
    writer = FakeWriter()
    worker = _worker(writer, size=1)
    worker.start()
    worker.submit(_copy([("a", XSS)]))
    deadline = time.monotonic() + 5
    while not writer.written and time.monotonic() < deadline:
        time.sleep(0.01)
    assert writer.written  # the thread handled it
    worker.stop()
    assert writer.closed


def test_an_idle_worker_never_opens_a_connection() -> None:
    def no_writer() -> Any:
        raise AssertionError("the writer was made")

    worker = DetectionWorker(no_writer)
    worker.run_once()
    worker.stop()
