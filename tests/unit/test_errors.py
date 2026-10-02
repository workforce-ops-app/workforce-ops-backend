"""Every error is RFC 9457 problem details, and none reveals internals or echoes input.

Each test adds a small route to the app that fails on purpose, then checks the response.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterator

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.testclient import TestClient

from app.core import errors
from app.core.config import Settings

Handler = Callable[[Request, Exception], Awaitable[JSONResponse]]

PROBLEM = "application/problem+json"


def assert_problem(response_json: dict, status: int, title: str) -> None:
    assert response_json["type"] == "about:blank"
    assert response_json["status"] == status
    assert response_json["title"] == title


def test_unknown_path_is_a_404_problem(client: TestClient) -> None:
    response = client.get("/api/no-such-thing")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith(PROBLEM)
    assert_problem(response.json(), 404, "Not Found")


def test_wrong_method_is_a_405_problem_that_keeps_the_allow_header(client: TestClient) -> None:
    response = client.post("/api/health")

    assert response.status_code == 405
    assert response.headers["content-type"].startswith(PROBLEM)
    assert_problem(response.json(), 405, "Method Not Allowed")
    assert response.headers["allow"] == "GET"


def test_raised_http_error_keeps_status_and_detail(app: FastAPI, client: TestClient) -> None:
    @app.get("/api/test/forbidden")
    def forbidden() -> None:
        raise HTTPException(status_code=403, detail="Not allowed")

    response = client.get("/api/test/forbidden")

    assert response.status_code == 403
    assert response.headers["content-type"].startswith(PROBLEM)
    assert_problem(response.json(), 403, "Forbidden")
    assert response.json()["detail"] == "Not allowed"


def test_invalid_input_is_a_422_problem_without_echoing_the_input(
    app: FastAPI, client: TestClient
) -> None:
    @app.get("/api/test/items/{item_id}")
    def item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    # A classic XSS payload (no "/" in it, so it stays one path segment).
    submitted = "<img src=x onerror=alert(1)>"
    response = client.get(f"/api/test/items/{submitted}")

    assert response.status_code == 422
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert_problem(body, 422, "Unprocessable Content")
    assert body["errors"], "expected at least one entry in errors"
    assert body["errors"][0]["location"] == "path.item_id"
    assert body["errors"][0]["message"]
    # Reflecting user input back is how reflected XSS starts.
    assert "onerror" not in response.text


SENSITIVE_MESSAGE = "database password is hunter2"


def add_crash_route(app: FastAPI) -> None:
    @app.get("/api/test/crash")
    def crash() -> None:
        raise RuntimeError(SENSITIVE_MESSAGE)


def failed_request_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if getattr(r, "fields", {}).get("action") == "request.failed"]


def test_unexpected_error_is_a_500_problem_that_hides_internals(app: FastAPI) -> None:
    add_crash_route(app)
    # The default TestClient raises any exception that escapes the app, so this test also
    # proves the error is not raised again for the server to log in full.
    client = TestClient(app)

    response = client.get("/api/test/crash")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert_problem(body, 500, "Internal Server Error")
    assert body["detail"] == "An unexpected error occurred."
    assert body["error_id"]
    # Nothing about the real failure reaches the browser (threat model I4).
    assert SENSITIVE_MESSAGE not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text


def test_unexpected_error_log_has_the_error_id_but_not_the_message(
    app: FastAPI, client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    add_crash_route(app)

    response = client.get("/api/test/crash")

    [record] = failed_request_records(caplog)
    assert record.fields["error_id"] == response.json()["error_id"]  # type: ignore[attr-defined]
    assert record.fields["error"] == "RuntimeError"  # type: ignore[attr-defined]
    assert any("in crash" in frame for frame in record.fields["stack"])  # type: ignore[attr-defined]
    # Exception messages can hold passwords, SQL, or submitted values (decision 0031).
    assert record.exc_info is None
    assert SENSITIVE_MESSAGE not in caplog.text


def settings_for(app_env: str) -> Settings:
    return Settings(app_env=app_env, database_url="mysql+pymysql://test:test@localhost:3307/test")  # type: ignore[arg-type]


# Overriding the settings fixture builds the app before the test starts capturing logs.
@pytest.mark.parametrize(
    ("settings", "full_errors_logged"),
    [
        (settings_for("development"), True),
        (settings_for("test"), False),
        (settings_for("production"), False),
    ],
    ids=["development", "test", "production"],
)
def test_full_errors_are_logged_only_in_development(
    app: FastAPI, caplog: pytest.LogCaptureFixture, full_errors_logged: bool
) -> None:
    add_crash_route(app)

    response = TestClient(app).get("/api/test/crash")

    [record] = failed_request_records(caplog)
    assert (record.exc_info is not None) == full_errors_logged
    assert (SENSITIVE_MESSAGE in caplog.text) == full_errors_logged
    assert SENSITIVE_MESSAGE not in response.text


def test_error_after_the_response_started_is_logged_and_not_raised(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    @app.get("/api/test/stream")
    def stream() -> StreamingResponse:
        def chunks() -> Iterator[str]:
            yield "first chunk"
            raise RuntimeError(SENSITIVE_MESSAGE)

        return StreamingResponse(chunks())

    response = TestClient(app).get("/api/test/stream")

    # The 200 was already sent, so no 500 can follow; the error is still logged safely.
    assert response.status_code == 200
    [record] = failed_request_records(caplog)
    assert record.exc_info is None
    assert SENSITIVE_MESSAGE not in caplog.text


def test_non_http_traffic_passes_through(app: FastAPI) -> None:
    # Startup and shutdown ("lifespan") events go straight through the middleware.
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize(
    "handler",
    [errors.http_exception_handler, errors.request_validation_error_handler],
)
def test_handlers_do_not_answer_for_errors_they_do_not_own(handler: Handler) -> None:
    # A handler that receives an exception type it does not own re-raises it
    # instead of answering with the wrong status.
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})

    with pytest.raises(ValueError):
        asyncio.run(handler(request, ValueError("not mine")))
