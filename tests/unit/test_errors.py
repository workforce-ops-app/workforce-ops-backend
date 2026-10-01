"""Every error is RFC 9457 problem details, and none reveals internals or echoes input.

Each test adds a small route to the app that fails on purpose, then checks the response.
"""

import asyncio
from collections.abc import Awaitable, Callable

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.core import errors

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


@pytest.mark.parametrize("secret", ["database password is hunter2"])
def test_unexpected_error_is_a_500_problem_that_hides_internals(
    app: FastAPI, client: TestClient, secret: str
) -> None:
    @app.get("/api/test/crash")
    def crash() -> None:
        raise RuntimeError(secret)

    response = client.get("/api/test/crash")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert_problem(body, 500, "Internal Server Error")
    assert body["detail"] == "An unexpected error occurred."
    # Nothing about the real failure reaches the browser (threat model I4).
    assert secret not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text


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
