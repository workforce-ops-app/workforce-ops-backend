"""Threat I6: API answers are never kept in the browser's cache (app/core/caching.py).

A later user of a shared computer must not find someone else's answers in the browser's
cache. Every kind of answer is checked, including the ones made before or around the
endpoints (the CSRF check, the 500 catch-all), because personal data can be in any of them.
"""

from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from tests.session_data import SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here


def assert_no_store(response: object) -> None:
    assert response.headers["cache-control"] == "no-store"  # type: ignore[attr-defined]


def test_a_signed_in_persons_answer_is_never_stored(signin: SignInSetup) -> None:
    browser = signin.new_client()
    signin.sign_in(browser, email(signin, "a_ana"))
    # "Who am I": names the person and their company.
    response = browser.get("/api/sessions/current")
    assert response.status_code == 200
    assert_no_store(response)


def test_every_kind_of_answer_is_never_stored(app: FastAPI, client: TestClient) -> None:
    @app.get("/api/test/crash")
    def crash() -> None:
        raise RuntimeError("boom")

    assert_no_store(client.get("/api/health"))  # 200
    assert_no_store(client.get("/api/sessions/current"))  # 401: not signed in
    assert_no_store(client.get("/api/no-such-path"))  # 404
    assert_no_store(client.get("/api/test/crash"))  # 500 from the catch-all
    # 403 from the CSRF check, before any endpoint runs: a change from another site.
    forged = client.delete("/api/sessions", headers={"Origin": "https://evil.example"})
    assert forged.status_code == 403
    assert_no_store(forged)


def test_an_endpoint_can_set_its_own_caching_rule(app: FastAPI, client: TestClient) -> None:
    @app.get("/api/test/public")
    def public(response: Response) -> dict[str, str]:
        response.headers["Cache-Control"] = "public, max-age=60"
        return {"status": "ok"}

    assert client.get("/api/test/public").headers["cache-control"] == "public, max-age=60"
