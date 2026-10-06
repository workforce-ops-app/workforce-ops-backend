"""AU6 (threat S4): forged requests are refused (app/auth/csrf.py, authentication.md).

Each test plays another website that makes a signed-in person's browser send a request
to our API. The browser attaches the session cookie by itself; what the other site cannot
do is set a matching Origin header or know the CSRF token.
"""

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from app.auth.csrf import REFUSED, CsrfMiddleware, csrf_token
from app.auth.sessions import COOKIE_NAME, hash_cookie
from tests.session_data import BASE_URL, PASSWORD, SignInSetup, email, signin

__all__ = ["signin"]  # the fixture, imported so pytest finds it here


def signed_in_browser(setup: SignInSetup) -> TestClient:
    """A browser where Ana of company A is signed in; it holds her cookie, not her token."""
    browser = setup.new_client()
    setup.sign_in(browser, email(setup, "a_ana"))
    del browser.headers["X-CSRF-Token"]
    return browser


def still_signed_in(setup: SignInSetup, browser: TestClient) -> bool:
    return browser.get("/api/sessions/current").status_code == 200


@pytest.mark.parametrize(
    ("case", "origin", "token"),
    [
        ("no token", BASE_URL, None),
        ("a wrong token", BASE_URL, "A" * 43),
        ("an empty token", BASE_URL, ""),
        ("another site's origin", "https://evil.example", "right"),
        ("a look-alike origin", "https://testserver.evil.example", "right"),
        ("plain http instead of https", "http://testserver", "right"),
        ("origin null", "null", "right"),
        ("no origin", None, "right"),
    ],
)
def test_forged_changes_are_refused(
    signin: SignInSetup, case: str, origin: str | None, token: str | None
) -> None:
    browser = signed_in_browser(signin)
    right = signin.client.app.state.csrf_key  # type: ignore[attr-defined]
    headers = {}
    if token is not None:
        cookie_hash = hash_cookie(browser.cookies.get(COOKIE_NAME))
        assert cookie_hash is not None
        headers["X-CSRF-Token"] = csrf_token(right, cookie_hash) if token == "right" else token
    if origin is None:
        del browser.headers["Origin"]
    else:
        headers["Origin"] = origin

    # "Sign out everywhere": a change the attacker would like to force.
    response = browser.delete("/api/sessions", headers=headers)

    assert response.status_code == 403, case
    assert response.json()["detail"] == REFUSED  # the same answer for every reason
    # Refused before the endpoint ran: Ana is still signed in.
    browser.headers["Origin"] = BASE_URL
    assert still_signed_in(signin, browser), case


def test_the_right_token_from_our_own_origin_is_accepted(signin: SignInSetup) -> None:
    browser = signin.new_client()
    signin.sign_in(browser, email(signin, "a_ana"))  # keeps the token, as our pages do
    assert browser.delete("/api/sessions/current").status_code == 204


def test_another_sessions_token_does_not_work(signin: SignInSetup) -> None:
    # The token belongs to one session: an attacker's own token (from their own sign-in)
    # is useless in the victim's browser.
    attacker = signin.new_client()
    signin.sign_in(attacker, email(signin, "a_ana"))
    victim = signed_in_browser(signin)
    response = victim.delete(
        "/api/sessions", headers={"X-CSRF-Token": attacker.headers["X-CSRF-Token"]}
    )
    assert response.status_code == 403


def test_the_token_comes_with_the_session_and_cannot_be_made_without_the_key(
    signin: SignInSetup,
) -> None:
    browser = signin.new_client()
    signed = browser.post(
        "/api/sessions", json={"email": email(signin, "a_ana"), "password": PASSWORD}
    ).json()
    current = browser.get("/api/sessions/current").json()
    assert signed["csrf_token"] == current["csrf_token"]

    # Computed from the session alone it would be predictable; the server's key makes it
    # impossible to compute for anyone without the key.
    cookie_hash = hash_cookie(browser.cookies.get(COOKIE_NAME))
    assert cookie_hash is not None
    assert (
        csrf_token(b"a guessed key, long enough to look real", cookie_hash) != signed["csrf_token"]
    )


def test_a_forged_sign_in_from_another_site_is_refused(signin: SignInSetup) -> None:
    # Login CSRF: another site signs the victim's browser into the attacker's account, so
    # whatever the victim then enters lands in the attacker's account. No session exists
    # yet, so the Origin check is what stops it.
    response = signin.new_client().post(
        "/api/sessions",
        json={"email": email(signin, "a_ana"), "password": PASSWORD},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "set-cookie" not in response.headers


def test_signing_in_again_works_with_a_leftover_cookie_and_no_token(signin: SignInSetup) -> None:
    # A browser idle past the hour still has its cookie but no longer the token (the page
    # was closed). Sign-in must still work, or the person would be locked out.
    browser = signed_in_browser(signin)
    assert signin.sign_in(browser, email(signin, "a_ana")) == 201


def test_reading_needs_neither_token_nor_origin(signin: SignInSetup) -> None:
    browser = signed_in_browser(signin)
    del browser.headers["Origin"]
    assert browser.get("/api/sessions/current").status_code == 200


def test_the_configured_application_address_is_the_only_accepted_origin() -> None:
    # Behind nginx the API may see another host name than the browser; APP_ORIGIN is then
    # the address that counts, and the request's own host no longer does. Checked on the
    # middleware directly, with a sign-in request (no session, so only Origin counts).
    check = CsrfMiddleware(app=None, key=b"k" * 32, origin="https://workforce.example/")  # type: ignore[arg-type]

    def sign_in_from(origin: str) -> bool:
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/sessions",
            "scheme": "http",
            "server": ("api", 8000),
            "query_string": b"",
            "headers": [(b"host", b"api:8000"), (b"origin", origin.encode())],
        }
        return check.allowed(Request(scope))

    assert sign_in_from("https://workforce.example")
    assert sign_in_from("https://WORKFORCE.example")  # compared ignoring case
    assert not sign_in_from("http://api:8000")  # the API's own host no longer counts
    assert not sign_in_from("https://evil.example")
