"""Refusing forged requests: the Origin check and the CSRF token (authentication.md).

Course topic: CSRF (cross-site request forgery). The attack: a signed-in manager has
another site open; that site makes the manager's browser send a request to our API, and
the browser attaches the session cookie automatically, so the request would act as the
manager. Three defenses, so one mistake is not enough:

1. SameSite=Strict on the session cookie (app/modules/sessions/router.py): the browser
   does not attach the cookie to requests started by other sites. Not enough on its own:
   "site" means the registered domain, so a page on any subdomain (or a sibling app on the
   same domain) counts as the same site; and it depends on the browser getting it right.
2. The Origin check (here): every request that changes something must say it comes from
   the application's own address. Browsers set the Origin header themselves, and a page
   cannot fake it. This also covers sign-in, which has no session yet (so another site
   cannot sign a victim into the attacker's account).
3. The CSRF token (here): every request that changes something, from a browser with a
   session, must send X-CSRF-Token. The token is HMAC-SHA256(csrf_key, the session token's
   hash): it changes with every session, needs no database column, and cannot be computed
   without the server's key. Another site cannot read our pages or answers, so it never
   learns the token, and cannot put it in a forged request.

GET requests never change anything, so they need neither.
"""

import base64
import hashlib
import hmac

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.sessions import COOKIE_NAME, hash_cookie

# The methods that may change something; every other method only reads.
CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Signing in: checked for Origin only, never for a token. It starts a session rather than
# acting within one, and a browser may still carry the cookie of a session that already
# ended (idle for an hour); demanding that dead session's token would lock the person out.
# A forged sign-in (into the attacker's account) is refused by the Origin check.
SIGN_IN = ("POST", "/api/sessions")

# One answer for every refusal: it does not tell an attacker which check failed.
REFUSED = "This request did not come from the application's own pages."


def csrf_token(key: bytes, token_hash: bytes) -> str:
    """The CSRF token for a session: HMAC-SHA256(key, the session token's hash), as text."""
    digest = hmac.new(key, token_hash, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _origin(value: str) -> str:
    """An origin in one form for comparing: lowercase, no trailing slash."""
    return value.strip().rstrip("/").lower()


class CsrfMiddleware:
    """Runs before every request reaches an endpoint; refuses forged changes with 403."""

    def __init__(self, app: ASGIApp, *, key: bytes, origin: str | None) -> None:
        self.app = app
        self.key = key
        # The application's own address, or None to use the address of each request.
        self.origin = _origin(origin) if origin else None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Only HTTP requests that change something are checked; everything else passes.
        if scope["type"] != "http" or scope["method"] not in CHANGING_METHODS:
            await self.app(scope, receive, send)
            return

        # Request(scope) reads the headers and cookies; the body is left for the endpoint.
        if not self.allowed(Request(scope)):
            response = JSONResponse(
                status_code=403,
                content={
                    "type": "about:blank",
                    "title": "Forbidden",
                    "status": 403,
                    "detail": REFUSED,
                },
                media_type="application/problem+json",
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)

    def allowed(self, request: Request) -> bool:
        """Whether a changing request passes the Origin check and, with a session, the token."""
        # 1. Origin: present and exactly the application's own address. A missing Origin,
        #    "null" (sandboxed pages, some redirects), or any other site is refused.
        own = self.origin or _origin(f"{request.url.scheme}://{request.url.netloc}")
        if _origin(request.headers.get("origin", "")) != own:
            return False

        # 2. Token: only a browser that carries a session cookie can act as someone, so
        #    only then is the token needed. Sign-in starts a session instead (see SIGN_IN).
        if (request.method, request.url.path.rstrip("/")) == SIGN_IN:
            return True
        token_hash = hash_cookie(request.cookies.get(COOKIE_NAME))
        if token_hash is None:
            return True
        sent = request.headers.get("x-csrf-token", "")
        # compare_digest takes the same time however many characters match, so the
        # answer time does not reveal the token bit by bit.
        return hmac.compare_digest(sent.encode(), csrf_token(self.key, token_hash).encode())
