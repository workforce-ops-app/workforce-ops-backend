"""Keep API answers out of the browser's cache (threat model I6; OWASP ASVS V8.2.1).

Answers carry personal data: who is signed in, their shifts, their company's people. A
browser may write an answer to its cache on disk, where a later user of the same computer
could find it even after signing out. `Cache-Control: no-store` tells the browser and any
proxy in between never to keep a copy.

(Not to be confused with `no-cache`, which the frontend's nginx sends for pages and
scripts: "keep a copy, but ask before each use." That suits public files, not personal
data.)
"""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

NO_STORE = "no-store"


class NoStoreMiddleware:
    """Adds `Cache-Control: no-store` to every HTTP answer that has no Cache-Control yet.

    Registered outside the other middleware (app/main.py), so it also covers answers they
    make themselves, such as the CSRF check's 403. An endpoint that sets its own
    Cache-Control keeps it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_header(message: Message) -> None:
            # The status line and headers go out in the first message; add ours there.
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if "cache-control" not in headers:
                    headers["Cache-Control"] = NO_STORE
            await send(message)

        await self.app(scope, receive, send_with_header)
