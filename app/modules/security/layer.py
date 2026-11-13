"""The detection layer: copy what a request sent, never change it (docs/features/detection.md).

Course topic: code injection. Detection RECORDS what looks like an attack; it never
blocks one (rule DE1, decision 0030). The real protection is how the application is
built: bound parameters for SQL, textContent for display, permission checks. A false
alarm must never stop real work, so this layer cannot refuse, change, or slow down a
request or its answer.

How a request goes through it (DetectionMiddleware below):
1. Find the route the request is for, the same way the router will. A credential route
   (marked with @detection_skip) is passed straight through: nothing of it is copied, not
   even the email field (rule DE3, collection rule 2).
2. Pass the request on UNCHANGED. While the endpoint reads the body, keep a copy of the
   bytes it read, up to MAX_BODY_BYTES. The body is never read ahead of the endpoint, so
   the endpoint sees exactly what the client sent, when it asks for it.
3. After the answer has been sent, make the copy by the collection rules (collect()): only
   path values, query string values, and strings in a JSON body, each with its field name;
   never a header; never a field with a secret-like name, nor anything inside one; with
   the DE4 caps. The copy is made here, in the request, so a secret never reaches the
   queue, the worker, the database, or the logs.
4. Hand the copy to the worker (app/modules/security/worker.py) without waiting: a full
   queue drops it and counts the drop (DE11). The worker runs the detector and records
   the events.

Any error in steps 3 and 4 is logged (without the request's values) and swallowed: a bug
in detection must never turn into an error for the person who sent the request (DE1).
"""

import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl

from fastapi.routing import RouteContext, iter_route_contexts
from starlette.routing import BaseRoute, Match
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.db.base import utcnow
from app.detection.detector import MAX_TOTAL_CHARS, MAX_VALUE_CHARS, MAX_VALUES

logger = logging.getLogger(__name__)

# The body bytes kept while the endpoint reads them. Bodies have no size limit of their
# own yet (#94), so this bounds the memory one request can make the layer use. A larger
# body is not inspected at all: half a JSON document cannot be read.
MAX_BODY_BYTES = 1_048_576  # 1 MiB
# How deep into nested JSON objects and lists the copy looks. Deeper values are left out,
# so a crafted body cannot make the walk use unbounded time or stack.
MAX_DEPTH = 32
# The `field` column's length (app/modules/security/models.py).
MAX_FIELD_CHARS = 100
# The `client_address` column's length: an IPv6 address in text.
MAX_ADDRESS_CHARS = 45

# Collection rule 3: a field whose name, lowercased and without "_" and "-", contains one
# of these is left out, with everything inside it.
SECRET_WORDS = (
    "password",
    "passwd",
    "secret",
    "token",
    "csrf",
    "apikey",
    "authorization",
    "cookie",
    "session",
)

# The name of the marker detection_skip() puts on an endpoint function.
_SKIP_MARK = "__detection_skip__"


def detection_skip[Endpoint: Callable[..., Any]](endpoint: Endpoint) -> Endpoint:
    """Mark an endpoint as a credential route: detection copies nothing of its requests.

    Collection rule 2: sign-in, password change, password reset, invitation acceptance,
    and any later route that takes a credential. Put it under the route decorator:

        @router.post("")
        @detection_skip
        def create_session(...): ...

    The mark sits on the function itself, so the list of skipped routes cannot be
    forgotten in a separate file. The SecretStr walk in tests/unit/test_detection_layer.py
    fails if a route takes a SecretStr field that neither this mark nor rule 3 keeps out.
    """
    setattr(endpoint, _SKIP_MARK, True)
    return endpoint


def is_skipped(route: BaseRoute | RouteContext | None) -> bool:
    """Whether a route's endpoint is marked with detection_skip. For a route inside an
    included router, the mark is on the original route's endpoint."""
    original = getattr(route, "original_route", route)
    endpoint = getattr(original, "endpoint", None)
    return bool(getattr(endpoint, _SKIP_MARK, False))


def is_secret_name(name: str) -> bool:
    """Collection rule 3: whether a field's name looks like it holds a secret."""
    simple = name.lower().replace("_", "").replace("-", "")
    return any(word in simple for word in SECRET_WORDS)


@dataclass(frozen=True)
class Identity:
    """The valid session a request carried, as signed_in() found it (rule DE9)."""

    session_id: uuid.UUID
    company_id: uuid.UUID
    user_id: uuid.UUID


# Where signed_in() leaves the request's Identity, in the request's state (scope["state"]).
IDENTITY_KEY = "detection_identity"


def note_identity(state: dict[str, Any], identity: Identity) -> None:
    """Remember that this request carried a valid session. Called by signed_in()
    (app/auth/dependencies.py) once the session is checked, so a company is only ever
    taken from a session the application itself has verified (DE9)."""
    state[IDENTITY_KEY] = identity


@dataclass
class RequestCopy:
    """What the worker gets from one request: the collected values and facts about it."""

    values: list[tuple[str, str]]  # (field, text), already filtered and capped
    method: str
    route: str | None  # the route template, for example /api/shifts/{shift_id}
    client_address: str | None
    request_id: str
    occurred_at: datetime
    identity: Identity | None = None  # None: no valid session (a platform event)


@dataclass
class _Collector:
    """Gathers (field, text) pairs with the DE4 caps applied while copying, so even the
    copy itself stays small: at most 200 values, each cut to 2,000 characters, and at most
    100,000 characters in all."""

    values: list[tuple[str, str]] = field(default_factory=list)
    total: int = 0

    @property
    def full(self) -> bool:
        return len(self.values) >= MAX_VALUES or self.total >= MAX_TOTAL_CHARS

    def add(self, name: str, text: str) -> None:
        if self.full:
            return
        text = text[:MAX_VALUE_CHARS][: MAX_TOTAL_CHARS - self.total]
        self.values.append((name[:MAX_FIELD_CHARS], text))
        self.total += len(text)

    def walk(self, name: str, value: Any, depth: int = 0) -> None:
        """Every string inside a JSON value, depth first, skipping secret-named fields
        (with everything inside them) at any depth. Numbers, booleans, and null are not
        text, so they are not collected."""
        if self.full or depth > MAX_DEPTH:
            return
        if isinstance(value, str):
            self.add(name, value)
        elif isinstance(value, dict):
            for key, inner in value.items():
                if is_secret_name(str(key)):
                    continue  # rule 3: the field and everything inside it
                self.walk(f"{name}.{key}", inner, depth + 1)
        elif isinstance(value, list):
            for index, inner in enumerate(value):
                self.walk(f"{name}[{index}]", inner, depth + 1)


def collect(
    path_params: dict[str, Any], query_string: bytes, body: bytes | None
) -> list[tuple[str, str]]:
    """The collection rules (DE3): the values of a request detection may look at.

    Only three places are read, in this order: path values, query string values, and the
    strings in a JSON body (`body` is None when there is no JSON body to read). Headers
    are never passed in, so they can never be collected. A secret-named field is left
    out wherever it is.
    """
    collector = _Collector()
    # 1. Path values, for example path.shift_id.
    for name, value in path_params.items():
        if not is_secret_name(name):
            collector.add(f"path.{name}", str(value))
    # 2. Query string values, decoded as the endpoint sees them, for example query.search.
    #    Decoded once here; the detector decodes again (normalization step 1), which is
    #    what catches a double-encoded quote.
    query = query_string.decode("latin-1")
    for name, value in parse_qsl(query, keep_blank_values=False):
        if not is_secret_name(name):
            collector.add(f"query.{name}", value)
    # 3. Strings in a JSON body, for example body.note or body.items[0].note. A body that
    #    is not valid JSON has nothing to collect (the endpoint refuses it anyway).
    if body:
        try:
            document = json.loads(body)
        except (ValueError, RecursionError):
            document = None
        collector.walk("body", document)
    return collector.values


def _is_json(scope: Scope) -> bool:
    """Whether the request says its body is JSON. Only this one header is READ, to decide
    whether to keep the body; no header is ever copied."""
    for name, value in scope.get("headers", []):
        if name == b"content-type":
            return value.split(b";")[0].strip().lower() == b"application/json"
    return False


def _find_route(
    routes: list[RouteContext], scope: Scope
) -> tuple[RouteContext | None, dict[str, Any]]:
    """The route the router will choose, and its path values, matched the same way the
    router does: the first full match, otherwise the first partial one (the path matches
    but not the method, so the answer is 405). Found BEFORE the request goes on, so a
    request the CSRF check refuses still knows whether it was for a credential route."""
    partial: tuple[RouteContext | None, dict[str, Any]] = (None, {})
    for route in routes:
        match, child = route.matches(scope)
        if match == Match.FULL:
            return route, child.get("path_params", {})
        if match == Match.PARTIAL and partial[0] is None:
            partial = (route, child.get("path_params", {}))
    return partial


class DetectionMiddleware:
    """The detection layer around the whole API (see the top of this file).

    `routes` is the application's route list (app.router.routes). Included routers sit in
    it as one entry each, so it is flattened into every single route (with its full path)
    on the first request, when every router has been included. `submit` hands a copy to
    the worker without waiting.
    """

    def __init__(
        self, app: ASGIApp, *, routes: list[BaseRoute], submit: Callable[[RequestCopy], None]
    ) -> None:
        self.app = app
        self._routes = routes
        self._flat: list[RouteContext] | None = None
        self.submit = submit

    @property
    def routes(self) -> list[RouteContext]:
        if self._flat is None:
            self._flat = list(iter_route_contexts(self._routes))
        return self._flat

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Which route, and is it a credential route? Then pass it through untouched.
        try:
            route, path_params = _find_route(self.routes, scope)
        except Exception:
            # Without the message or stack: neither may carry what was sent.
            logger.error("Detection could not match the route")
            route, path_params = None, {}
        if is_skipped(route):
            await self.app(scope, receive, send)
            return

        # A request ID for the event rows, kept in the request's state so the log line
        # for the same request (#92) can use the same one.
        state = scope.setdefault("state", {})
        request_id = state.setdefault("request_id", uuid.uuid4().hex)
        occurred_at = utcnow()

        # 2. Keep a copy of the body bytes as the endpoint reads them, only for JSON.
        keep_body = _is_json(scope)
        chunks: list[bytes] = []
        kept = 0
        body_complete = False
        too_big = False

        async def receive_and_keep() -> Message:
            nonlocal kept, body_complete, too_big
            message = await receive()
            if keep_body and message["type"] == "http.request" and not too_big:
                chunk = message.get("body", b"")
                kept += len(chunk)
                if kept > MAX_BODY_BYTES:
                    too_big = True
                    chunks.clear()  # half a document cannot be read: keep nothing
                else:
                    chunks.append(chunk)
                    body_complete = not message.get("more_body", False)
            # The message goes on exactly as it came.
            return message

        try:
            await self.app(scope, receive_and_keep, send)
        finally:
            # 3. and 4. The answer has been sent (or the app failed): copy and hand over.
            try:
                body = b"".join(chunks) if keep_body and body_complete and not too_big else None
                client = scope.get("client")
                address = client[0][:MAX_ADDRESS_CHARS] if client else None
                copy = RequestCopy(
                    values=collect(path_params, scope.get("query_string", b""), body),
                    method=scope["method"],
                    route=getattr(route, "path", None),
                    client_address=address,
                    request_id=request_id,
                    occurred_at=occurred_at,
                    identity=state.get(IDENTITY_KEY),
                )
                if copy.values:
                    self.submit(copy)
            except Exception:
                # Never the values or the message: either could hold what was sent.
                logger.error("Detection could not copy a request")
