"""Who sent each request and from where, on every log line; one line per refusal (#92).

Course topic: logging and monitoring (OWASP ASVS V16.2.1, V16.3.2, V16.3.3). Without
this, a 403, another company's record answered with 404, or a forged request left no
trace, so nobody could see an attack in progress or investigate one afterwards.

How a request goes through it (RequestContextMiddleware below, the outermost layer):
1. Give the request an ID and note the address that sent it. The ID is kept in the
   request's state, where the detection layer (app/modules/security/layer.py) takes the
   same one for its security events, so an event and a log line can be matched.
2. Keep both in a context variable for as long as the request runs. Every log record
   written meanwhile carries them (the record factory below), and the JSON log format
   (app/core/logging.py) puts them on the line, with the person and
   company once signed_in() has checked the session. Endpoints that run in a thread see
   the same context: the web framework copies it into the thread.
3. When the answer is a refusal (403, or 404 on a real route), write exactly one line
   for it: what was refused (REFUSAL_KINDS), the permission when authorize() refused, the
   method, the route TEMPLATE (/api/shifts/{shift_id}, never the raw path, which may carry
   attacker text), and the answer's status. Never the body, a header, a cookie, or a
   token: none of them is ever read here.
4. Hand most refusals (RECORDED_KINDS) to the detection worker as security events too,
   so owners see them on the security page and the detection study can count them
   (docs/features/detection.md, "Refused requests"). The event, like the line, holds
   only what the server decided: no value the client sent.

What was refused is noted on the way out by whoever refused it: the CSRF check
(app/auth/csrf.py) and the error handler (app/core/errors.py), which reads it from the
exception (app/authz/check.py's Forbidden and NotFound, app/auth/reauth.py's errors). A
403 or 404 that noted nothing gets the default kind for its status.

Refusals are log lines and security events, not audit entries: a burst of them (a script
probing IDs) would fill the audit log's chain with noise
(docs/architecture/authorization.md).
"""

import logging
import uuid
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from fastapi.routing import RouteContext, iter_route_contexts
from starlette.routing import BaseRoute
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.db.base import utcnow
from app.modules.security.layer import (
    IDENTITY_KEY,
    Refusal,
    RequestCopy,
    client_address,
    find_route,
)

# The refusal log lines' own logger, so they can be found (and later read by detection)
# without matching message text.
refusals = logging.getLogger("app.refusals")

# What a refusal line's "event" can say.
AUTHZ_DENIED = "authz.denied"  # 403: no permission, or not over this record or person
TENANCY_NOT_FOUND = "tenancy.not_found"  # 404: authorize() found another company's target
NOT_FOUND = "request.not_found"  # 404 on a real route: missing, or another company's
CSRF_REFUSED = "csrf.refused"  # 403: a changing request without our Origin or token
REAUTH_REQUIRED = "auth.reauth_required"  # 403: enter the password again first
REAUTH_FAILED = "auth.reauth_failed"  # 403: the password entered again was wrong
REAUTH_LOCKED = "auth.reauth_locked"  # 403: too many wrong passwords entered again
REFUSAL_KINDS = (
    AUTHZ_DENIED,
    TENANCY_NOT_FOUND,
    NOT_FOUND,
    CSRF_REFUSED,
    REAUTH_REQUIRED,
    REAUTH_FAILED,
    REAUTH_LOCKED,
)

# The refusals also recorded as security events (the security page, the detection
# study): all but REAUTH_REQUIRED, the ordinary first step of every sensitive action.
# app/modules/security/models.py lists them as REFUSAL_EVENT_KINDS.
RECORDED_KINDS = frozenset(REFUSAL_KINDS) - {REAUTH_REQUIRED}

# The kind for a refusal that noted none, by status. A 404 counts only on a real route:
# another company's record and one that does not exist answer the same, on purpose
# (docs/architecture/tenancy.md), so both are logged. A path that matches no route at all
# is not logged: scanners send thousands, and they reach no code.
_DEFAULT_KIND = {403: AUTHZ_DENIED, 404: NOT_FOUND}


@dataclass
class RequestContext:
    """What one request's log lines say about it. One object per request, changed in
    place (never replaced), so a thread that copied the context sees the same object."""

    request_id: str
    client_address: str | None
    # The request's state (scope["state"]): signed_in() leaves the checked session's
    # person and company there (IDENTITY_KEY), so they are read from it when a line is
    # written, never from what the client sent.
    state: dict[str, Any] = field(default_factory=dict)
    # What was refused, noted by whoever refused it (note_refusal).
    refusal: str | None = None
    permission: str | None = None

    def fields(self) -> dict[str, Any]:
        """The fields every log line of this request carries."""
        found: dict[str, Any] = {"request_id": self.request_id}
        if self.client_address is not None:
            found["client_address"] = self.client_address
        identity = self.state.get(IDENTITY_KEY)
        if identity is not None:
            found["company_id"] = str(identity.company_id)
            found["user_id"] = str(identity.user_id)
        return found


# The running request's context; None outside a request (startup, the detection worker).
_current: ContextVar[RequestContext | None] = ContextVar("request_context", default=None)


def current_fields() -> dict[str, Any]:
    """The running request's fields for a log line, or none outside a request."""
    context = _current.get()
    return context.fields() if context is not None else {}


def note_refusal(kind: str, permission: str | None = None) -> None:
    """Say what is being refused, for the request's refusal line. The last note wins: a
    check that failed and was caught (and so refused nothing) is overwritten by the one
    whose answer is actually sent, which notes as the answer leaves."""
    context = _current.get()
    if context is not None:
        context.refusal = kind
        context.permission = permission


def _attach_context_to_records() -> None:
    """Make every log record carry the running request's fields from the moment it is
    written (record.request_context), wherever and however late it is formatted. Wraps
    whatever record factory is already set, once."""
    previous = logging.getLogRecordFactory()
    if getattr(previous, "_adds_request_context", False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        record.request_context = current_fields()
        return record

    factory._adds_request_context = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)


_attach_context_to_records()


class RequestContextMiddleware:
    """The request context around the whole API (see the top of this file).

    `routes` is the application's route list (app.router.routes), flattened on the first
    request (when every router has been included), to name the route of a refusal the
    CSRF check answered before any route was chosen. `submit` hands a refusal's copy to
    the detection worker without waiting (app/modules/security/worker.py), which records
    it as a security event with the same queue, rate cap, and company rules as every
    other event (DE6, DE9, DE11).
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        routes: list[BaseRoute],
        submit: Callable[[RequestCopy], None] | None = None,
    ) -> None:
        self.app = app
        self._routes = routes
        self.submit = submit
        self._flat: list[RouteContext] | None = None

    @property
    def routes(self) -> list[RouteContext]:
        if self._flat is None:
            self._flat = list(iter_route_contexts(self._routes))
        return self._flat

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. The ID (shared with detection through the state) and the sender's address.
        state = scope.setdefault("state", {})
        request_id = state.setdefault("request_id", uuid.uuid4().hex)
        context = RequestContext(request_id, client_address(scope), state)
        occurred_at = utcnow()
        # 2. For every line written while the request runs.
        token = _current.set(context)
        status: int | None = None

        async def send_and_watch(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_watch)
        finally:
            # 3. One line for a refusal. Any error here is logged and swallowed: logging
            #    must never turn an answer into an error.
            try:
                if status in _DEFAULT_KIND:
                    self._refused(scope, context, status, occurred_at)
            except Exception:
                refusals.error("A refusal could not be logged")
            _current.reset(token)

    def _refused(
        self, scope: Scope, context: RequestContext, status: int, occurred_at: datetime
    ) -> None:
        """The refusal's log line and, for the kinds in RECORDED_KINDS, its event."""
        route, _ = find_route(self.routes, scope)
        template = getattr(route, "path", None)
        if status == 404 and template is None:
            return  # no such route: nothing was refused (see _DEFAULT_KIND)
        kind = context.refusal or _DEFAULT_KIND[status]
        if self.submit is not None and kind in RECORDED_KINDS:
            # A copy with no values: the event holds only what the server decided.
            self.submit(
                RequestCopy(
                    values=[],
                    method=scope["method"],
                    route=template,
                    client_address=context.client_address,
                    request_id=context.request_id,
                    occurred_at=occurred_at,
                    identity=context.state.get(IDENTITY_KEY),
                    refusal=Refusal(kind, context.permission),
                )
            )
        line: dict[str, Any] = {
            "event": kind,
            "status": status,
            "method": scope["method"],
            "route": template,
        }
        if context.permission is not None:
            line["permission"] = context.permission
        refusals.warning("Request refused", extra={"fields": line})
