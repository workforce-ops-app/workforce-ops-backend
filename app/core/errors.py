"""One error format for the whole API: RFC 9457 "problem details" (decision 0026).

Every error response has the media type application/problem+json and the fields "type"
("about:blank"), "title" (the standard phrase for the status, e.g. "Not Found"), "status",
and, where useful, "detail".

- HTTP errors (Starlette's HTTPException, which also covers FastAPI's): unknown paths (404),
  wrong methods (405), and errors raised on purpose, e.g. HTTPException(403, "Not allowed").
- Invalid requests (RequestValidationError): 422 with an "errors" list of location and
  message; the submitted value is never copied into the response (reflected XSS).
- Anything unexpected: 500 with a generic message and an "error_id". The log line with the
  same error_id records the error type and where it happened, never the exception message,
  which can hold passwords, SQL, or submitted values (threat model I4, decision 0031). Only
  in development does the log also get the full message and stack trace.
"""

import logging
import traceback
import uuid
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)


# HTTPException Handler #
async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, StarletteHTTPException):
        raise exc
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": "about:blank",
            "title": HTTPStatus(exc.status_code).phrase,
            "status": exc.status_code,
            "detail": str(exc.detail),
        },
        # Keep headers such as Allow (405), WWW-Authenticate (401), and Retry-After (429).
        headers=exc.headers,
        media_type="application/problem+json",
    )


# RequestValidationError Handler #
async def request_validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):
        raise exc
    return JSONResponse(
        status_code=422,
        content={
            "type": "about:blank",
            "title": "Unprocessable Content",
            "status": 422,
            "errors": [
                {
                    "location": ".".join(str(part) for part in error["loc"]),
                    "message": error["msg"],
                }
                for error in exc.errors()
            ],
        },
        media_type="application/problem+json",
    )


# Catch-all for unexpected errors #
class UnexpectedErrorMiddleware:
    """Turns any unexpected exception into a 500 problem response and a safe log line.

    This is middleware rather than an exception handler on purpose: Starlette re-raises an
    exception after its 500 handler runs, and the server (uvicorn) then logs the full
    message and stack trace itself. Catching the exception here, and not raising it again,
    keeps the message out of every log outside development.
    """

    def __init__(self, app: ASGIApp, *, log_full_errors: bool) -> None:
        self.app = app
        self.log_full_errors = log_full_errors

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_and_track(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, send_and_track)
        except Exception as exc:
            error_id = str(uuid.uuid4())
            self.log(exc, error_id)
            if response_started:
                return  # too late for a new response; the connection just closes
            response = JSONResponse(
                status_code=500,
                content={
                    "type": "about:blank",
                    "title": "Internal Server Error",
                    "status": 500,
                    "detail": "An unexpected error occurred.",
                    "error_id": error_id,
                },
                media_type="application/problem+json",
            )
            await response(scope, receive, send)

    def log(self, exc: Exception, error_id: str) -> None:
        fields = {
            "action": "request.failed",
            "error": type(exc).__name__,
            "error_id": error_id,
            # Where it happened (file, line, function) but not the source line or the
            # message, so a value written into either cannot reach the log.
            "stack": [
                f"{frame.filename}:{frame.lineno} in {frame.name}"
                for frame in traceback.extract_tb(exc.__traceback__)
            ],
        }
        if self.log_full_errors:
            logger.error("Unexpected request error", exc_info=exc, extra={"fields": fields})
        else:
            logger.error("Unexpected request error", extra={"fields": fields})


def register_error_handlers(app: FastAPI, *, log_full_errors: bool) -> None:
    """Attach the error handlers to the app. Called once by create_app.

    log_full_errors puts exception messages and stack traces in the log; it is only for
    development.
    """
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, request_validation_error_handler)
    app.add_middleware(UnexpectedErrorMiddleware, log_full_errors=log_full_errors)
