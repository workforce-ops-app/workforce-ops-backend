"""One error format for the whole API: RFC 9457 "problem details" (decision 0026).

Every error response has the media type application/problem+json and the fields "type"
("about:blank"), "title" (the standard phrase for the status, e.g. "Not Found"), "status",
and, where useful, "detail".

- HTTP errors (Starlette's HTTPException, which also covers FastAPI's): unknown paths (404),
  wrong methods (405), and errors raised on purpose, e.g. HTTPException(403, "Not allowed").
- Invalid requests (RequestValidationError): 422 with an "errors" list of location and
  message; the submitted value is never copied into the response (reflected XSS).
- Anything unexpected: 500 with a generic message. The real error and its stack trace go to
  the log, never into the response (threat model I4).
"""

import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

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


# InternalServerError Handler #
async def internal_server_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unexpected error while handling request", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "type": "about:blank",
            "title": "Internal Server Error",
            "status": 500,
            "detail": "An unexpected error occurred.",
        },
        media_type="application/problem+json",
    )


def register_error_handlers(app: FastAPI) -> None:
    """Attach the error handlers to the app. Called once by create_app."""
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, request_validation_error_handler)
    app.add_exception_handler(Exception, internal_server_error_handler)
