"""The app factory: builds the FastAPI application.

Run locally with:  uvicorn app.main:create_app --factory --reload

Modules are discovered, not listed: every package in app/modules/ that has a router.py
with a variable named `router` is included automatically, so adding a feature never
means editing this file (decisions 0004 and 0012).
"""

import importlib
import pkgutil

from fastapi import APIRouter, FastAPI

from app import modules
from app.auth.csrf import CsrfMiddleware
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging


def discover_routers() -> list[APIRouter]:
    """Find `router` in every app/modules/<feature>/router.py."""
    routers = []
    for module_info in pkgutil.iter_modules(modules.__path__):
        if not module_info.ispkg:
            continue
        module_name = f"app.modules.{module_info.name}.router"
        try:
            router_module = importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            if exc.name == module_name:
                continue  # a module without endpoints
            # router.py exists but one of its imports is missing: fail at startup instead
            # of starting without that feature's endpoints.
            raise
        router = getattr(router_module, "router", None)
        if isinstance(router, APIRouter):
            routers.append(router)
    return routers


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        settings = get_settings()
    configure_logging(settings.log_level)

    if settings.is_production:
        docs_url = None
        openapi_url = None
    else:
        docs_url = "/api/docs"
        openapi_url = "/api/openapi.json"

    app = FastAPI(
        title="Workforce Operations API",
        # The interactive API docs are for development only; production does not
        # advertise every endpoint.
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )
    log_full_errors = settings.is_development
    # Forged requests are refused before they reach any endpoint (app/auth/csrf.py). The
    # API does not start without the key: every change to data depends on it. Added before
    # the error handlers, so an unexpected error in the check still gets a safe 500.
    if settings.csrf_key is None:
        raise RuntimeError("CSRF_KEY is not set; the API cannot protect changes without it")
    # Two separate secrets (authentication.md): one leaked key must not weaken the other.
    audit_key = settings.audit_signing_key
    if (
        audit_key is not None
        and audit_key.get_secret_value() == settings.csrf_key.get_secret_value()
    ):
        raise RuntimeError("CSRF_KEY must differ from AUDIT_SIGNING_KEY")
    # The key is kept on the app, so the check and the endpoints that hand out tokens
    # (app/modules/sessions/router.py) always use the same one.
    app.state.csrf_key = settings.csrf_key.get_secret_value().encode("utf-8")
    app.add_middleware(CsrfMiddleware, key=app.state.csrf_key, origin=settings.app_origin)
    register_error_handlers(app, log_full_errors=log_full_errors)
    for router in discover_routers():
        app.include_router(router)
    return app
