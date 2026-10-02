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
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Workforce Operations API",
        # The interactive API docs are for development only; production does not
        # advertise every endpoint.
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/api/openapi.json",
    )
    register_error_handlers(app, log_full_errors=settings.app_env == "development")
    for router in discover_routers():
        app.include_router(router)
    return app
