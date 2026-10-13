"""Development Swagger UI helpers.

Swagger runs in the browser like the application pages do, so authenticated write
requests need the CSRF token returned by the session API. The token stays in this page's
JavaScript closure: it is never persisted, logged, or sent to another origin.
"""

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, Response

CSRF_SCRIPT_PATH = "/api/docs/swagger-csrf.js"

CSRF_SCRIPT = r"""(() => {
  let csrfToken = null;
  const ownOrigin = window.location.origin;
  const changingMethods = new Set(["POST", "PUT", "PATCH", "DELETE"]);
  const sessionPaths = new Set(["/api/sessions", "/api/sessions/current"]);
  const pendingSignOuts = new Set();

  function sameOriginUrl(value) {
    const url = new URL(value, ownOrigin);
    return url.origin === ownOrigin ? url : null;
  }

  function responseBody(response) {
    if (response.obj && typeof response.obj === "object") return response.obj;
    const text = response.data || response.text || response.body;
    if (typeof text !== "string") return null;
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }

  window.swaggerCsrf = {
    request(request) {
      const url = sameOriginUrl(request.url);
      const method = (request.method || "GET").toUpperCase();
      if (url && csrfToken && changingMethods.has(method)) {
        request.headers = request.headers || {};
        request.headers["X-CSRF-Token"] = csrfToken;
      }
      if (url && method === "DELETE" && sessionPaths.has(url.pathname)) {
        pendingSignOuts.add(url.href);
      }
      return request;
    },

    response(response) {
      const url = sameOriginUrl(response.url);
      const status = Number(response.status);
      if (!url) return response;

      if (status === 401) csrfToken = null;
      if (pendingSignOuts.delete(url.href) && status >= 200 && status < 300) {
        csrfToken = null;
      } else if (status >= 200 && status < 300 && sessionPaths.has(url.pathname)) {
        const body = responseBody(response);
        if (body && typeof body.csrf_token === "string") csrfToken = body.csrf_token;
      }
      return response;
    },
  };
})();
"""


def _swagger_html() -> HTMLResponse:
    """Build FastAPI's normal Swagger page with the two CSRF interceptors."""

    response = get_swagger_ui_html(
        openapi_url="/api/openapi.json",
        title="Workforce Operations API - Swagger UI",
    )
    html = bytes(response.body).decode()
    html = html.replace(
        "<!-- `SwaggerUIBundle` is now available on the page -->",
        f'<script src="{CSRF_SCRIPT_PATH}"></script>\n'
        "    <!-- `SwaggerUIBundle` is now available on the page -->",
    )
    html = html.replace(
        "    presets: [",
        "    requestInterceptor: window.swaggerCsrf.request,\n"
        "    responseInterceptor: window.swaggerCsrf.response,\n"
        "    presets: [",
    )
    return HTMLResponse(html)


def add_development_swagger(app: FastAPI) -> None:
    """Expose Swagger with CSRF support; called only for a development app."""

    app.add_api_route("/api/docs", _swagger_html, include_in_schema=False)
    app.add_api_route(
        CSRF_SCRIPT_PATH,
        lambda: Response(CSRF_SCRIPT, media_type="application/javascript"),
        include_in_schema=False,
    )
