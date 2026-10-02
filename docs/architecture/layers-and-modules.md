# Layers and modules

**In short:** the backend is one Python package, `app`. Shared building blocks (settings, logging, errors, and later sign-in, permissions, company separation, and the audit log) live in their own folders; every feature lives in its own folder under `app/modules/` and is found automatically. Adding a feature means adding a folder, never editing the shared code.

Decisions: [0004 feature modules](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0004-backend-feature-modules.md) · [0012 extension points](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0012-extensibility-patterns.md)

> **Status:** partly built. `app/main.py`, `app/core/` (settings, logging, errors), and the health module exist; the other shared layers arrive in Phase 2.

## The package

```
app/
├── main.py          create_app(): builds the app, registers error handlers, discovers modules
├── core/            config.py (settings), logging.py (JSON logs), errors.py (problem details)
├── db/              engine, session, base model (Phase 1, database slice)
├── auth/            sign-in, sessions, CSRF, password re-entry (Phase 2)
├── authz/           permissions, scopes, reporting chain, authorize() (Phase 2)
├── tenancy/         the automatic company filter (Phase 2)
├── audit/           the signed audit log (Phase 2)
└── modules/<feature>/
    ├── router.py       HTTP only: paths, status codes, request and response models
    ├── schemas.py      request and response shapes
    ├── service.py      business rules; calls authorize()
    ├── repository.py   the only code that talks to the database
    ├── models.py       tables
    └── permissions.py  the permissions this module declares
```

## How a request flows

```mermaid
flowchart LR
    R["Request"] --> RT["router.py<br/>(HTTP only)"]
    RT --> S["service.py<br/>(rules, authorize())"]
    S --> RP["repository.py<br/>(queries)"]
    RP --> DB[("MySQL")]
    RT -. "any error" .-> E["core/errors.py<br/>problem details"]
```

- The **router** turns HTTP into function calls and back; it holds no business rules.
- The **service** decides what is allowed and what happens.
- The **repository** is the only place with database queries, so security review knows where to look for SQL.
- **Errors** anywhere become one response format ([0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md)): RFC 9457 problem details, never a stack trace.

## How modules are found

`create_app()` looks at every package in `app/modules/`. If it has a `router.py` with a variable named `router` (an `APIRouter`), that router is included. No list to edit, so two pull requests adding two modules never conflict on a shared file.

A package without a `router.py` is simply skipped. But if a `router.py` exists and one of its own imports is missing (a typo, or a package that is not installed), the app refuses to start. Skipping it instead would start the server without that feature's endpoints while the health check still said everything was fine.

## Adding an endpoint

In the feature's `router.py`, one function per method and path. Type hints are the validation rules: FastAPI checks every request against them before the function runs, and anything that does not fit becomes a 422 automatically.

```python
router = APIRouter(prefix="/api/notes", tags=["notes"])


class NoteIn(BaseModel):  # request body shape (schemas.py)
    title: str = Field(min_length=1, max_length=100)


@router.get("/{note_id}")  # path parameter
def get_note(note_id: int) -> NoteOut: ...


@router.get("")  # query parameter: ?pinned=true
def list_notes(pinned: bool | None = None) -> list[NoteOut]: ...


@router.post("", status_code=201)  # JSON body, 201 Created
def create_note(note: NoteIn) -> NoteOut: ...
```

| Method | Use for | Usual status |
|---|---|---|
| `GET` | reading; never changes anything | 200 |
| `POST` | creating, or an action such as `/approve` | 201 or 200 |
| `PATCH` | changing some fields | 200 |

## Errors: raising and adding types

- Raise `HTTPException(status_code, detail)` for a known problem (`404`, `403`, `409`, ...). The handler in `core/errors.py` turns every one of them into problem details ([errors and status codes](../user/errors.md)).
- FastAPI picks the **most specific** registered handler: validation errors go to the 422 handler and HTTP errors to the HTTP handler. Both keep the exception's headers (such as `Allow` on a 405).
- Anything else reaches `UnexpectedErrorMiddleware`, the 500 catch-all. It is middleware, not an exception handler, because Starlette re-raises an exception after its 500 handler runs and uvicorn then logs the full message. The middleware logs a safe line (an `error_id`, the error type, and file and line only) and does not raise again. Full messages and stack traces are logged only when `APP_ENV=development` ([errors](../user/errors.md#what-the-server-log-keeps)).
- **Adding an error type** (for example `NotFoundError` raised by a service, so services need not know about HTTP): define the exception class in `core/errors.py`, write a handler that returns the matching problem response, and register it in `register_error_handlers`.

## Running it

```
uvicorn app.main:create_app --factory --reload
```

Then open http://localhost:8000/api/health. In development the interactive API docs are at http://localhost:8000/api/docs; they are switched off in production, so a production server does not advertise its endpoints.
