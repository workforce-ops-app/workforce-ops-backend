# Contributor Documentation: Backend

**In short:** how to set up and work on the backend. The shared workflow (issues, branches, PRs, CI) is in the [contributor guide](https://github.com/workforce-ops-app/.github/tree/main/docs/contributing); this page covers what is specific to this repository.

## First-time setup

Needs Python 3.13 and pre-commit ([local setup](https://github.com/workforce-ops-app/.github/blob/main/docs/contributing/local-setup.md)). From this repository's folder:

```
py -3.13 -m venv .venv                 # macOS/Linux: python3.13 -m venv .venv
.venv\Scripts\activate                 # macOS/Linux: source .venv/bin/activate
python -m pip install -e ".[dev]"      # the app plus the development tools
copy .env.example .env                 # macOS/Linux: cp .env.example .env
pre-commit install
```

- **The virtual environment** (`.venv`) keeps this project's packages separate from other projects and from the system Python. Activate it in each new terminal before working here; the prompt then starts with `(.venv)`.
- **`-e` (editable)** means code changes take effect without reinstalling.
- **Dependencies** are pinned to exact versions in `pyproject.toml`; Dependabot proposes updates. After pulling a change to `pyproject.toml`, run the install line again.
- **Settings** come from environment variables; `.env` holds them for local use and is never committed. Every setting is listed in `.env.example`.


## Quick reference

| Task | Command |
|---|---|
| Run all CI checks locally | `python ../.github/scripts/ci_runner.py` |
| Run one check | `python ../.github/scripts/ci_runner.py --only lint` |
| Install git hooks | `pre-commit install` |
| Run the API locally | `uvicorn app.main:create_app --factory --reload`, then http://localhost:8000/api/health |
| Run the tests | `python -m pytest` |
| Run the tests with coverage (which lines of `app/` the tests run; missing line numbers listed per file) | `python -m pytest --cov --cov-report=term` |
| Format the code | `ruff format .` |
| Lint (including security rules) | `ruff check .` (add `--fix` for automatic fixes) |
| Type check | `mypy app` |
| Check dependencies for known vulnerabilities | `pip-audit --skip-editable` |
| Check the migrations (needs Docker running) | `python -m scripts.check_migrations` |
| Start the API and MySQL in Docker | `docker compose up -d --build` (see [running with Docker](#running-with-docker)) |
| Run the integration test (needs Docker running) | `python -m scripts.integration_test` |

## Database and migrations

How the database layer is built is in [layers and modules](../architecture/layers-and-modules.md#the-database-layer). The Alembic commands below use `DATABASE_URL` and `DATABASE_PASSWORD` from `.env` and need a running MySQL 8.4: start it with `docker compose up -d db` ([running with Docker](#running-with-docker)).

| Task | Command |
|---|---|
| Apply all migrations | `alembic upgrade head` |
| Undo the last migration | `alembic downgrade -1` |
| Show the current and latest migration | `alembic current` and `alembic heads` |
| Create a migration from changed models | `alembic revision --autogenerate -m "add notes table"` |
| Show the SQL without running it | `alembic upgrade head --sql` |

- **Read every generated migration** before committing it. Autogenerate compares the models with the database and can miss or misread changes (renamed columns look like a drop plus an add, which would lose data). Fill in `downgrade()` so it undoes `upgrade()` exactly.
- **One migration per pull request.** If another pull request's migration merges first, set your migration's `down_revision` to that one. The migration check fails when the history has two heads ([modularity](https://github.com/workforce-ops-app/.github/blob/main/docs/contributing/modularity.md)).
- **The migration check** (`python -m scripts.check_migrations`, also run by CI) confirms there is one head, then runs upgrade, downgrade, and upgrade again on a throwaway MySQL 8.4 container that it removes afterwards. To use an existing empty database instead, set `MIGRATION_CHECK_DATABASE_URL`.

**Queries go in `repository.py` only**, written with SQLAlchemy, never by building SQL strings:

```python
# app/modules/notes/repository.py
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.notes.models import Note


def get_note(session: Session, note_id: uuid.UUID) -> Note | None:
    return session.scalars(select(Note).where(Note.id == note_id)).one_or_none()


def add_note(session: Session, title: str) -> Note:
    note = Note(title=title)  # id, created_at, and updated_at fill themselves in
    session.add(note)
    session.flush()  # sends the INSERT now, inside the request's transaction
    return note
```

SQLAlchemy sends `note_id` and `title` as bound parameters (`WHERE notes.id = %(id_1)s`), like a PDO prepared statement in PHP, so a value can never change the query. Never build SQL text out of values (f-strings, `+`, `%`); if raw SQL is ever needed, use `text()` with named placeholders such as `:note_id`.

## Running with Docker

`docker-compose.yml` runs the API and MySQL 8.4 together ([0034](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0034-database-driver-ids-and-local-layout.md)). Needs Docker Desktop running, and `MYSQL_ROOT_PASSWORD` and `MYSQL_APP_PASSWORD` set in `.env` (Compose refuses to start without them, so there is never a blank database password).

| Task | Command |
|---|---|
| Start everything (builds the API image) | `docker compose up -d --build` |
| Start only MySQL (to run the API with uvicorn instead) | `docker compose up -d db` |
| See whether both are healthy | `docker compose ps` |
| Follow the API's log lines | `docker compose logs -f api` |
| Apply the migrations | `docker compose run --rm api alembic upgrade head` |
| Stop (data is kept) | `docker compose down` |
| Reset the database (**deletes all local data**) | `docker compose down --volumes` |

- **Addresses:** the API is at http://localhost:8000/api/health and MySQL at `localhost:3307` (next to XAMPP's 3306). Both listen on `127.0.0.1` only, so other computers on your network cannot reach them.
- **Passwords:** MySQL creates the `workforce_app` user with `MYSQL_APP_PASSWORD` the first time it starts. `DATABASE_PASSWORD` in `.env` must be the same password (it is kept out of `DATABASE_URL`, so any characters work, including `@`, `:`, `/`, and `%`). Changing either later needs a database reset, because MySQL only reads them when the data volume is new. Everyone picks their own passwords (for example `python -c "import secrets; print(secrets.token_hex(16))"`); they are never shared or committed, and CI generates throwaway ones.
- **Networks:** MySQL is only on a private network with the API. The API also joins the shared `workforce-ops` network, where the frontend's nginx reaches it; nginx can never reach the database directly.
- **The image** runs as an ordinary user (not root), and `.env` is never copied into it (`.dockerignore`); settings arrive as environment variables when the container starts.
- **The integration test** (`python -m scripts.integration_test`, also run by CI) starts a separate copy with throwaway passwords and free ports, so it never touches your own running copy or its data, then removes it.

### After pulling changes

Each contributor has their own database; GitHub carries its **structure**, never its **data**.

- **Structure** travels as migrations in `migrations/versions/`. After `git pull`, apply any you do not have yet with `docker compose run --rm api alembic upgrade head` (add `--build` to `docker compose up` too, so the API image has the new code). Alembic records the last migration it applied in the `alembic_version` table, so only new ones run, whoever pulls first.
- **Data** stays on each computer and is never committed. To see the same data as everyone else, start from an empty database and load the demo data:

  ```
  docker compose down --volumes                      # deletes your local data
  docker compose up -d --build
  docker compose run --rm api alembic upgrade head
  python -m scripts.seed_demo                        # once the seed script exists (Phase 2)
  ```

## Conventions specific to this repository

- New features go in `app/modules/<feature>/` with `router.py`, `schemas.py`, `service.py`, `repository.py`, `models.py`, and `permissions.py`.
- Only `repository.py` talks to the database, and every query is tenant-scoped and parameterized.
- Every service entry point calls `authorize()` with a permission and a target.
- One Alembic migration per PR.
- Security regression tests go in `tests/security/`.
