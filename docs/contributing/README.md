# Contributor Documentation: Backend

**In short:** how to set up and work on the backend. The shared workflow (issues, branches, PRs, CI) is in the [contributor guide](https://github.com/workforce-ops-app/.github/tree/main/docs/contributing); this page covers what is specific to this repository.

## First-time setup

Needs Python 3.13 and pre-commit ([local setup](https://github.com/workforce-ops-app/.github/blob/main/docs/contributing/local-setup.md)). From this repository's folder:

```
py -3.13 -m venv .venv                 # macOS/Linux: python3.13 -m venv .venv
.venv\Scriptsctivate                 # macOS/Linux: source .venv/bin/activate
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
| Run the tests with coverage (which lines of `app/` the tests run; missing line numbers listed per file) | `python -m pytest --cov --cov-report=term` |
| Format the code | `ruff format .` |
| Lint (including security rules) | `ruff check .` (add `--fix` for automatic fixes) |
| Type check | `mypy app` |
| Check dependencies for known vulnerabilities | `pip-audit --skip-editable` |

## Conventions specific to this repository

- New features go in `app/modules/<feature>/` with `router.py`, `schemas.py`, `service.py`, `repository.py`, `models.py`, and `permissions.py`.
- Only `repository.py` talks to the database, and every query is tenant-scoped and parameterized.
- Every service entry point calls `authorize()` with a permission and a target.
- One Alembic migration per PR.
- Security regression tests go in `tests/security/`.
