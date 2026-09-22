# Contributor Documentation — Backend

**In short:** how to set up and work on the backend. The shared workflow (issues, branches, PRs, CI) is in the [contributor guide](https://github.com/workforce-ops-app/.github/tree/main/docs/contributing); this page covers what is specific to this repository.

> Pending: setup commands will be added with the application scaffold.

## Quick reference

| Task | Command |
|---|---|
| Run all CI checks locally | `python ../.github/scripts/ci_runner.py` |
| Run one check | `python ../.github/scripts/ci_runner.py --only lint` |
| Install git hooks | `pre-commit install` |

## Conventions specific to this repository

- New features go in `app/modules/<feature>/` with `router.py`, `schemas.py`, `service.py`, `repository.py`, `models.py`, and `permissions.py`.
- Only `repository.py` talks to the database, and every query is tenant-scoped and parameterized.
- Every service entry point calls `authorize()` with a permission and a target.
- One Alembic migration per PR.
- Security regression tests go in `tests/security/`.
