# Project Architecture: Backend

**In short:** how the backend is put together: its layers, modules, data model, and security design.

> Pages marked *design* describe agreed decisions whose code does not exist yet. The pages marked *to do* are written before the code they describe; the decisions behind them are already made (0024 authorization, 0026 API conventions, 0027 authentication).

## Overview

The backend is organized by feature module ([decision 0004](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0004-backend-feature-modules.md)). Shared layers (`auth`, `authz`, `tenancy`, `audit`, `detection`, `jobs`) provide extension points so modules plug in without editing them ([decision 0012](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0012-extensibility-patterns.md)).

## Pages

| Page | Status |
|---|---|
| Layers and modules (the `app/` structure, how modules plug in) | to do: written with the backend skeleton (Phase 1) |
| [Data model](data-model.md) (core tables, conventions, time zones, retention) | design |
| [Tenancy](tenancy.md) (keeping companies separate) | design |
| [Authorization](authorization.md) (permissions, starting roles, scopes, reporting chain, escalation rules) | design |
| [Authentication and sessions](authentication.md) (passwords, sessions, CSRF, lockouts, one-time links, password re-entry) | design |
| [Audit log](audit-log.md) (signed per-company chains) | design |
| Detection (pattern-based detection of attack attempts) | to do: next tier ([0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md)) |
| Background jobs (time-off review deadline, nightly audit verification, session and link cleanup) | to do: written with the first job (Phase 2) |
| [Glossary](glossary.md) | kept current with each page |
