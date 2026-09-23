# Project Architecture — Backend

**In short:** how the backend is put together: its layers, modules, data model, and security design.

> Pending: authorization details and API conventions are still being designed. Pages marked *design* describe agreed decisions whose code does not exist yet.

## Overview

The backend is organized by feature module ([decision 0004](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0004-backend-feature-modules.md)). Shared layers (`auth`, `authz`, `tenancy`, `audit`, `detection`, `jobs`) provide extension points so modules plug in without editing them ([decision 0012](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0012-extensibility-patterns.md)).

## Pages

| Page | Status |
|---|---|
| Layers and modules | to do |
| [Data model](data-model.md) (core tables, conventions, time zones, retention) | design |
| [Tenancy](tenancy.md) (keeping companies separate) | design |
| Authentication and sessions | to do |
| Authorization (permissions and scopes) | to do |
| [Audit log](audit-log.md) (signed per-company chains) | design |
| Detection | to do |
| Background jobs | to do |
| [Glossary](glossary.md) | started |
