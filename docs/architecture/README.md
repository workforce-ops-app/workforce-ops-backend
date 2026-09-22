# Project Architecture — Backend

**In short:** how the backend is put together: its layers, modules, data model, and security design.

> Pending: the data model, tenancy enforcement, authorization, and API conventions are still being designed. These pages will be filled in as those decisions are made.

## Overview

The backend is organized by feature module ([decision 0004](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0004-backend-feature-modules.md)). Shared layers (`auth`, `authz`, `tenancy`, `audit`, `detection`, `jobs`) provide extension points so modules plug in without editing them ([decision 0012](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0012-extensibility-patterns.md)).

## Pages

| Page | Status |
|---|---|
| Layers and modules | to do |
| Data model (schema diagrams) | to do |
| Tenancy (company isolation) | to do |
| Authentication and sessions | to do |
| Authorization (permissions and scopes) | to do |
| Audit log | to do |
| Detection | to do |
| Background jobs | to do |
| [Glossary](glossary.md) | started |
