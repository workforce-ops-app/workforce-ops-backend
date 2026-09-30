# User Documentation: Backend API

**In short:** how to use the backend's API, for frontend developers and anyone integrating with it. End-user guides (for employees, managers, administrators, and owners) live in the frontend repository.

> Written as the endpoints are built (Phases 2 and 3). The conventions are already decided in [decision 0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md) and the [authentication](../architecture/authentication.md) page; the generated reference will be in [../api/](../api/README.md).

## Topics

| Topic | Status |
|---|---|
| Signing in and sessions | to do (design: [authentication](../architecture/authentication.md)) |
| CSRF tokens on requests that change something | to do (design: [authentication](../architecture/authentication.md#forged-requests-csrf)) |
| Password re-entry for sensitive actions | to do (design: [authentication](../architecture/authentication.md#password-re-entry-for-sensitive-actions)) |
| [Errors and status codes](errors.md) | done |
| Paging, filtering, and sorting | to do (design: [0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md)) |
| Addresses: everything under `/api`, with no version number | to do (design: [0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md)) |
