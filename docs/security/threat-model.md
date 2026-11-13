# Threat model

**In short:** a map of how data moves through the application, who might attack it, and what could go wrong at each step, with the protection that answers each threat and the test that proves it. It was written before any code, so the code is built against it, and the security audits check the application against it. It covers the core tier; each later feature adds its own rows.

> **Status:** design, core tier. Method: STRIDE on a data-flow diagram with four attacker profiles ([decision 0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md)).

## What we protect

| Asset | Why it matters |
|---|---|
| Company data: people, schedules, time-off requests | Personal and business information; each company must only ever see its own |
| Credentials: password hashes, session tokens, one-time setup and reset links | Whoever holds them can act as the user |
| Access rules: roles, role assignments, reporting lines | Access is handed down from the owner: only the owner holds every permission, and each person can pass on at most what they hold, only to people below them. Whoever changes these rules outside that path could give themselves or others more power than the owner intended |
| The audit log and its signing key | The trustworthy record of who did what |
| Availability | People need to see their shifts and request time off when they need to |
| Backups (next tier) | The way back after data is destroyed |

## How data moves

```mermaid
flowchart LR
    subgraph Internet["Internet (untrusted)"]
        B["Browser<br/>employee, manager,<br/>administrator, owner"]
        X["Outside attacker"]
    end
    subgraph Host["Application host (trusted)"]
        N["nginx<br/>pages, security headers,<br/>forwards /api"]
        A["API (FastAPI)<br/>sign-in, permissions,<br/>company filter, audit"]
        J["Background jobs<br/>(inside the API process)"]
        L["Application log<br/>(no personal data)"]
    end
    subgraph Data["Database (trusted, separate credentials)"]
        D[("MySQL<br/>application user:<br/>limited grants")]
    end
    subgraph Secrets["Secrets (outside the database)"]
        K["Audit signing key,<br/>database passwords"]
    end
    O["Operator / platform staff<br/>(seed script, migrations)"]

    B -- "HTTPS, session cookie,<br/>CSRF token" --> N
    X -. "any request" .-> N
    N -- "/api/*" --> A
    A -- "parameterized queries" --> D
    J --> D
    A -- "reads" --> K
    A --> L
    O -- "migration user" --> D
```

**Trust boundaries:**

| # | Boundary | What crosses it | Rule |
|---|---|---|---|
| TB1 | Internet → nginx | every request | nothing from the browser is trusted: not the body, not hidden fields, not IDs |
| TB2 | nginx → API | forwarded `/api` requests | the API checks sign-in, CSRF, and permissions on every request; nginx adds headers only |
| TB3 | API → database | queries | only through SQLAlchemy with bound parameters; the application's database user cannot drop, truncate, or alter tables, and can only add to the audit log |
| TB4 | API → secrets | the audit signing key, database passwords | kept in the environment, never in the database or the repositories |
| TB5 | Company → company | nothing | every company's data is in the same database but must never cross ([tenancy](../architecture/tenancy.md)) |
| TB6 | Person → person inside a company | actions on someone else's account, roles, or requests | allowed only with the right permission and a position above that person in the reporting chain |

## Who might attack

| Profile | Starting point | What they want |
|---|---|---|
| **P1 Outside attacker** | no account; can send any request from the internet | take over accounts, read data, disrupt the service |
| **P2 Malicious employee** | a valid account with the Employee role | see coworkers' or other companies' data, give themselves more access, approve their own requests, hide what they did |
| **P3 Compromised manager or administrator** | a privileged account, stolen or misused | reach people outside their part of the company, raise their own access further, change many records at once, cover their tracks |
| **P4 Rogue platform staff** | access to the server or the database | read companies' data, change records directly, rewrite the audit log, destroy data or backups |

The profiles are also how audit findings are grouped for research question RQ2 ([report plan](https://github.com/workforce-ops-app/.github/blob/main/docs/project/report-plan.md)).

## Threats and protections

Each row names the threat, who could carry it out, the protection (with the decision that sets it), and how it is tested. IDs are stable: findings, tests, and pull requests refer to them.

### Spoofing: pretending to be someone else

| ID | Threat | Profiles | Protection | Tested by |
|---|---|---|---|---|
| S1 | Guessing passwords, or trying passwords leaked from other sites | P1 | at least 15 characters, common-password blocklist, Argon2id hashing, escalating lockouts (never longer than 1 hour), 20 sign-in attempts per minute per address ([0027](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0027-authentication-and-sessions.md)) | lockout and rate-limit tests; Burp Suite |
| S2 | Stealing a session cookie (via XSS, an unencrypted connection, or a shared computer) | P1, P2 | `__Host-session` cookie with `Secure; HttpOnly; SameSite=Strict`; HTTPS only; strict Content Security Policy; 1 hour idle and 30 day maximum session | cookie attribute tests; idle and maximum expiry tests |
| S3 | Session fixation: planting a known session ID before the victim signs in | P1 | a new session ID at sign-in and on password change | test that the session ID changes at sign-in |
| S4 | Forged requests (CSRF): another site makes the victim's browser send a request | P1 | CSRF token in the `X-CSRF-Token` header, `SameSite=Strict`, Origin check | requests with a missing or wrong token or Origin are rejected |
| S5 | Stealing or guessing a setup or reset link | P1, P2 | long random token stored only as a hash, single use, 48 hours by default, token kept in the link's `#` part so it is never sent to servers or logs; using it signs out other sessions | tests for reuse, expiry, and wrong tokens |
| S6 | Blaming another address in the security events by sending a forged `X-Forwarded-For` header | P1, P2 | the client address is taken from nginx's header only when the request came through nginx (DE8 in [detection](../features/detection.md)) | test that a forged header from outside does not change the recorded address (planned, DT4) |

### Tampering: changing data without permission

| ID | Threat | Profiles | Protection | Tested by |
|---|---|---|---|---|
| T1 | SQL injection | P1, P2 | database access only through SQLAlchemy with bound parameters, no hand-built SQL strings ([0022](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0022-sqlalchemy-and-alembic.md)) | sqlmap and ZAP; security lint rules in CI; detection study |
| T2 | Changing fields the user must not set, such as `company_id`, status, or the author | P2 | request schemas list the allowed fields; the company always comes from the session ([0016](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0016-tenant-isolation.md)) | tests that send extra fields |
| T3 | Changing another company's records by guessing or reusing IDs | P1, P2, P3 | automatic company filter, company-aware foreign keys, 404 for other companies' records (0016) | cross-company suite on every endpoint |
| T4 | Editing, removing, or inserting audit entries directly in the database | P3, P4 | HMAC-signed chain with the key outside the database; the application's database user may only add entries; nightly verification; latest signatures copied to the application log ([0018](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0018-audit-log-chains.md)) | verification test with a tampered, a removed, and an inserted entry |
| T5 | Stored XSS: script hidden in names, shift notes, or request comments | P2, P3 | text is always shown with `textContent`, never `innerHTML` (enforced by lint); strict Content Security Policy with no inline scripts ([0005](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0005-frontend-multi-page-vanilla-js.md)) | XSS payloads in every text field; ZAP |
| T6 | Numbers outside what the database or the browser can hold (the web form of integer overflow): a value past a MySQL column's limit makes the request fail with an internal error, and JavaScript rounds anything past 2^53 | P1, P2 | every numeric request field has a minimum and maximum that fit its column (lists already allow at most 200 items); MySQL's default strict mode refuses out-of-range values instead of clipping them; IDs are UUID strings, so the browser never rounds them (0019, 0026) | boundary tests: maximum, maximum + 1, negative, and huge values answer 422, never 500 (planned, #105) |
| T7 | Stored XSS through the security page: the excerpt of a detected attack is attacker text, shown to owners and administrators | P1, P2 | excerpts are stored as plain text, at most 200 characters, and always shown with `textContent`; strict Content Security Policy (DE7 in [detection](../features/detection.md)) | XSS payloads as excerpts on the security page (planned, DT7) |

### Repudiation: denying having done something

| ID | Threat | Profiles | Protection | Tested by |
|---|---|---|---|---|
| R1 | Denying an approval, a role change, or a schedule change | P2, P3 | every such action writes an audit entry in the same database transaction, naming the actor (0018); sensitive actions need the password re-entered ([0025](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0025-sensitive-actions-and-security-settings.md)) | tests assert the audit entry for each action |
| R2 | Covering one's tracks by removing audit entries | P3, P4 | the application cannot remove entries; any removal breaks the chain (T4) | as T4 |
| R3 | Forging application log lines: text with line breaks written into the log looks like separate entries, for example a fake copy of the latest audit signatures | P1, P2 | log messages are fixed text; user input only goes in as extra fields, which the JSON log format escapes (`app/core/logging.py`); logs contain no personal details (0031) | test that a value with line breaks stays one log line; ruff's logging-format rules (planned, #106) |
| R4 | Evading detection with an unusual form of an attack, so it never appears on the security page | P1, P2 | none needed for safety: detection only records, and the real protections are T1, T5, and the course-topic rows; input is normalized before matching, and the study measures how much slips through ([detection](../features/detection.md)) | detection study: recall per attack type on the test set and the field set |

### Information disclosure: seeing what you should not

| ID | Threat | Profiles | Protection | Tested by |
|---|---|---|---|---|
| I1 | Reading another company's records | P1, P2, P3 | the four tenancy layers (0016) | cross-company suite |
| I2 | Reading records in your own company outside your scope | P2, P3 | `authorize()` on every record and a scope filter on every list ([authorization](../architecture/authorization.md)) | scope tests: 403 inside the company |
| I3 | Finding out which records, people, or email addresses exist | P1, P2, P3 | IDs are not guessable (UUIDv7); other companies' records answer 404; sign-in gives the same error for an unknown email and a wrong password | tests compare responses for existing and missing records and accounts |
| I4 | Error messages that reveal internals (stack traces, SQL) | P1 | one error format that never includes internal details ([0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md)) | tests with malformed input; ZAP |
| I5 | Leaking password hashes, tokens, or secrets | P1, P4 | Argon2id; session and link tokens stored only as hashes; secrets never committed (secret scanning in CI and git hooks); logs contain no personal details ([0031](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0031-demo-environment-and-data.md)) | secret scan; log review in audits |
| I6 | Personal data left in the browser's cache on a shared computer, readable after signing out | P1, P2 | every API answer says `Cache-Control: no-store` (`app/core/caching.py`); the frontend never keeps the session in browser storage | test that every kind of answer carries the header |
| I7 | Format string attacks: user text used as a format template, such as `user_text.format(obj)`, can read the program's internals, for example `{0.__class__.__init__.__globals__}` reaching secrets | P1, P2 | user text is only ever a value, never the template for `str.format`, `%`, or a log message | test that text such as `{0.__class__}` and `%s%n` is stored and returned exactly as typed; ruff's logging-format rules (planned, #106) |
| I8 | Detection storing secrets: a password, token, or cookie copied into a security event | P4 | no headers are collected, credential routes are skipped, and secret-named fields are left out at any depth while the copy is made, before anything is queued; credential fields are `SecretStr` (DE3 in [detection](../features/detection.md)) | test that attack strings in headers, credential routes, and nested secret fields leave no event and no stored text; test over every request model's `SecretStr` fields (planned, DT4) |

### Denial of service: making the application unusable

| ID | Threat | Profiles | Protection | Tested by |
|---|---|---|---|---|
| D1 | Flooding the sign-in form, or locking real users out on purpose | P1 | rate limits per address and per session; lockouts escalate but never exceed 1 hour, so they cannot lock someone out for good (0025, 0027) | rate-limit and lockout tests |
| D2 | Expensive requests: huge lists or bodies, slow queries | P1, P2 | lists are paged (at most 200 items); request size limits; query timeouts (0026) | tests with oversized requests |
| D3 | Destroying data from inside | P3, P4 | records are deactivated or archived, never deleted ([0020](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0020-status-over-deletion.md)); the application's database user cannot drop or truncate; confirmation for changes to 10 or more shifts (0025); backups in the next tier ([0028](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0028-backup-and-recovery.md)) | database grant check (`check_migrations.py`, `_grant_problems`); batch confirmation tests (`tests/security/test_shift_batch.py`); restore drills (next tier) |
| D4 | Slow patterns: crafted input that makes a regular expression take a very long time (ReDoS), freezing a worker | P1 | inspection runs after the answer is sent, values are capped at 2,000 characters and 200 per request, and patterns without nested repetition must pass a worst-case timing test (DE2, DE4, DE5 in [detection](../features/detection.md)) | worst-case timing test in CI (planned, DT3) |
| D5 | Flooding the security events to fill the table or bury a real attack among noise | P1, P2 | at most 20 events per minute per source, then one inserted summary row; a fixed-size queue that drops and counts copies instead of waiting; events kept 1 year (DE6, DE11 in [detection](../features/detection.md)) | rate-cap test; full-queue test (planned, DT2, DT4) |

### Elevation of privilege: gaining more power than you were given

| ID | Threat | Profiles | Protection | Tested by |
|---|---|---|---|---|
| E1 | Giving yourself more access: editing your own roles or reporting lines | P2, P3 | nobody changes their own role assignments or reporting lines ([0024](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0024-authorization-model.md)) | escalation tests |
| E2 | Granting a permission you do not hold, or copying your own level onto others without anyone above knowing | P3 | nobody grants a permission they do not hold (0024); giving a role at your own level needs approval from someone above you ([0032](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0032-delegation-limits.md)) | escalation tests; approval tests |
| E3 | Acting on a peer or a superior, for example one administrator resetting another's password | P3 | acting on a person needs the permission **and** a position above them in the reporting chain (0024) | tests for peers, superiors, and people in other branches of the chain |
| E4 | Rearranging reporting lines to get above someone | P3 | adding or ending a line needs a position above both people, `reporting_line.manage`, and the password re-entered; loops are rejected; every change is audited (0024, 0025) | tests for loops, self-changes, and missing positions |
| E5 | Approving your own request | P2, P3 | nobody reviews their own request ([0029](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0029-request-approval-routing.md)) | self-approval tests |
| E6 | Taking over a company: removing the last owner, adding yourself or an ally as owner, or one co-owner removing another | P3 | only owners add or remove owners, with the password re-entered; adding needs every current owner, removing needs every other owner; the last owner cannot be removed (0024, 0025, 0032) | owner-change and last-owner tests |
| E7 | Weakening company security settings | P3 | companies can only make settings stricter, within platform limits (0025) | tests for values below the limits |
| E8 | Calling the API directly for actions whose buttons are hidden | P2 | the interface only hides buttons for convenience; the API checks every action | every endpoint's permission test runs without the interface |
| E9 | Changing a role held by peers or superiors, for example an administrator weakening or reshaping the Administrator role | P3 | a role can be changed only by someone above every current holder, or the Owner; the Owner role is locked (0032) | role-editing tests with holders above, beside, and below the editor |
| E10 | Memory corruption in compiled code (buffer or heap overflow, return-oriented programming) letting an attacker run their own code on the server | P1 | our own code is written in memory-safe languages (Python, JavaScript), so these bugs cannot come from it; the compiled parts underneath (the Python interpreter, nginx, the native parts of `cryptography` and `argon2-cffi`) are pinned and checked for known vulnerabilities, and rely on the operating system's defenses: ASLR, stack canaries, and non-executable memory | pip-audit and npm audit in CI; Dependabot; `checksec` on the compiled programs in each image (planned, #107) |

## Course topics and audit checklist

| Course topic | Threats |
|---|---|
| SQL injection | T1 |
| Session hijacking | S2, S3 |
| Cross-site request forgery | S4 |
| Cross-site scripting | T5 |
| Cryptography | S1 (Argon2id), S5 and I5 (hashed tokens), T4 (HMAC chain) |
| Secure coding and defense in depth | T3, I1 to I3, E1 to E9; detection (R4, D4) |
| Type safety | T2 (request schemas checked by Pydantic at run time and by mypy in CI) |
| Code injection | T1, I7 (ruff's security rules forbid `eval`, `exec`, and `pickle` on untrusted data) |
| Integer overflow | T6 |
| Format string vulnerabilities | I7, R3 |
| Memory safety, buffer overflow, return-oriented programming, ASLR, stack canaries | E10 |

The audits follow the applicable areas of OWASP ASVS Level 2 (0030); the first one is the [midterm audit](audit-midterm.md):

| ASVS area | Threats |
|---|---|
| Authentication | S1, S5 |
| Session management | S2, S3, S4 |
| Access control | T3, I1, I2, E1 to E9 |
| Validation, sanitization, and encoding | T1, T2, T5 to T7, I7, D4 |
| Cryptography | T4, I5 |
| Error handling and logging | I4, R1 to R4, I8, D5, S6 |
| API and web service | T2, D2 |
| Configuration (headers, secrets) | S2, I5, I6 |
| Secure build and dependencies | E10 |

## Known limits

- **Company separation is enforced by the application.** MySQL has no row-level security. Layers 2 to 4 of [tenancy](../architecture/tenancy.md) exist so that one application bug is not enough to leak data, but someone with the database password bypasses layer 1.
- **A compromised administrator can act immediately.** Until the stretch safeguards (waiting periods, second approvals) exist, an administrator whose password is known to the attacker can make every change their permissions and position allow. Each change is audited (0025).
- **Platform staff with both the database and the signing key could forge the audit log.** Keeping the key out of the database, and copying the latest signatures to the application log, makes this harder and detectable after the fact, not impossible (0018).
- **Email addresses are unique across the platform.** When an administrator adds an email that another company already uses, the answer is only "this email can't be used", but that still reveals that the address is taken somewhere (I3).
- **Network-level flooding is out of scope.** It is the hosting provider's job; the report states this under threats to validity (0030).
- **Compiled code underneath the application is trusted, not audited.** Memory-safety bugs in the Python interpreter, nginx, or native libraries are outside what our tests can find; we keep them updated and check that their built-in defenses are on (E10), but do not fuzz or review them.
- **The audits run on local and test copies only**, not a production deployment.

## Keeping it current

- Each feature page lists the threats (by ID) that apply to it; a new kind of threat gets a new row here in the same pull request.
- Next-tier features add rows when they are designed: file uploads, coverage and swaps, announcements, notifications, backups. Detection added S6, T7, R4, I8, D4, and D5.
- Audit findings name the threat ID they fall under, or add one.
