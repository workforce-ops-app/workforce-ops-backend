# Midterm backend audit (OWASP ASVS 5.0, Level 2)

**In short:** before the midterm we checked the backend against a recognized security checklist, the OWASP Application Security Verification Standard (ASVS), at Level 2. Of the 201 checklist items in scope, 111 pass, 18 fail, and the rest do not apply yet: the feature is not built, it depends on where the application will be hosted, or it belongs to the frontend audit. The checks that matter most for the demo pass: company separation, permissions and scopes, sessions and cookies, forged-request protection, SQL injection, and safe error messages. Most failures are already planned work (sign-in lockouts and rate limits, a restricted database account, audit log verification) or security policies that have not been written down yet. Each failure is listed below with the issue that fixes it.

- **Status:** done for the midterm backend as merged on 2026-10-12 (`main` at `0974d71`); batch shift changes (SC2, #62) are checked when they merge
- **Related:** #67 (this audit), tracker workforce-ops-app/.github#56 (AU1 and AU2), [threat model](threat-model.md), [security controls](security-controls.md), [findings log](findings-log.md)

## Scope

- **What:** the backend as built for the midterm ([0036](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0036-midterm-scope-schedules.md)): sign-in and sessions, CSRF protection, permissions and scopes, company separation, input handling, errors and logging, the audit log, departments, and shifts. The frontend's nginx configuration is included where it sets the headers on API answers.
- **Not covered:** the frontend's own code (frontend audit, Phase 4); features after the midterm, which the audits planned for the second half cover ([0023](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0023-feature-tiers-and-audit-schedule.md)).
- **Checklist:** [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0/5.0), Level 1 and Level 2 requirements, as decided in [0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md). Whole chapters that do not apply are listed at the end.

## Method

1. Each requirement was read against the code, the configuration (`Dockerfile`, `docker-compose.yml`, the frontend's `nginx/nginx.conf`), and the documentation.
2. A requirement passes only when the code does what it asks and, where one exists, a test proves it. The checklist names the file or test for each one.
3. The automated checks ran on the same commit and all passed: 189 unit tests, 161 security tests, migrations, type check, `pip-audit` (no known vulnerabilities), and the secret scan.
4. Each failure became a finding: an issue from the security-finding template, or a link to the issue that already plans the fix. None of the findings can be exploited to reach another company's data or to act without permission, so none needed a private advisory ([security policy](https://github.com/workforce-ops-app/.github/blob/main/SECURITY.md)).

**Results:** **Pass** (done, and checked where the checklist says); **Fail** (needed now and missing, see Findings); **N/A** (the application has nothing this applies to); **Not built** (applies to a feature built after the midterm, checked in a later audit); **Deployment** (depends on hosting and HTTPS, open question 2 on the Roadmap); **Frontend** (checked in the frontend audit).

## Findings

Fixes are tracked as AU2 in workforce-ops-app/.github#56. A finding enters the [findings log](findings-log.md) once its fix merges.

| Finding | Requirements | Severity | Fixed by |
|---|---|---|---|
| **A1** Refused requests are not logged: a 403, a cross-company 404, or a forged request leaves no trace, and application log lines do not say who sent a request or from where | V16.2.1, V16.3.2, V16.3.3 | medium: an attack in progress (probing IDs, forged requests) cannot be seen or investigated | #92 |
| **A2** Sensitive data has no protection levels, and the keys have no written lifecycle (creation, rotation, retirement) | V11.1.1, V14.1.1, V14.1.2, V14.2.4 | low: the protections exist, but nothing says which data needs which, or how a leaked key is replaced | #93 |
| **A3** Limits on use are not defined: requests per person or overall, sessions per account, which functions are expensive, and query time limits | V2.1.3, V2.4.1, V7.1.2, V15.1.3 | low: a signed-in person can send unlimited requests and open unlimited sessions | #94 |
| **A4** Sign-in uses a password only; ASVS Level 2 expects a second factor. Two-factor sign-in is a stretch item, so the deviation must be recorded | V6.3.3 | medium: a stolen password is enough to sign in | workforce-ops-app/.github#71 |
| **A5** No time frames for fixing vulnerable dependencies, and no software bill of materials | V15.1.1, V15.1.2 | low: dependency checks run, but nothing says how fast a finding must be fixed | workforce-ops-app/.github#72 |
| Sign-in has no lockouts or rate limits yet | V6.3.1, V2.4.1, V15.2.2 | high: passwords can be guessed without limit, and sign-in can be flooded | #50 (planned, Final demo milestone) |
| Oversized passwords reach the slow password hash | V6.3.1, V15.2.2 | medium: large requests cost the server time and memory | #85 |
| The application's database user can change the schema and edit the audit log | V13.2.2, V16.4.2 | medium: a break-in through the application gets full control of the database | #43 (planned, Final demo milestone) |
| Nothing verifies the audit log yet; changes are detectable but not detected | V16.4.2 | medium: tampering would go unnoticed until someone checks | #58 (planned, Final demo milestone) |

## Deferred to hosting

These depend on where and how the application is deployed (Roadmap open question 2, and question 3 on whether a local HTTPS deployment counts): TLS everywhere, including between nginx, the API, and MySQL (V12), HSTS and the HTTP to HTTPS redirect (V3.4.1, V4.1.2), a secrets manager (V13.3.1), and sending logs to a separate system (V16.4.3). They are rechecked when hosting is decided.

## Course topics checked

| Course topic | Requirements | Result |
|---|---|---|
| SQL injection | V1.2.4 | pass |
| XSS | V1.2.1, V3.2.1, V3.4.3, V3.4.4 (V3.2.2 in the frontend audit) | pass |
| CSRF | V3.3.2, V3.5.1, V3.5.3 | pass |
| Sessions | V7.2.1 to V7.4.2, V3.3.1 to V3.3.4 | pass |
| Password hashing | V11.4.2, V6.2.1 to V6.2.12 | pass |
| REST | V4.1.1, V8.2.1, V8.2.2, V15.3.3 | pass |
| SQL JOINs | V8.2.2 (lists filtered by scope and company across joins) | pass |

## Results by chapter

| Chapter | Pass | Fail | N/A | Not built | Deployment | Frontend |
|---|---|---|---|---|---|---|
| V1 Encoding and Sanitization | 15 | 0 | 12 | 0 | 0 | 0 |
| V2 Validation and Business Logic | 8 | 2 | 1 | 0 | 0 | 0 |
| V3 Web Frontend Security | 13 | 0 | 2 | 0 | 1 | 3 |
| V4 API and Web Service | 3 | 0 | 6 | 0 | 1 | 0 |
| V6 Authentication | 14 | 2 | 13 | 4 | 0 | 2 |
| V7 Session Management | 11 | 1 | 2 | 4 | 0 | 0 |
| V8 Authorization | 7 | 0 | 0 | 0 | 0 | 0 |
| V11 Cryptography | 8 | 1 | 5 | 0 | 0 | 0 |
| V12 Secure Communication | 0 | 0 | 1 | 0 | 8 | 0 |
| V13 Configuration | 9 | 1 | 2 | 0 | 1 | 0 |
| V14 Data Protection | 6 | 3 | 0 | 0 | 0 | 0 |
| V15 Secure Coding and Architecture | 6 | 4 | 2 | 0 | 0 | 1 |
| V16 Security Logging and Error Handling | 11 | 4 | 0 | 0 | 1 | 0 |
| **All 201** | **111** | **18** | **46** | **8** | **12** | **6** |

## Checklist

Each Level 1 and Level 2 requirement of the chapters in scope. The requirement column is a short summary; the full wording is in ASVS 5.0.0 under the same ID.

### V1 Encoding and Sanitization

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V1.1.1 | 2 | Decode input once, before validating it | Pass | Request bodies are parsed once (FastAPI and Pydantic); the only other decoding is the list cursor, decoded once and then checked (`repository.decode_cursor`) |
| V1.1.2 | 2 | Encode output as the last step, for its interpreter | Pass | SQL values are bound parameters (SQLAlchemy); JSON is written by the response serializer; HTML is the frontend's job (`textContent`) |
| V1.2.1 | 1 | Output encoding fits its context | Pass | The API answers JSON only; it never builds HTML |
| V1.2.2 | 1 | Untrusted data in built URLs is encoded | Pass | The only value the API builds for a URL is the list cursor, base64url-encoded |
| V1.2.3 | 1 | JSON is built with escaping | Pass | Pydantic and `json.dumps` write every answer; no JSON is assembled from strings |
| V1.2.4 | 1 | Database queries are parameterized | Pass | Every query goes through SQLAlchemy with bound parameters, never SQL text ([0022](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0022-sqlalchemy-and-alembic.md)); `tests/security/test_shifts.py::test_text_fields_come_back_exactly_as_written` |
| V1.2.5 | 1 | No OS command injection | Pass | The application runs no operating system commands |
| V1.2.6 | 2 | LDAP injection | N/A | No LDAP |
| V1.2.7 | 2 | XPath injection | N/A | No XML or XPath |
| V1.2.8 | 2 | LaTeX injection | N/A | No LaTeX |
| V1.2.9 | 2 | Regular expression metacharacters are escaped | Pass | No input is used as a pattern; the password name check compares text, not patterns (`app/auth/passwords.py`) |
| V1.3.1 | 1 | HTML from rich-text editors is sanitized | N/A | No HTML input is accepted (announcements, next tier, will need this) |
| V1.3.2 | 1 | No eval() or dynamic code execution | Pass | None in the application |
| V1.3.3 | 2 | Input for risky contexts is limited | Pass | Every text field has a maximum length (`schemas.py` files); IDs and dates are typed |
| V1.3.4 | 2 | SVG is sanitized | N/A | No uploads yet; SVG will be refused by design (next tier) |
| V1.3.5 | 2 | Markdown, CSS, or other scriptable input is sanitized | N/A | No such input |
| V1.3.6 | 2 | Server-side request forgery (SSRF) | N/A | The API makes no outbound requests |
| V1.3.7 | 2 | Template injection | N/A | No server-side templates |
| V1.3.8 | 2 | JNDI injection | N/A | Not Java |
| V1.3.9 | 2 | Memcache injection | N/A | No memcache |
| V1.3.10 | 2 | Format strings are not built from input | Pass | Log messages are fixed text with separate fields (`app/core/logging.py`) |
| V1.3.11 | 2 | Mail injection | N/A | No email is sent yet (next tier) |
| V1.4.1 | 2 | Memory-safe string handling | Pass | Python |
| V1.4.2 | 2 | Integer ranges are checked | Pass | List `limit` is 1 to 200; audit details refuse integers beyond 64 bits (`app/audit/record.py`) |
| V1.4.3 | 2 | Memory is released safely | Pass | Python's memory management |
| V1.5.1 | 1 | XML parsers are locked down (XXE) | N/A | No XML |
| V1.5.2 | 2 | Untrusted data is deserialized safely | Pass | Only JSON into typed Pydantic models; no pickle or similar |

### V2 Validation and Business Logic

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V2.1.1 | 1 | Input validation rules are documented | Pass | [schedules](../features/schedules.md), [authentication](../architecture/authentication.md) (passwords), and the request schemas |
| V2.1.2 | 2 | Rules for combined fields are documented | Pass | A shift ends after it starts, lasts at most 12 hours, and is not in the past ([schedules](../features/schedules.md)) |
| V2.1.3 | 2 | Business limits are documented per user and overall | **Fail** | Per-request limits are documented (31 days, 200 items, 12 hours); limits per person and across the application are only designed for sign-in. A3: #94 |
| V2.2.1 | 1 | Input is checked against expected values | Pass | Typed UUIDs, dates with offsets, lengths, `extra="forbid"` (`app/modules/schedules/schemas.py`) |
| V2.2.2 | 1 | Validation happens on the server | Pass | All rules are in the service layer; the frontend's checks are convenience only |
| V2.2.3 | 2 | Related fields are checked together | Pass | Start and end, the person's department or team, overlapping shifts (`app/modules/schedules/service.py`) |
| V2.3.1 | 1 | Multi-step flows keep their order | N/A | No multi-step flows yet (time-off review comes after the midterm) |
| V2.3.2 | 2 | Documented business limits are enforced | Pass | 12-hour shifts, no past shifts, no double booking, ended and cancelled shifts locked; `tests/unit/test_shifts_api.py` |
| V2.3.3 | 2 | Business operations are transactions | Pass | Each action and its audit entry commit together or not at all (`app/audit/record.py`) |
| V2.3.4 | 2 | Limited resources cannot be double-booked | Pass | The person's row is locked (`SELECT ... FOR UPDATE`) while overlaps are checked (`repository.person`) |
| V2.4.1 | 2 | Anti-automation against excessive calls | **Fail** | No rate limits on any endpoint yet. Sign-in: #50; other endpoints: A3: #94 |

### V3 Web Frontend Security

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V3.2.1 | 1 | API answers cannot be rendered as pages | Pass | JSON content type with `X-Content-Type-Options: nosniff` and a CSP on every answer (frontend `nginx/nginx.conf`, which serves `/api`) |
| V3.2.2 | 1 | Text is shown with safe functions | Frontend | Frontend audit (Phase 4); the screens use `textContent` |
| V3.3.1 | 1 | Cookies are Secure with a __Host- or __Secure- prefix | Pass | `__Host-session` with `Secure` (`app/modules/sessions/router.py`); `tests/security/test_sign_in.py::test_the_cookie_has_every_protective_attribute` |
| V3.3.2 | 2 | SameSite fits each cookie's purpose | Pass | `SameSite=Strict` on the only cookie; same test |
| V3.3.3 | 2 | Cookies use the __Host- prefix | Pass | Same cookie and test |
| V3.3.4 | 2 | Session cookies are HttpOnly | Pass | `HttpOnly`; the token is never in an answer body; same test |
| V3.4.1 | 1 | HSTS for at least a year | Deployment | nginx sends `max-age=31536000; includeSubDomains` over HTTPS; there is no HTTPS deployment yet |
| V3.4.2 | 1 | CORS origin is fixed or allowlisted | Pass | No CORS headers at all: pages and API share one origin ([0003](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0003-same-origin-deployment.md)) |
| V3.4.3 | 2 | Content-Security-Policy | Pass | `default-src 'self'` and more on every answer (frontend `nginx/nginx.conf`) |
| V3.4.4 | 2 | X-Content-Type-Options: nosniff | Pass | On every answer (frontend `nginx/nginx.conf`) |
| V3.4.5 | 2 | Referrer-Policy | Pass | `strict-origin-when-cross-origin` (frontend `nginx/nginx.conf`) |
| V3.4.6 | 2 | frame-ancestors in the CSP | Pass | `frame-ancestors 'none'` (frontend `nginx/nginx.conf`) |
| V3.5.1 | 1 | Cross-origin requests to sensitive functions are refused | Pass | Origin check and CSRF token on every changing request (`app/auth/csrf.py`); `tests/security/test_csrf.py` |
| V3.5.2 | 1 | If relying on CORS preflight, it cannot be skipped | N/A | Not relied on; the Origin check covers simple requests too |
| V3.5.3 | 1 | Changes use POST, PUT, PATCH, or DELETE | Pass | No GET changes anything; `tests/security/test_csrf.py::test_reading_needs_neither_token_nor_origin` |
| V3.5.4 | 2 | Separate applications on separate hostnames | N/A | One application |
| V3.5.5 | 2 | postMessage origins are checked | Frontend | Frontend audit (Phase 4); no postMessage is used |
| V3.7.1 | 2 | Only supported client technologies | Frontend | Frontend audit (Phase 4) |
| V3.7.2 | 2 | Redirects to other hosts only from an allowlist | Pass | The API never redirects to another host |

### V4 API and Web Service

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V4.1.1 | 1 | Content-Type matches the body | Pass | `application/json` or `application/problem+json` (JSON is UTF-8 by definition, RFC 8259) |
| V4.1.2 | 2 | Only user-facing endpoints redirect HTTP to HTTPS | Deployment | No HTTPS deployment yet |
| V4.1.3 | 2 | Headers set by the proxy cannot be overridden by users | Pass | nginx sets `Host` and `X-Forwarded-*`; the API ignores forwarded headers and uses `APP_ORIGIN` for its Origin check |
| V4.2.1 | 2 | HTTP message boundaries are handled consistently | Pass | Standard servers only (nginx in front of uvicorn), no custom parsing |
| V4.3.1 | 2 | GraphQL limits | N/A | No GraphQL |
| V4.3.2 | 2 | GraphQL introspection | N/A | No GraphQL |
| V4.4.1 | 1 | WebSockets over TLS | N/A | No WebSockets |
| V4.4.2 | 2 | WebSocket Origin check | N/A | No WebSockets |
| V4.4.3 | 2 | WebSocket session tokens | N/A | No WebSockets |
| V4.4.4 | 2 | WebSocket tokens from the HTTPS session | N/A | No WebSockets |

### V6 Authentication

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V6.1.1 | 1 | Defenses against password guessing are documented | Pass | [authentication: lockouts and rate limits](../architecture/authentication.md#lockouts-and-rate-limits) |
| V6.1.2 | 2 | Context-specific words are documented | Pass | Company name, email name, display name, and their words ([authentication](../architecture/authentication.md)) |
| V6.1.3 | 2 | All sign-in pathways are documented | Pass | One pathway: email and password |
| V6.2.1 | 1 | Passwords are at least 8 characters (15 recommended) | Pass | At least 15 (`app/auth/passwords.py`); `tests/security/test_password_rules.py::test_short_passwords_are_refused` |
| V6.2.2 | 1 | Users can change their password | Not built | Account screens and endpoints come after the midterm (frontend #21) |
| V6.2.3 | 1 | Changing a password needs the current one | Not built | As above |
| V6.2.4 | 1 | New passwords are checked against common passwords | Pass | Blocklist of the 100,000 most-used passwords, filtered to 15 characters or more; `test_common_passwords_are_refused_in_any_case`. Applied wherever a password is set (only the demo seed so far) |
| V6.2.5 | 1 | No composition rules | Pass | Any characters allowed (`app/auth/passwords.py`) |
| V6.2.6 | 1 | Password fields are masked | Frontend | Frontend audit (Phase 4) |
| V6.2.7 | 1 | Paste and password managers work | Frontend | Frontend audit (Phase 4) |
| V6.2.8 | 1 | Passwords are checked exactly as received | Pass | No truncation or case change; Unicode NFKC normalization only, as NIST SP 800-63B recommends |
| V6.2.9 | 2 | Passwords of 64+ characters are allowed | Pass | Up to 128; `test_long_passphrases_are_accepted` |
| V6.2.10 | 2 | No forced password rotation | Pass | None ([authentication](../architecture/authentication.md)) |
| V6.2.11 | 2 | Context-specific words are refused | Pass | `test_passwords_built_from_names_are_refused` |
| V6.2.12 | 2 | New passwords are checked against breached passwords | Pass | The NCSC list is built from breach data; an offline list, not a live breach service |
| V6.3.1 | 1 | Password guessing and credential stuffing are stopped | **Fail** | Not yet: lockouts and rate limits are designed but not built (#50); oversized passwords still reach Argon2id (#85) |
| V6.3.2 | 1 | No default accounts | Pass | None; demo accounts exist only after the demo seed, which refuses production |
| V6.3.3 | 2 | Multi-factor authentication (or a combination of factors) | **Fail** | Password only; two-factor sign-in is a stretch item ([0023](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0023-feature-tiers-and-audit-schedule.md)). A4: workforce-ops-app/.github#71 |
| V6.3.4 | 2 | No undocumented sign-in pathways | Pass | Only sign-in may read across companies; `tests/security/test_sign_in.py::test_only_sign_in_uses_the_cross_company_read` |
| V6.4.1 | 1 | Initial passwords and activation codes are random and expire | Not built | Setup links come after the midterm |
| V6.4.2 | 1 | No password hints or secret questions | Pass | None |
| V6.4.3 | 2 | Secure password reset | Not built | Reset links come after the midterm |
| V6.4.4 | 2 | Lost second factor needs identity proofing | N/A | No second factor |
| V6.5.1 | 2 | One-time codes work once | N/A | No one-time codes (setup links will be checked when built) |
| V6.5.2 | 2 | Low-entropy lookup secrets are hashed | N/A | None |
| V6.5.3 | 2 | One-time codes come from a CSPRNG | N/A | None |
| V6.5.4 | 2 | One-time codes have 20+ bits of entropy | N/A | None |
| V6.5.5 | 2 | One-time codes have a short lifetime | N/A | None |
| V6.6.1 | 2 | SMS or phone one-time passwords | N/A | None |
| V6.6.2 | 2 | Out-of-band codes are bound to their request | N/A | None |
| V6.6.3 | 2 | Out-of-band codes are rate limited | N/A | None |
| V6.8.1 | 2 | Identities cannot be spoofed across identity providers | N/A | No external identity providers |
| V6.8.2 | 2 | Signed assertions are validated | N/A | None |
| V6.8.3 | 2 | SAML assertions are used once | N/A | None |
| V6.8.4 | 2 | Authentication strength from an identity provider is checked | N/A | None |

### V7 Session Management

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V7.1.1 | 2 | Idle and absolute session limits are documented and justified | Pass | 1 hour idle, 30 days at most ([0027](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0027-authentication-and-sessions.md), [authentication](../architecture/authentication.md)) |
| V7.1.2 | 2 | Concurrent sessions per account are documented | **Fail** | Not documented; in practice unlimited. A3: #94 |
| V7.1.3 | 2 | Federated session lifetimes | N/A | No federation |
| V7.2.1 | 1 | Session tokens are checked on the server | Pass | Hashed and looked up on every request (`app/auth/sessions.py::load_session`) |
| V7.2.2 | 1 | Session tokens are generated, not static keys | Pass | A new random token per sign-in |
| V7.2.3 | 1 | Reference tokens are unique, CSPRNG, 128+ bits | Pass | 32 bytes from `secrets.token_bytes`; `test_each_sign_in_gets_a_new_unguessable_token` |
| V7.2.4 | 1 | A new token at sign-in; the old one ends | Pass | `test_a_planted_token_never_becomes_a_signed_in_session`, `test_signing_in_again_ends_the_browsers_previous_session` |
| V7.3.1 | 2 | Inactivity timeout | Pass | 1 hour; `test_a_session_ends_after_an_hour_without_requests` |
| V7.3.2 | 2 | Absolute maximum lifetime | Pass | 30 days; `test_activity_keeps_a_session_alive_but_never_past_30_days` |
| V7.4.1 | 1 | Ended sessions cannot be used again | Pass | Signing out deletes the row (`sign_out`); expired rows are deleted when presented |
| V7.4.2 | 1 | Disabling an account ends its sessions | Pass | `test_deactivating_a_person_ends_their_session` |
| V7.4.3 | 2 | Option to end other sessions after a password change | Not built | No password change yet |
| V7.4.4 | 2 | Sign out is visible on every signed-in page | Pass | Header button (frontend #13); `DELETE /api/sessions/current` |
| V7.4.5 | 2 | Administrators can end a person's sessions | Not built | People screen comes after the midterm |
| V7.5.1 | 2 | Re-authentication before changing sign-in details | Not built | No such changes yet (`reauth_at` is ready for S5) |
| V7.5.2 | 2 | Users can see and end their sessions | Not built | Sign out everywhere exists (`DELETE /api/sessions`); a list of sessions does not |
| V7.6.1 | 2 | Sessions between relying parties and identity providers | N/A | No federation |
| V7.6.2 | 2 | Sessions start only by an explicit action | Pass | Only `POST /api/sessions` creates one |

### V8 Authorization

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V8.1.1 | 1 | Function and data access rules are documented | Pass | [authorization](../architecture/authorization.md) |
| V8.1.2 | 2 | Field-level rules are documented | Pass | Request schemas list the writable fields; answers list the readable ones ([schedules](../features/schedules.md)) |
| V8.2.1 | 1 | Functions need explicit permissions | Pass | `authorize()` in every service function (`app/authz/check.py`); `tests/security/test_authorization.py` |
| V8.2.2 | 1 | Data access needs permission for that item (IDOR, BOLA) | Pass | Scopes per record and per list (`scope_filter`); `test_the_list_filter_agrees_with_authorize_for_every_pair`, `tests/security/test_shifts.py` |
| V8.2.3 | 2 | Field access needs permission for that field (BOPLA) | Pass | `extra="forbid"` on requests, fixed answer models; `test_fields_outside_the_rules_cannot_be_set` |
| V8.3.1 | 1 | Authorization is enforced on the server | Pass | The API checks every request; the interface only hides buttons (threat E8) |
| V8.4.1 | 2 | Tenants can never affect each other | Pass | Four tenancy layers ([tenancy](../architecture/tenancy.md)); `tests/security/test_cross_company.py`, `test_org_company_links.py` |

### V11 Cryptography

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V11.1.1 | 2 | Key management policy and lifecycle | **Fail** | Keys are separate and kept out of the database, but creation, rotation, and retirement are not written down. A2: #93 |
| V11.1.2 | 2 | Cryptographic inventory | Pass | Added by this audit: [security controls: cryptography](security-controls.md#cryptography) |
| V11.2.1 | 2 | Validated crypto libraries | Pass | argon2-cffi, Python's `hashlib`, `hmac`, `secrets` (OpenSSL) |
| V11.2.2 | 2 | Crypto agility | Pass | Argon2id settings are stored in each hash and upgraded at sign-in; audit entries store their key ID |
| V11.2.3 | 2 | At least 128 bits of security | Pass | SHA-256, HMAC-SHA256 with keys of 32+ characters, 256-bit tokens |
| V11.3.1 | 1 | No insecure block modes or padding | N/A | No encryption in the application |
| V11.3.2 | 1 | Only approved ciphers | N/A | No encryption in the application |
| V11.3.3 | 2 | Encrypted data is authenticated | N/A | No encryption in the application |
| V11.4.1 | 1 | Only approved hash functions | Pass | SHA-256 and HMAC-SHA256; no MD5 or SHA-1 |
| V11.4.2 | 2 | Passwords use a slow, memory-hard hash | Pass | Argon2id, 64 MiB, 3 passes, 4 lanes (above OWASP's minimum) |
| V11.4.3 | 2 | Integrity hashes are collision resistant | Pass | HMAC-SHA256 for the audit chain and CSRF tokens |
| V11.4.4 | 2 | Keys derived from passwords use stretching | N/A | No keys are derived from passwords |
| V11.5.1 | 2 | Unguessable values come from a CSPRNG with 128+ bits | Pass | `secrets`; IDs (UUIDv7) are never used as secrets |
| V11.6.1 | 2 | Approved key generation and signatures | N/A | No public-key cryptography; the HMAC keys are generated with `secrets` (`.env.example`) |

### V12 Secure Communication

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V12.1.1 | 1 | Only TLS 1.2 and 1.3 | Deployment | No HTTPS deployment yet (open question: hosting) |
| V12.1.2 | 2 | Recommended cipher suites | Deployment | As above |
| V12.1.3 | 2 | mTLS client certificates | N/A | None |
| V12.2.1 | 1 | TLS for everything external | Deployment | As above |
| V12.2.2 | 1 | Publicly trusted certificates | Deployment | As above |
| V12.3.1 | 2 | TLS for every connection, including the database | Deployment | nginx to API and API to MySQL run unencrypted on private Docker networks; decided with hosting |
| V12.3.2 | 2 | TLS clients check certificates | Deployment | As above |
| V12.3.3 | 2 | TLS between internal HTTP services | Deployment | As above |
| V12.3.4 | 2 | Trusted certificates between internal services | Deployment | As above |

### V13 Configuration

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V13.1.1 | 2 | All communication needs are documented | Pass | Browser to nginx to API to MySQL, nothing external ([layers and modules](../architecture/layers-and-modules.md), `docker-compose.yml`) |
| V13.2.1 | 2 | Backend connections are authenticated | Pass | The API signs in to MySQL with its own user and password |
| V13.2.2 | 2 | Backend connections use least privilege | **Fail** | The application's database user can also change the schema and edit the audit log; #43 |
| V13.2.3 | 2 | No default service credentials | Pass | Compose refuses to start without passwords; none are built in |
| V13.2.4 | 2 | Allowlist of outbound destinations | N/A | No outbound requests |
| V13.2.5 | 2 | Server allowlist for outbound loads | N/A | No outbound requests |
| V13.3.1 | 2 | A secrets management solution | Deployment | Secrets come from the environment (`.env` locally); a vault depends on hosting |
| V13.3.2 | 2 | Least privilege for secrets | Pass | CSRF and audit keys are separate (startup refuses them equal), never in the database or repository |
| V13.4.1 | 1 | No source control metadata deployed | Pass | The image copies `app/` and `migrations/` only |
| V13.4.2 | 2 | Debug modes off in production | Pass | Production hides API docs and full error logs (`app/main.py`) |
| V13.4.3 | 2 | No directory listings | Pass | nginx has no autoindex; the API serves no files |
| V13.4.4 | 2 | HTTP TRACE not supported | Pass | No TRACE route (405) |
| V13.4.5 | 2 | Docs and monitoring endpoints only where intended | Pass | `/api/docs` and `/api/openapi.json` outside production only; `/api/health` is intended |

### V14 Data Protection

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V14.1.1 | 2 | Sensitive data is identified and classified | **Fail** | The threat model lists what we protect, but no protection levels. A2: #93 |
| V14.1.2 | 2 | Each protection level has requirements | **Fail** | As above. A2: #93 |
| V14.2.1 | 1 | No sensitive data in URLs | Pass | Session in a cookie, password in the body |
| V14.2.2 | 2 | No sensitive data cached in server components | Pass | `Cache-Control: no-store` on every answer; `tests/security/test_no_store.py` |
| V14.2.3 | 2 | No sensitive data sent to third parties | Pass | No trackers; the CSP allows only our own origin |
| V14.2.4 | 2 | Controls per protection level are implemented | **Fail** | Depends on V14.1.1. A2: #93 |
| V14.3.1 | 1 | Authenticated data is cleared from the client at the end | Pass | The frontend keeps session data in memory only; answers are `no-store` |
| V14.3.2 | 2 | Anti-caching headers | Pass | `no-store` (`app/core/caching.py`) |
| V14.3.3 | 2 | No sensitive data in browser storage | Pass | The frontend writes nothing to browser storage (frontend `js/core/session.js`) |

### V15 Secure Coding and Architecture

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V15.1.1 | 1 | Remediation time frames for vulnerable components | **Fail** | Dependabot and `pip-audit` run, but no time frames are written down. A5: workforce-ops-app/.github#72 |
| V15.1.2 | 2 | Software bill of materials (SBOM) | **Fail** | None kept. A5: workforce-ops-app/.github#72 |
| V15.1.3 | 2 | Resource-heavy functions are documented | **Fail** | Not written down (sign-in hashing, lists). A3: #94 |
| V15.2.1 | 1 | Components within the remediation time frames | Pass | `pip-audit` finds no known vulnerabilities (local CI, 2026-10-12) |
| V15.2.2 | 2 | Defenses for resource-heavy functions | **Fail** | Lists are bounded (31 days, 200 items) but sign-in is not; #50 and #85 |
| V15.2.3 | 2 | Production has only required functionality | Pass | Tests, scripts, and API docs are not in production |
| V15.3.1 | 1 | Answers return only the needed fields | Pass | Fixed answer models; `test_no_answer_contains_a_password_hash_or_token_hash` |
| V15.3.2 | 2 | Outbound calls do not follow redirects | N/A | No outbound calls |
| V15.3.3 | 2 | Mass assignment is prevented | Pass | `extra="forbid"`; `test_fields_outside_the_rules_cannot_be_set` |
| V15.3.4 | 2 | Proxies pass the real client address | N/A | The address is not used yet; rate limits (#50) will need it |
| V15.3.5 | 2 | Types are checked; comparisons are strict | Pass | Pydantic types; `hmac.compare_digest` for tokens |
| V15.3.6 | 2 | No prototype pollution in JavaScript | Frontend | Frontend audit (Phase 4) |
| V15.3.7 | 2 | No HTTP parameter pollution | Pass | FastAPI reads each parameter from one declared place (query, body, or cookie) |

### V16 Security Logging and Error Handling

| ID | L | Requirement (summary) | Result | Where it is checked |
|---|---|---|---|---|
| V16.1.1 | 2 | Log inventory | Pass | Added by this audit: [security controls: logs](security-controls.md#logs) |
| V16.2.1 | 2 | Log entries say when, where, who, and what | **Fail** | Audit entries do; application log lines carry no request ID, person, or source address. A1: #92 |
| V16.2.2 | 2 | UTC timestamps | Pass | Log lines and audit entries use UTC |
| V16.2.3 | 2 | Logs go only where the inventory says | Pass | Standard output and the audit tables |
| V16.2.4 | 2 | Logs use a common format | Pass | One JSON object per line ([0035](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0035-logging-unexpected-errors.md)) |
| V16.2.5 | 2 | Sensitive data is not logged | Pass | `tests/security/test_sign_in.py::test_failed_sign_ins_never_log_the_password`, `tests/security/test_audit_log.py::test_no_entry_can_contain_a_password_token_or_hash` |
| V16.3.1 | 2 | Sign-in attempts are logged | Pass | Success and failure are audited; an unknown email goes to the application log without the email |
| V16.3.2 | 2 | Failed authorization is logged | **Fail** | A 403 or cross-company 404 is answered but not logged. A1: #92 |
| V16.3.3 | 2 | Security events and bypass attempts are logged | **Fail** | Refused forged requests (CSRF, Origin) are not logged. A1: #92 |
| V16.3.4 | 2 | Unexpected errors are logged | Pass | With an `error_id` (`app/core/errors.py`) |
| V16.4.1 | 2 | Log injection is prevented | Pass | The JSON formatter escapes every value |
| V16.4.2 | 2 | Logs are protected and cannot be modified | **Fail** | Changes to the audit log are detectable (signed chain; `tests/security/test_audit_log.py`), but the application's database user can still edit it (#43) and nothing verifies it yet (#58) |
| V16.4.3 | 2 | Logs are sent to a separate system | Deployment | Depends on hosting |
| V16.5.1 | 2 | Generic error messages | Pass | 500 answers say only "An unexpected error occurred." with an `error_id`; `tests/unit/test_errors.py` |
| V16.5.2 | 2 | Safe operation when a dependency fails | Pass | A database failure gives a generic 500; connections are checked before reuse |
| V16.5.3 | 2 | Failures are closed, not open | Pass | An action whose audit entry fails is not saved; a query without a company is refused |

## Chapters not in scope

| Chapter | Why |
|---|---|
| V5 File Handling | no uploads yet; task-note photos and logos (next tier) bring it in |
| V9 Self-contained Tokens | sessions use random reference tokens, not JWTs |
| V10 OAuth and OIDC | no external sign-in |
| V17 WebRTC | not used |

## Next

- When batch shift changes (SC2, #62) merge: check V2.2.3, V2.3.2 to V2.3.4, V8.2.1, V8.2.2, V8.4.1, and V16.3.2 for `POST /api/shifts/batch`, and add the result here.
- Rows marked **Not built** are checked by the audits planned for the second half, as their features arrive.
- Rows marked **Deployment** are checked once hosting is decided.
