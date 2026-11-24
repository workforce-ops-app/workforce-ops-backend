# Final audit: the outside attacker (profile P1)

**In short:** the whole application attacked from outside with no account, as attacker profile P1 of the [threat model](threat-model.md): someone on the internet who wants to take over accounts, read data, or disrupt the service. Both teammates run it together on a local copy with the standard tools ([0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md)). With the internal audit, its findings give research question RQ2 its comparison of outside and inside threats.

- **Status:** prepared, not run yet. The checklists below are ready; every Result column is empty until the audit runs
- **Related:** #119 (this audit), the tools in workforce-ops-app/workforce-ops-research `audit/`, [threat model](threat-model.md), [security controls](security-controls.md), [findings log](findings-log.md), [midterm audit](audit-midterm.md)

## Scope

- **What:** every endpoint and page an outsider can reach, on the combined code of every open pull request (`review/integration` of the backend and the frontend). Record the two commits here when the audit starts: backend `________`, frontend `________`.
- **Who attacks:** both teammates together, on the whole application, not split by who built what (0030).
- **Where:** a local copy only, started as the tools' README says (demo data from `scripts/seed_demo.py`, development settings so `/api/openapi.json` exists). Never a hosted copy, never anyone else's system.
- **Not covered:** the signed-in attacker profiles (P2 employee, P3 manager or administrator), the platform staff profile (P4), and hosting (TLS, HSTS), which stays deferred as in the midterm audit.

## Method

1. Start the local copy and note both commits above.
2. Run the tools from the research repository's `audit/` folder, each writing to its own folder in `results/audit/` with `run.json` (times and commits):
   - `check_signed_out.py`: every operation once with no session (the endpoint table below);
   - `run_zap.sh baseline`, then `run_zap.sh api` twice: as an outsider meets it, and with the Origin header (`ORIGIN=...`), so the attacks also reach the checks behind the forged-request check;
   - `run_sqlmap.sh` on the public endpoints;
   - Burp Suite Community by hand, for each threat row below.
3. For every row, write the result and where the evidence is (a run folder, a Burp note, a screenshot).
4. Each finding gets an issue from the security-finding template (a private advisory first if it reaches another company's data or acts without permission), a row in the Findings table below, and, once fixed, a row in the [findings log](findings-log.md) with its tool, fix, regression test, threat ID, and attacker profile.

**Results:** **Pass** (the protection held, and the evidence shows it); **Finding** (it did not: file it); **Expected** (an alert or odd answer that is the documented behavior; say which document); **False alarm** (a tool alert that is wrong; say why).

## Threats from outside

One row for each P1 threat in the [threat model](threat-model.md). "What to try" is the starting point, not the limit: follow anything that looks wrong.

| Threat | What to try | Tools | Result | Evidence |
|---|---|---|---|---|
| S1 Password guessing and stuffing | 25 wrong passwords on one demo account: the 5th locks it, and from then on even the right password gets the same answer as a wrong one; the 21st request from one address in a minute gets 429 with `Retry-After`. Common passwords on sign-up and set-password must be refused | Burp Intruder, ZAP | | |
| S2 Stealing a session cookie | Inspect the cookie after sign-in: `__Host-session`, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`. Try reading it from the browser console (`document.cookie`). Look for the token in any answer body, URL, or log | browser, Burp | | |
| S3 Session fixation | Set a made-up `__Host-session` cookie, sign in, and check the cookie changes; set an old valid token from another browser and check sign-in replaces it | Burp | | |
| S4 Forged requests (CSRF) | From a page on another origin (a local file or another port), send POSTs with the victim's cookie: no Origin, a wrong Origin, a right Origin without the `X-CSRF-Token`, a token from another session. All must be refused | Burp, a local HTML file | | |
| S5 Setup and reset links | A redeemed link used again, an expired one, one with a changed character, one from another company; the token never in a server log or `Referer` | Burp, browser | | |
| S6 Forged `X-Forwarded-For` | Send sign-in attempts with a made-up `X-Forwarded-For` straight to the API port and through nginx: the limit and the security events must count the real address | Burp | | |
| S7 Sign-up around the sign-in limits | Alternate sign-in and sign-up requests from one address: together they count toward the 20 a minute; the 6th sign-up in an hour gets 429. A taken email gets the same answer as on the people screen | Burp | | |
| T1 SQL injection | sqlmap on the public endpoints; ZAP's injection rules on the API scan; hand-written quotes and comments in every field Burp sees | sqlmap, ZAP, Burp | | |
| T3 Other companies' records by ID | Unreachable without an account: confirm every ID route answers 401 signed out (endpoint table); IDs are UUIDv7, so look for any sequential or guessable ID in an answer | check script, Burp | | |
| T6 Numbers past their limits | Very large and negative numbers, `1e309`, and 2^53 + 1 in every numeric field the public endpoints accept (and in query strings such as `limit`): 422, never 500 | Burp, ZAP | | |
| T7 Stored XSS through the security page | Send XSS inputs (research `audit/xss-inputs.txt`) in a sign-in email and a URL path so detection records them; then, signed in as an owner, open the security page: the excerpt must show as text | Burp, browser | | |
| R3 Forged log lines | Send line breaks (`%0d%0a`, `\n`) and JSON fragments in sign-in fields and paths; read the API's log: every entry stays one JSON line with the input escaped inside a field | Burp, `docker compose logs api` | | |
| R4 Evading detection | Send the same injection in forms detection might miss (double URL encoding, mixed case, comments inside keywords) and note which appear on the security page. This only measures detection; the protection is T1 and the course-topic rows | Burp, security page | | |
| I1 Reading another company's records | Without an account, every company data route answers 401 (endpoint table). The cross-company tests cover signed-in reads | check script | | |
| I3 Finding out what exists | Compare answers, timing, and headers for an unknown email and a known one with a wrong password at sign-in; a taken email at sign-up in any letter case; a made-up and a real ID on any route (401 either way when signed out) | Burp (Comparer, timing column) | | |
| I4 Errors that reveal internals | Malformed JSON, wrong content types, huge bodies, unknown fields, wrong HTTP methods on every public endpoint: one problem format, no stack trace, SQL, or file path | ZAP, Burp | | |
| I5 Leaking hashes, tokens, or secrets | Search every answer, header, and page (including `/api/openapi.json` and the JavaScript files) for hashes, tokens, keys, and internal addresses | ZAP, Burp search | | |
| I6 Data left in the browser cache | Sign in, open pages, sign out, then press Back and look in the browser's cache: answers say `Cache-Control: no-store`; nothing stays in `localStorage` or `sessionStorage` | browser developer tools | | |
| I7 Format strings | `{0.__class__}`, `%s%s%s%n`, and `${7*7}` in every public text field; the answer and the log show them as plain text | Burp | | |
| D1 Flooding sign-in, locking users out | A burst of requests from one address (429 after 20 a minute); lock a demo account on purpose and check the lock ends (never longer than 1 hour) | Burp Intruder | | |
| D2 Expensive requests | Bodies of several megabytes, very long strings in every field, thousands of JSON keys, deep nesting: refused quickly with a 4xx answer, and the API stays responsive | Burp, ZAP | | |
| D4 Slow patterns (ReDoS) | Long repeated input such as `aaaa...!` (10,000 characters) in fields and paths while timing other requests: answers stay quick, since inspection runs after the answer | Burp | | |
| D5 Flooding security events | Many attack-looking requests from one address in a minute: at most 20 events, then one summary row; real requests keep working | Burp Intruder, security page | | |
| D6 Mass fake sign-ups | Sign-ups in a loop from one address (429 from the 6th in an hour); check that nothing half-made is left after a refused one | Burp Intruder | | |
| E10 Memory corruption in compiled parts | Covered by the dependency checks and checksec (#107) rather than by attacking; confirm the image versions match the ones those checks ran on | `pip-audit`, checksec | | |

## Endpoints

### Public (no account needed)

| Endpoint | What to try | Result | Evidence |
|---|---|---|---|
| `GET /api/health` | Only `{"status": "ok"}`: no version, host name, or database details | | |
| `POST /api/sessions` (sign in) | S1, S3, S6, T1, I3, I4, D1 above | | |
| `POST /api/sign-up` | S7, T1, T6, I3, I4, D2, D6 above; also extra fields (`company_id`, `role`, `password_hash`): 422 | | |
| `POST /api/password-links/redeem` | S5, T1, I4 above | | |
| The pages (`/pages/*.html`) | ZAP baseline: the security headers on every page (CSP, `nosniff`, `Referrer-Policy`, `frame-ancestors 'none'`); no comments or files that should not be served | | |

### Every other operation must answer 401 with no session

Filled from `check_signed_out.py`: the expected answer is 401 for every row. A row marked "look" by the script is judged here. The list is the API's OpenAPI document on `review/integration` at `1879557` (2026-11-19); re-run the script on the audited commit and add any new operation.

| Method | Path | Expected | Result |
|---|---|---|---|
| GET | `/api/announcements` | 401 |  |
| POST | `/api/announcements` | 401 |  |
| GET | `/api/announcements/managed` | 401 |  |
| GET | `/api/announcements/{announcement_id}` | 401 |  |
| PATCH | `/api/announcements/{announcement_id}` | 401 |  |
| POST | `/api/announcements/{announcement_id}/archive` | 401 |  |
| POST | `/api/announcements/{announcement_id}/read` | 401 |  |
| GET | `/api/announcements/{announcement_id}/reads` | 401 |  |
| GET | `/api/approval-requests` | 401 |  |
| GET | `/api/approval-requests/{request_id}` | 401 |  |
| POST | `/api/approval-requests/{request_id}/approve` | 401 |  |
| POST | `/api/approval-requests/{request_id}/cancel` | 401 |  |
| POST | `/api/approval-requests/{request_id}/deny` | 401 |  |
| POST | `/api/audit/verify` | 401 |  |
| GET | `/api/departments` | 401 |  |
| POST | `/api/departments` | 401 |  |
| PATCH | `/api/departments/{department_id}` | 401 |  |
| POST | `/api/departments/{department_id}/archive` | 401 |  |
| PUT | `/api/me/password` | 401 |  |
| GET | `/api/owners` | 401 |  |
| POST | `/api/owners` | 401 |  |
| POST | `/api/owners/{user_id}/remove` | 401 |  |
| GET | `/api/permissions` | 401 |  |
| GET | `/api/reporting-lines` | 401 |  |
| POST | `/api/reporting-lines` | 401 |  |
| POST | `/api/reporting-lines/{line_id}/end` | 401 |  |
| GET | `/api/role-assignments` | 401 |  |
| POST | `/api/role-assignments` | 401 |  |
| DELETE | `/api/role-assignments/{assignment_id}` | 401 |  |
| GET | `/api/roles` | 401 |  |
| POST | `/api/roles` | 401 |  |
| GET | `/api/roles/{role_id}` | 401 |  |
| PATCH | `/api/roles/{role_id}` | 401 |  |
| POST | `/api/roles/{role_id}/archive` | 401 |  |
| GET | `/api/security-events` | 401 |  |
| GET | `/api/security-events/summary` | 401 |  |
| DELETE | `/api/sessions` | 401 |  |
| GET | `/api/sessions/current` | 401 |  |
| DELETE | `/api/sessions/current` | 401 |  |
| POST | `/api/sessions/current/reauth` | 401 |  |
| GET | `/api/shifts` | 401 |  |
| POST | `/api/shifts` | 401 |  |
| POST | `/api/shifts/batch` | 401 |  |
| GET | `/api/shifts/{shift_id}` | 401 |  |
| PATCH | `/api/shifts/{shift_id}` | 401 |  |
| POST | `/api/shifts/{shift_id}/assign` | 401 |  |
| POST | `/api/shifts/{shift_id}/cancel` | 401 |  |
| GET | `/api/teams` | 401 |  |
| POST | `/api/teams` | 401 |  |
| PATCH | `/api/teams/{team_id}` | 401 |  |
| POST | `/api/teams/{team_id}/archive` | 401 |  |
| POST | `/api/teams/{team_id}/members` | 401 |  |
| DELETE | `/api/teams/{team_id}/members/{user_id}` | 401 |  |
| GET | `/api/time-off-requests` | 401 |  |
| POST | `/api/time-off-requests` | 401 |  |
| GET | `/api/time-off-requests/waiting` | 401 |  |
| GET | `/api/time-off-requests/{request_id}` | 401 |  |
| POST | `/api/time-off-requests/{request_id}/approve` | 401 |  |
| POST | `/api/time-off-requests/{request_id}/cancel` | 401 |  |
| POST | `/api/time-off-requests/{request_id}/deny` | 401 |  |
| GET | `/api/users` | 401 |  |
| POST | `/api/users` | 401 |  |
| GET | `/api/users/{user_id}` | 401 |  |
| PATCH | `/api/users/{user_id}` | 401 |  |
| POST | `/api/users/{user_id}/deactivate` | 401 |  |
| POST | `/api/users/{user_id}/reactivate` | 401 |  |
| POST | `/api/users/{user_id}/reset-link` | 401 |  |
| DELETE | `/api/users/{user_id}/sessions` | 401 |  |
| POST | `/api/users/{user_id}/setup-link` | 401 |  |
| POST | `/api/users/{user_id}/unlock` | 401 |  |

## Findings

One row per finding, filled during the audit. Severity as in the midterm audit: high (an attacker gets in, reads other data, or stops the service), medium, low.

| Finding | Threat | Tool | Severity | Issue | Fixed by |
|---|---|---|---|---|---|

## Summary for the report

Filled when the audit ends: how many rows passed, how many findings by severity, and which threats they fall under. The report compares these outside findings (P1) with the internal audit's (P2 and P3) for RQ2 ([report plan](https://github.com/workforce-ops-app/.github/blob/main/docs/project/report-plan.md)).
