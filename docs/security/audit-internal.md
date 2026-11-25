# Final audit: the inside attacker (profiles P2 and P3)

**In short:** the whole application attacked from inside, with real accounts, as attacker profiles P2 (a malicious employee) and P3 (a compromised manager or administrator) of the [threat model](threat-model.md). Both teammates run it together on a local copy ([0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md)). Its findings, set against the [outside audit](audit-external.md)'s, answer research question RQ2's comparison of inside and outside threats.

- **Status:** prepared, not run yet. The checklists below are ready; every Result column stays empty until the audit runs
- **Related:** #118 (this audit), the tools in workforce-ops-app/workforce-ops-research `audit/`, [threat model](threat-model.md), [authorization](../architecture/authorization.md), [security controls](security-controls.md), [findings log](findings-log.md), [outside audit](audit-external.md)

## Scope

- **What:** every endpoint and page a signed-in person can reach, on the combined code of every open pull request (`review/integration` of the backend and the frontend). Record the two commits here when the audit starts: backend `________`, frontend `________`.
- **Who attacks:** both teammates together, on the whole application, not split by who built what (0030).
- **Where:** a local copy only, with the demo data (`scripts/seed_demo.py`, one `DEMO_PASSWORD` for every account) and development settings, as the research repository's `audit/README.md` says. Never a hosted copy.
- **Not covered:** the outsider (P1, in the [outside audit](audit-external.md)), platform staff with server or database access (P4), and hosting. An owner's powers inside their own company are by design; the owner rows below only check what even an owner must not do.

## The accounts

The demo data gives each profile a real person in Northwind Cafe (`@example.com`), with Summit Outfitters (`@example.org`) as the other company. The reporting lines (`REPORTING_LINES` in the seed script) are: Olivia over Marcus; Marcus over Sofia, Ana, and Priya; Ana over Felix and Ben; Felix over Ben and Cara; Priya over Diego. Ella has no manager.

| Profile | Who | Role and scope | Use for |
|---|---|---|---|
| P2 | `ben.okafor@example.com` | Employee, Kitchen; Weekend Crew and Morning Prep | the main malicious employee |
| P2 | `ella.novak@example.com` | Employee, Front of House; no team, no manager | an employee nobody is above |
| P3 | `felix.grant@example.com` | Manager of the Weekend Crew team only | a manager reaching past their team |
| P3 | `ana.diaz@example.com` | Manager, Kitchen | a department manager reaching past their department |
| P3 | `priya.shah@example.com` | Manager, Front of House | a peer of Ana, in another department |
| P3 | `sofia.reyes@example.com` | Administrator, below Marcus | an administrator acting on a superior |
| P3 | `marcus.lee@example.com` | Administrator, below Olivia | the strongest non-owner |
| (owner) | `olivia.hart@example.com` | Owner | only for the E6 owner rows |
| other company | `kai.tanaka@example.org` and `henry.adams@example.org` | Employee and Administrator of Summit Outfitters | IDs and data that must stay invisible (T3, I1) |

## Method

1. Start the local copy, seed it, and note both commits above.
2. **Collect IDs as the stronger account.** Sign in as Marcus (and Henry for the other company), browse every screen with Burp recording, and note the IDs of people, shifts, requests, roles, assignments, lines, announcements, departments, and teams. These are the IDs the weaker accounts try.
3. **Replay as the weaker account.** For every request Burp recorded, send it again with the weaker account's session cookie and its `X-CSRF-Token` (Repeater by hand, or the Autorize extension, which runs in Burp Community). Each answer is judged against the endpoint table below: the action is refused (403, or 404 where the record must stay invisible), or it is allowed and the permission table says it should be.
4. **Change what the interface would never send:** extra fields (`company_id`, `status`, `employee_id`, `requested_by`, `approver_id`), another person's ID in a body, a scope that covers more than yours, the same request twice at once.
5. Scan signed in as Ben, so the input checks are reached past the session check. `run_zap.sh` has no signed-in mode yet (it scans as an outsider); until it has one, use Burp's scanner-free tools (Intruder with the XSS and injection lists) on Ben's requests.
6. For every row, write the result and where the evidence is (a Burp note, a run folder, a screenshot, an audit entry's ID).
7. Each finding gets an issue from the security-finding template (a private advisory first if it reaches another company's data or acts without permission), a row in the Findings table below, and, once fixed, a row in the [findings log](findings-log.md) with its tool, fix, regression test, threat ID, and attacker profile.

**Results:** **Pass** (the protection held, and the evidence shows it); **Finding** (it did not: file it); **Expected** (an odd answer that is the documented behavior; say which document); **False alarm** (a tool alert that is wrong; say why).

## P2: the malicious employee

One row for each threat the [threat model](threat-model.md) lists for P2. "What to try" is the starting point, not the limit.

| Threat | What to try | Tools | Result | Evidence |
|---|---|---|---|---|
| S2 Stealing a session cookie | As Ben, put a stored XSS input (T5) where Ana will see it, and check nothing runs and `document.cookie` never shows the session; on a shared computer, sign out and check Back shows nothing (I6) | browser, Burp | | |
| S5 Setup and reset links | Ben asks for nothing, so try the endpoints that make links (`/users/{id}/setup-link`, `/reset-link`) for Cara: 403. If a link reaches Ben (for example forwarded by mistake), it works once only and signs out other sessions | Burp | | |
| S6 Forged `X-Forwarded-For` | As Ben, send attack-looking requests with a made-up `X-Forwarded-For` to the API port and through nginx: the security page shows the real address | Burp, security page | | |
| T1 SQL injection | Quotes and comments in every text field and query parameter Ben can send (time-off reason, offer answers, list filters, cursors) | Burp, ZAP | | |
| T2 Fields the user must not set | Ben's time-off request with `employee_id` set to Cara, `status: "approved"`, `company_id`, `approval_request_id`; a password change with extra fields; an offer answer for another coworker: 422 or the field ignored, never applied | Burp | | |
| T3 Other companies' records by ID | Every Summit ID collected in step 2 in every route Ben can call: 404, never 403 (which would confirm it exists) | Burp | | |
| T5 Stored XSS | `audit/xss-inputs.txt` in every text Ben can write that others read: his time-off reason (seen by Ana and Felix), offer notes, his own display name if he can change it; then open those screens as Ana | Burp, browser | | |
| T6 Numbers past their limits | Very large and negative numbers, `1e309`, and 2^53 + 1 in every numeric field and query parameter Ben can send (`limit`, days, counts): 422, never 500 | Burp | | |
| T7 Stored XSS through the security page | Ben sends XSS inputs that detection records; then Marcus opens the security page: the excerpt is shown as text | Burp, browser | | |
| R1 Denying an action | Ben asks for time off, cancels it, answers an offer; each appears in the audit log with Ben as the actor (read it as Marcus) | browser, audit page or API | | |
| R3 Forged log lines | Line breaks (`%0d%0a`, `\n`) and JSON fragments in Ben's text fields; every log entry stays one JSON line | Burp, `docker compose logs api` | | |
| R4 Evading detection | The same injection in several forms (double encoding, mixed case, comments inside keywords); note which reach the security page. Measures detection only | Burp, security page | | |
| I1 Another company's data | As Ben, every list endpoint: nothing from Summit, even with filters or cursors made from Summit IDs | Burp | | |
| I2 Own company, outside scope | Ben lists people (`/api/users`: 403, he lacks `user.view`; by ID he sees only himself), Front of House shifts and time off, Cara's time-off request by ID, approval requests for others; the schedule shows the Kitchen only, with role names but no permissions | Burp, browser | | |
| I3 Finding out what exists | Compare answers for a real and a made-up ID of a coworker's request, shift, and person: the same status and body shape | Burp Comparer | | |
| I6 Data left in the browser cache | Sign out, press Back, look in the cache and storage: nothing personal remains | browser developer tools | | |
| I7 Format strings | `{0.__class__}`, `%s%s%s%n`, `${7*7}` in Ben's text fields; shown and logged as plain text | Burp | | |
| I9 Announcements meant for others | Ben opens an announcement for Front of House or for a team he is not in, by ID (404), and its read list (404); his list holds only his company, department, and teams | Burp | | |
| D2 Expensive requests | Huge bodies, very long strings, `limit=100000`, deep JSON in Ben's requests: refused quickly, the API stays responsive | Burp | | |
| D5 Flooding security events | Many attack-looking requests from Ben's session in a minute: at most 20 events, then one summary row | Burp Intruder, security page | | |
| E1 Giving yourself more access | Ben posts a role assignment for himself (`/api/role-assignments`), a reporting line with himself as manager, an owner request for himself: all refused | Burp | | |
| E5 Approving your own request | Ben approves or denies his own time-off request, through `/time-off-requests/{id}/approve` and through `/approval-requests/{id}/approve`; also when someone added a role that would let him review: refused. Ella (nobody above her) asks for time off: it goes to the owners, and she cannot name or become her own reviewer | Burp | | |
| E8 Hidden buttons | Every write Marcus's screens send (step 2), replayed as Ben: refused unless the permission table allows it | Burp (Autorize or Repeater) | | |

## P3: the compromised manager or administrator

One row for each threat the [threat model](threat-model.md) lists for P3.

| Threat | What to try | Tools | Result | Evidence |
|---|---|---|---|---|
| T3 Other companies' records by ID | As Marcus, every Summit ID in every route, including writes (edit a Summit shift, end a Summit line, approve a Summit request): 404 | Burp | | |
| T4 Changing audit entries | Look for any endpoint that edits or removes audit entries (none should exist); `/api/audit/verify` after the audit says the chain is whole | Burp, audit verify | | |
| T5 Stored XSS | XSS inputs in everything a manager or administrator writes that others read: announcements (only `**bold**` becomes markup), department and team names, role names, shift notes, denial comments; open each as Ben | Burp, browser | | |
| R1 Denying an action | Marcus changes a role, Ana approves time off, Felix edits a shift; each has an audit entry naming them; sensitive ones asked for the password again | browser, audit API | | |
| R2 Covering tracks | Marcus deactivates a person, archives a role, ends a line: nothing removes or edits the earlier audit entries; the chain still verifies | audit API | | |
| I1 Another company's data | As Marcus and Ana, every list with filters, cursors, and IDs from Summit: nothing from Summit | Burp | | |
| I2 Own company, outside scope | Felix lists shifts and time off outside the Weekend Crew; Ana reads Front of House shifts, people, and time-off reasons; Priya reads Kitchen requests; a manager reads the security page or the audit log (refused without `security.view`, `audit.view`) | Burp | | |
| I3 Finding out what exists | As Ana, a real and a made-up ID of a Front of House person or request: the same answer; a taken email when Marcus creates a person, in any letter case | Burp Comparer | | |
| I9 Announcements | Felix reads the read list of an announcement for the whole Kitchen; Ana reads one for Front of House: 404 | Burp | | |
| D3 Destroying data from inside | As Marcus, look for any delete of people, shifts, requests, or audit entries (records are deactivated or archived only); archive a department with active teams (refused) | Burp | | |
| E1 Giving yourself more access | Ana gives herself the Administrator role or a wider scope, adds a line with herself above Priya, edits her own role's permissions: refused | Burp | | |
| E2 Granting what you do not hold | Ana creates a role with `user.manage` and assigns it (she lacks it); Marcus gives Sofia the Administrator role at his own level: it waits for Olivia's approval, and Olivia sees it | Burp, approvals screen | | |
| E3 Acting on a peer or a superior | Sofia (below Marcus) resets Marcus's password link, deactivates him, removes his roles, or ends his sessions: refused. Ana does the same to Priya (a peer) and to Diego (Priya's): refused | Burp | | |
| E4 Rearranging reporting lines | Sofia adds a line putting herself above Marcus (a loop), or above Ana; Ana ends the line between Priya and Diego; every attempt without the password re-entered: refused | Burp | | |
| E5 Approving your own request | Ana asks for time off and approves it herself (both endpoints); Marcus approves an approval request he opened | Burp | | |
| E6 Taking over a company | As Marcus: add himself or Sofia as an owner, remove Olivia. As Olivia, with a second owner added: removing the other owner follows 0032 (either may remove the other, password re-entered); the last owner can never be removed | Burp | | |
| E7 Weakening security settings | Marcus sets the password minimum, lockout, or session limits below the platform's limits, or a department minimum below the company's: 422 | Burp | | |
| E9 Changing a role held by peers or superiors | Sofia edits or archives the Administrator role (Marcus holds it); Marcus edits the Owner role; Ana edits the Manager role (Priya holds it): refused | Burp | | |
| E11 Announcements outside your scope | Felix posts to the whole Kitchen or the company; Ana posts to Front of House; check `/api/announcements/audiences` offers only what each may post to | Burp | | |
| Concurrency | Two of Marcus's sessions send the same approval, role change, or owner change at the same moment (Burp's "send group in parallel"); one wins, nothing is applied twice, no 500 | Burp Repeater groups | | |

## Endpoints by account

For every operation, the expected answer for each weaker account, from the [authorization](../architecture/authorization.md) starting roles and the feature pages. "Own" means only the account's own records; "scope" means only inside its department or team (and below it in the reporting chain for people); "refused" is 403, or 404 for a record the account must not know about. The list is the API's OpenAPI document on the end of the open pull requests (#196, #160, #181) on 2026-11-25; re-run `check_signed_out.py` on the audited commit and add any new operation.

| Operations | Ben (employee) | Felix (team manager) | Ana (department manager) | Sofia (administrator below Marcus) | Result |
|---|---|---|---|---|---|
| `GET /api/sessions/current`, `DELETE /api/sessions/current`, `DELETE /api/sessions`, `POST /api/sessions/current/reauth`, `PUT /api/me/password` | own | own | own | own | |
| `GET /api/users`, `GET /api/users/{id}` | list refused (403); by ID only his own account | scope | scope | company | |
| `POST /api/users`, `PATCH /api/users/{id}`, `.../deactivate`, `.../reactivate`, `.../unlock`, `.../sessions` (DELETE), `.../setup-link`, `.../reset-link` | refused | refused | refused | people below her only, password re-entered where the docs say | |
| `GET /api/departments`, `GET /api/departments/mine`, `GET /api/teams` | per the org docs | per the org docs | per the org docs | company | |
| `POST`/`PATCH` departments and teams, `.../archive`, `POST /api/teams/{id}/members`, `DELETE /api/teams/{id}/members/{user}` | refused | refused | refused | allowed (`org.manage`) | |
| `GET /api/departments/{id}/settings`, `PUT /api/departments/{id}/settings/{key}` | refused | refused | own department only, confirmed by all its managers | allowed within the company's limits | |
| `GET /api/roles`, `GET /api/roles/{id}`, `GET /api/permissions` | refused | refused | refused | allowed | |
| `POST /api/roles`, `PATCH /api/roles/{id}`, `.../archive` | refused | refused | refused | only roles she is above every holder of; never Owner | |
| `GET`/`POST /api/role-assignments`, `DELETE /api/role-assignments/{id}` | refused | refused | refused | people below her; same level waits for approval | |
| `GET`/`POST /api/reporting-lines`, `.../end` | refused | refused | refused | above both people, password re-entered | |
| `GET`/`POST /api/owners`, `.../remove` | refused | refused | refused | refused (owners only) | |
| `GET /api/approval-requests`, `GET /api/approval-requests/{id}`, `.../approve`, `.../deny`, `.../cancel` | only requests he made or that are about him; never approve own | as reviewer of what waits for him | as reviewer | as reviewer; never own | |
| `GET /api/shifts`, `GET /api/shifts/{id}` | own department (and own shifts) | scope | scope | company | |
| `POST /api/shifts`, `.../batch`, `PATCH /api/shifts/{id}`, `.../assign`, `.../cancel` | refused | team only | department only; never onto someone's approved time off | company | |
| `GET`/`POST /api/time-off-requests`, `GET .../{id}`, `.../cancel` | own; coworkers' requests show no reason | own, and scope to review | own, and scope to review | own, and company | |
| `GET .../waiting`, `.../approve`, `.../deny`, `.../send-up` | refused (send-up: own request only) | what waits for him | what waits for her | what waits for her | |
| `GET .../offerable`, `PUT`/`DELETE .../offers/{shift_id}` | his own shifts, for coworkers' requests in his department | the same | the same | the same | |
| `GET /api/announcements`, `GET /api/announcements/{id}`, `.../read` | his audiences only | his audiences only | her audiences only | company | |
| `POST`/`PATCH /api/announcements`, `.../archive`, `GET .../managed`, `GET .../audiences`, `GET .../reads` | refused | his team only | her department only | company | |
| `GET /api/security-events`, `.../summary`, `POST /api/audit/verify` | refused | refused | refused | allowed | |

## Findings

One row per finding, filled during the audit. Severity as in the midterm audit: high (an attacker gets in, reads other data, or stops the service), medium, low.

| Finding | Profile | Threat | Tool | Severity | Issue | Fixed by |
|---|---|---|---|---|---|---|

## Summary for the report

Filled when the audit ends, separately for P2 and P3: how many rows passed, how many findings by severity, and which threats they fall under. The report compares these inside findings with the outside audit's (P1) for RQ2 ([report plan](https://github.com/workforce-ops-app/.github/blob/main/docs/project/report-plan.md)), and the requests the tools sent become part of the detection study's field set (research #8).
