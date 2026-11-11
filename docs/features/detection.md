# Detection and the security page

- **Status:** design (next tier)
- **Related:** design workforce-ops-app/workforce-ops-backend#115, detection workforce-ops-app/workforce-ops-backend#116, security page workforce-ops-app/workforce-ops-frontend#61, tracker workforce-ops-app/.github#91; refused requests workforce-ops-app/workforce-ops-backend#92; method [decision 0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md); results go to the [research repository](https://github.com/workforce-ops-app/workforce-ops-research)

## In short
The API looks at the text people send it and notes anything that looks like an attack, such as SQL injection or a script tag, using regular expressions. It **only records what it saw; it never blocks a request**, because the real protection is how the application is built (bound parameters, safe rendering, permission checks). Owners and administrators see their company's records on a **security page**. The same detector is measured offline on public attack collections and tricky harmless text, which answers research question RQ1: what kinds of attack can pattern matching detect reliably?

## Who can use it

| Role | Can | Permission | Scope |
|---|---|---|---|
| Owner, Administrator | see the security page: their company's security events and counts per type | `security.view` | company |
| Manager, Employee | nothing; they never see security events, including their own | | |
| Platform staff | events from people who were not signed in (stretch: a cross-company view) | | platform |

`security.view` is a company-kind permission, so it needs a company-wide role assignment. The Owner and Administrator starting roles grant it; Manager and Employee do not ([authorization](../architecture/authorization.md#starting-roles)).

## How it works

```mermaid
sequenceDiagram
    participant C as Client
    participant D as Detection layer
    participant A as API endpoint
    participant W as Worker thread
    participant S as security_events
    C->>D: request
    D->>D: keep a copy of the text values (capped)
    D->>A: request, unchanged
    A-->>C: answer, unchanged
    D->>W: after the answer is sent: inspect the copy
    W->>W: normalize, match patterns
    W->>S: one row per match (rate capped)
```

1. A request arrives. The detection layer keeps a copy of the text the client sent: query string values, path values, and the strings inside a JSON body, each with the name of the field it came from (for example `body.note`). Passwords, tokens, and other secrets are **left out while the copy is made**, so they never reach the worker or the database ([what is collected](#what-is-collected-and-what-never-is)).
2. The request goes on to the endpoint **unchanged**. The answer goes back **unchanged**: a request that contains an attack string gets exactly the answer it would get without detection.
3. **After the answer is sent**, the copy goes into a queue with a fixed size, and a worker thread inspects it, so detection never makes a request slower for the person who sent it. If the queue is full, the copy is dropped and only counted (DE11).
4. Each value is **normalized** (decoded and simplified, see below) and checked against the patterns for each attack type.
5. Each match becomes one new row, with the attack type, the pattern that matched, the field, and a short excerpt. If the request carried a valid session, the row goes into the company's `security_events` and names the person. Otherwise it goes into `platform_security_events`, which has no company and no person (DE9).
6. Owners and administrators open the security page to see their company's events, newest first, with counts per type.

---
## Details

### Attack types

The types agreed at the design review (#17, topic 7), plus format strings from the course topics ([threat model](../security/threat-model.md), I7):

| Type | Code | Typical sign | Course topic |
|---|---|---|---|
| SQL injection | `sql_injection` | quote followed by SQL keywords, `UNION SELECT`, `OR 1=1`, comment markers, stacked queries | SQL injection |
| Cross-site scripting | `xss` | `<script`, event handler attributes (`onerror=`), `javascript:` URLs, `<svg`/`<img` with handlers | cross-site scripting |
| Path traversal | `path_traversal` | `../` and its encoded forms, absolute system paths such as `/etc/passwd` | secure coding |
| Command injection | `command_injection` | shell separators (`;`, `&&`, `\|`, backticks, `$(`) followed by a command name | code injection |
| Format string and template injection | `format_string` | `{0.__class__}`, `%n`, `%x` runs, `{{ ... }}`, `${...}` | format string vulnerabilities |

Each pattern has a stable ID (for example `SQLI-03`) so events, tests, and the study's results can refer to it.

### Rules

| ID | Rule | Why |
|---|---|---|
| DE1 | Detection **never blocks, changes, or delays** a request or its answer | log only (0030); a false alarm must never stop real work |
| DE2 | Inspection runs **after the answer is sent**, in a worker thread | no added waiting time for the person who sent the request |
| DE3 | **Secrets never enter the copy:** no headers are collected (so no cookies, CSRF header, or `Authorization` header), credential routes are skipped entirely, and fields with secret-like names are left out at any depth; the filtering happens while the copy is made, in the request, before anything is queued ([what is collected](#what-is-collected-and-what-never-is)) | detection must not become a place where secrets are kept (threat I8) |
| DE4 | Each value is cut to its first **2,000 characters**, a request contributes at most **200 values** and at most **100,000 characters** in total; bodies are already size-limited (#94) | bounds the work and memory an attacker can cause (threat D4) |
| DE5 | Patterns must not backtrack badly: no nested repetition such as `(a+)+`; every pattern passes a timing test on crafted worst-case input before it merges | a slow pattern lets one request freeze a worker (ReDoS, threat D4) |
| DE6 | At most **20 events per minute** from one source (session, or address when not signed in). Beyond that, the worker only counts in memory; when the minute ends it **inserts** one summary row with the final count. Rows are never updated ([rate cap](#rate-cap-and-queue)) | an attacker must not be able to fill the table or bury real events (threat D5), and insert-only rows keep the table a plain record |
| DE7 | The stored excerpt is at most **200 characters** around the match, stored as plain text and always shown with `textContent` | the excerpt is attacker text; showing it must not run it (threat T7) |
| DE8 | The client address comes from nginx's header only when the request came through nginx, as for log lines (#92) | an attacker must not be able to blame another address (threat S6) |
| DE9 | An event belongs to a company **only when the request carried a valid session**, and the company is the session's, as for every other table. Nothing in the request itself (an email typed into the sign-in form, an ID in the URL) can place an event in a company. Events without a valid session, including every sign-in attempt, go to the separate `platform_security_events` table ([two tables](#data-two-tables)) | events must never cross companies, and an unknown sender cannot be placed in one; otherwise anyone could fill a company's security page just by trying its people's emails at sign-in |
| DE10 | The detector is a plain Python module with no FastAPI or database code | the study scores exactly the code that runs in the application |
| DE11 | The queue between requests and the worker holds at most **200 request copies**. When it is full, the new copy is dropped without waiting, and the drops are counted and written as one `detection.dropped` row per minute | a flood of requests must not use up memory or slow the API (threat D5); dropping is safe because detection is a record, not a protection |

### Normalization

Attackers disguise input, so each value is simplified before matching, in this order:

1. URL-decode, at most twice (catches `%2527`, a double-encoded quote).
2. Decode HTML entities (`&lt;script&gt;`).
3. Unicode NFKC, which turns look-alike characters such as full-width `＜` into plain ones.
4. Lowercase.
5. Collapse runs of whitespace and remove SQL inline comments (`/**/`), which attackers use in place of spaces.

The normalized text is used only for matching. The stored excerpt is the original text, so the security page shows what was really sent.

### What is collected, and what never is

The copy is made in the request, before anything is queued, by these rules in order (DE3). A value left out here never reaches the queue, the worker, the database, or the logs.

1. **Only three places are read:** query string values, path values, and strings in a JSON body. **No header is collected**, so cookies, the CSRF header, and the `Authorization` header can never be copied. The client address (DE8) and the request ID are stored as facts about the request, not inspected.
2. **Credential routes are skipped entirely:** sign-in, password change, password reset, and invitation acceptance, plus any later route that takes a credential. Each such route is marked in code (`detection_skip`), so the list cannot be forgotten in a separate file. Even the email field is skipped there, because it may hold a password typed into the wrong field (the same reason the sign-in log leaves the email out).
3. **Fields with secret-like names are left out at any depth.** The name is lowercased and stripped of `_` and `-`; if it contains `password`, `passwd`, `secret`, `token`, `csrf`, `apikey`, `authorization`, `cookie`, or `session`, the field is skipped, and so is everything inside it when it holds an object or a list. This applies to nested JSON objects, objects inside lists, query parameters, and path parameters (for example an invitation token in the URL).
4. **Credential fields are typed as secrets.** Every password or token in a request model uses pydantic's `SecretStr`. A test walks every route's request model and fails if a `SecretStr` field sits on a route that is not skipped and has a name that rule 3 does not catch. So a new credential field cannot slip into detection unnoticed.

Rules 2 and 3 overlap on purpose: either one alone keeps the known credential fields out, and together they also cover a field someone adds later.

### Rate cap and queue

Rows are only ever inserted, never changed, so the rate cap (DE6) keeps its counts in the worker's memory and writes the result once:

1. The worker keeps a counter for each source and minute (`session or address`, `minute`).
2. The first 20 events in a minute are written as normal rows.
3. After that, events are only counted. When the minute ends (checked each time the worker takes a copy, and at least every 10 seconds), the worker **inserts** one `detection.summary` row whose `count` is how many events were held back, then forgets the counter.
4. At most **10,000 sources** are tracked at once. Events from further sources in the same minute go into one shared overflow counter, written the same way, so memory stays bounded even if every request comes from a new address.
5. When the application stops, the worker writes the summaries it still holds before it exits.

The queue (DE11) is a `queue.Queue` with a size of 200, filled with `put_nowait`. So a full queue never makes a request wait: the copy is dropped and a drop counter goes up, written each minute as one `detection.dropped` row in `platform_security_events`. Together with DE4, the queue can hold at most about 20 million characters of copied text.

The application runs one server process, so these limits are for the whole API. If more processes are added, each has its own counters, queue, and cap, and the limits apply per process.

### Data: two tables

Events with a company and events without one are kept in **separate tables**, so the company filter protects the first exactly as it protects every other table, and the second can never be read through a company's session.

**`security_events`:** the company's events. `CompanyOwned` (`company_id` required and filled from the session by the tenancy layer, layer 1), with company-aware foreign keys (layer 2), and included in the cross-company test suite like every other company-owned table.

| Column | Type | Rules |
|---|---|---|
| `id` | `BINARY(16)` | primary key (UUIDv7) |
| `company_id` | `BINARY(16)` | required; the session's company (DE9) |
| `user_id` | `BINARY(16)` | required; the person whose session sent the request; company-aware foreign key to `users` |
| `kind` | `VARCHAR(50)` | `detection.<type>` (for example `detection.xss`), `detection.summary` (DE6); later `authz.denied` and `csrf.refused` (#92) |
| `pattern_id` | `VARCHAR(20)` | which pattern matched; null for non-detection kinds |
| `field` | `VARCHAR(100)` | where the value was, for example `query.search` or `body.note` |
| `method`, `route` | `VARCHAR(10)`, `VARCHAR(200)` | the route template (`/api/shifts/{shift_id}`), not the raw path |
| `client_address` | `VARCHAR(45)` | IPv4 or IPv6 (DE8) |
| `request_id` | `VARCHAR(40)` | links to the application log line for the same request (#92) |
| `excerpt` | `VARCHAR(200)` | plain text (DE7) |
| `count` | `INT` | 1, or how many events a summary row stands for |
| `occurred_at` | `DATETIME(6)` | UTC |

**`platform_security_events`:** events from requests without a valid session, which belong to no company. The same columns **without `company_id` and `user_id`**, so a row cannot point at a company or a person even by mistake. Its kinds are the detection kinds, `detection.dropped` (DE11), and later `auth.lockout` (#92): a lockout happens before anyone is signed in, so it is a platform event too.
- It is **not** `CompanyOwned`, so the tenancy coverage test lists it as a stated exception, next to the audit tables, with the reason.
- Only the detection writer inserts into it, in a database session with no company. No endpoint reads it: the platform view is a stretch goal and gets its own permission and checks when it is designed.
- A company's session can never see these rows, because no company query touches this table, and the table has no company column a mistaken filter could match.

Both tables are kept for **1 year**, then removed by a nightly job (data model, retention). The application's database user may insert, read, and remove rows older than a year; it may not change them. Security events are **not** audit entries: they record what someone sent, not something the application did, and a flood of them must not grow the signed audit chain.

### Backend

| Method and path | Permission | What it does |
|---|---|---|
| `GET /api/security-events` | `security.view` | the company's events, newest first, paged (at most 200), filtered by `kind`, `user_id`, and a date range |
| `GET /api/security-events/summary` | `security.view` | counts per kind for the last 7 and 30 days |

There is no endpoint to change or remove events. Both endpoints read only `security_events`, filtered to the session's company by the tenancy layer like every other table; `platform_security_events` has no endpoint.

### Frontend

The security page (workforce-ops-app/workforce-ops-frontend#61): counts per type at the top, then the event list with filters. Each row shows the time, type, pattern, field, route, person (or "not signed in"), address, and excerpt. Every value is set with `textContent`.

### Audit and security

- Threats for the detector itself are in the [threat model](../security/threat-model.md): D4 (slow patterns), D5 (event flooding), T7 (attack text shown on the security page), I8 (secrets captured by detection), S6 (blaming another address), and R4 (evading detection).
- Security tests (`tests/security/`):
  - a request with an attack string gets the same status and body as without (DE1);
  - secrets are never stored (DE3): attack strings in headers, on credential routes, and in secret-named fields nested inside objects and lists leave no row and no text anywhere; and the `SecretStr` walk over every request model (rule 4);
  - the caps hold (DE4, DE6): after 20 events a source gets exactly one summary row with the right count, and no row is ever updated;
  - a full queue never slows a request (DE11): with the worker paused, requests still answer at normal speed and the drops are counted;
  - the excerpt survives as plain text (DE7);
  - company separation (DE9): another company's events answer 404, and a Manager gets 403; a sign-in attempt with an attack string in the email, for an account of a real company, writes nothing to that company's `security_events`; a request without a session writes only to `platform_security_events`.
- Reading the security page is not audited, like other reads.

### Known limitations

- **Detection can be evaded.** Pattern matching only sees known shapes of attack; a determined attacker can find a form that slips through (R4). That is acceptable because detection is a record, not a protection, and the study measures how much slips through.
- **Requests from people not signed in are not on any company's page** until the platform view exists (stretch).
- **Credential routes are not inspected,** so an injection attempt in the sign-in form leaves no detection event. These routes are protected by bound parameters and the sign-in lockout, and lockouts are recorded (#92).
- **Under a flood, some requests are not inspected:** a full queue drops copies (DE11), and the drops are counted, not hidden. If the application stops suddenly, at most one minute of held-back summary counts is lost.
- **Only text the API receives is inspected.** Attacks against nginx, or traffic that never reaches the API, are out of scope.

---
## Detection study (RQ1)

How the detector is measured for the report. The scripts, datasets, and results live in the [research repository](https://github.com/workforce-ops-app/workforce-ops-research), so the study can be repeated.

### Question and measures

**RQ1:** what types of attacks can pattern-based inspection of input detect reliably? For each attack type, on a test set the patterns were never tuned on:

| Measure | Meaning |
|---|---|
| Precision | of the inputs flagged as this type, how many really were |
| Recall | of the inputs that really were this type, how many were flagged |
| F1 | one number balancing the two |
| 95% confidence interval | Wilson interval for precision and recall, so a small set is not reported as more certain than it is |
| Confusion matrix | rows: the true type (or harmless); columns: the types flagged (or none). An input flagged as two types counts in both columns |
| False alarm rate on harmless input | the share of harmless inputs flagged as anything |
| Time per value | median and 99th percentile per pattern and for the whole detector |

"Reliably" is decided per type from these numbers and their intervals, and the report states the threshold it uses before the test set is scored.

### Data and how it is chosen

| Set | Source | Why |
|---|---|---|
| Attack input | [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) and [SecLists](https://github.com/danielmiessler/SecLists) (both MIT licensed), pinned to one commit each | widely used public collections, agreed at the design review; already labelled by attack type through their folder layout |
| Tricky harmless input | written by the team: names such as *O'Brien*, notes such as "please select a new shift", "I'll drop by at 5", "<3", "see ../notes", prices and times with `%` and `$` | false alarms are what make pattern matching look bad, so the harmless set is chosen to be hard, not easy |
| Ordinary harmless input | the demo data's text fields, and a public list of common surnames | the false alarm rate on everyday text, not only on tricky text |
| Field set | requests sent by ZAP, sqlmap, and Burp during the attacker audits (backend #118, #119), labelled by the tool's attack category, plus a scripted walk-through of the final demo as harmless traffic | checks the numbers on traffic the patterns were not built from |

**Selection rules,** written down before anything is scored:
1. Take every entry from the files for each type at the pinned commits. Leave out entries that need a different setting to be dangerous (binary data, attacks on other protocols), and record each excluded file with the reason.
2. Remove duplicates after normalization, and keep near-duplicates (equal after removing digits and whitespace) together in one set, so the test set is not just copies of the tuning set.
3. If a type has more than 1,000 entries, take a random sample of 1,000 with a fixed seed, so one large type does not dominate.
4. Target at least 300 test entries per attack type and 1,000 harmless test entries, which keeps the confidence intervals within about 3 to 6 percentage points.

### Tuning and test split

- Each type's entries are split **60% tuning, 40% test**, stratified by type and by source, with a fixed seed.
- The split is committed, with each file's SHA-256 checksum, **before any pattern is tuned**. Nobody looks at the test set while writing patterns.
- When tuning ends, the detector is tagged (for example `detector-v1`) and scored on the test set **once**. A later change is a new version with its own score; the first score stays in the report.
- The field set is scored with the same tagged version.

### Timing

- Each value is matched 100 times and the median is kept, using `time.perf_counter_ns`, on one stated machine with nothing else running.
- **Worst case:** for each pattern, crafted inputs at the 2,000 character cap (long runs of characters that almost match) must finish within a fixed budget per value (DE5). This doubles as the safety check against slow patterns, and runs as a test in CI.
- The time detection adds to the server's work per request is measured with and without the detection layer on the same requests.

### Threats to validity (for the report)

- **The test data comes from public collections,** which may over-represent attacks that are easy to spot. The field set and the tricky harmless set are there to check this.
- **The team wrote both the patterns and the tricky harmless set.** The harmless set is written and committed before tuning starts, so it cannot be chosen to fit the patterns.
- **Lab conditions:** timing comes from one machine, and the field set comes from our own audits, not real attackers.
- **Labels follow the collections' folders,** which are sometimes wrong or overlap; disagreements found while checking are recorded, not silently fixed.

---
## Slices

Filed under tracker workforce-ops-app/.github#91 once this design merges. Each is one pull request.

| ID | Repository | Slice | Depends on |
|---|---|---|---|
| DT1 | backend | this design page (#115) | |
| DT2 | backend | `security_events` and `platform_security_events` tables, the insert-only writer with the rate cap (DE6), and the yearly clean-up job | DT1 |
| DT3 | backend | the detector module: normalization, patterns, unit tests, and the worst-case timing test (DE4, DE5, DE10) | DT1 |
| DT4 | backend | the detection layer: copy values by the collection rules (including `SecretStr` on credential fields), the bounded queue, inspect after the answer, record events (DE1 to DE3, DE7 to DE9, DE11) | DT2, DT3 |
| DT5 | backend | `security.view` permission and the two endpoints | DT2 |
| DT6 | backend | security events in the demo data | DT2 |
| DT7 | frontend | the security page (#61) | DT5 |
| DS1 | research | fetch the datasets at pinned commits, apply the selection rules, write the split with checksums | DT1 |
| DS2 | research | the scoring script with tests: precision, recall, F1, intervals, confusion matrix, timing | DS1, DT3 |
| DS3 | research | score the tagged detector on the test set and the field set; publish the results | DS2, DT4, backend #118, #119 |
