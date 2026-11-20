# Announcements

- **Status:** posting, editing, archiving, and the managed list are built (AN1, #154: `app/modules/announcements/`, migration `0014`, the `team` column of `ScopeColumns` in `app/authz/scope.py`); reading, one announcement, read marks, and the read list are built (AN2, #155, no migration); the audiences you may post to are built (#177, for the posting form); the demo data is built (AN3, #156: `seed_announcements()` in `scripts/seed_demo.py`) (final demo, [0038](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0038-final-demo-scope.md))
- **Related:** design workforce-ops-app/workforce-ops-backend#110; backend workforce-ops-app/workforce-ops-backend#120; screens workforce-ops-app/workforce-ops-frontend#65; tracker workforce-ops-app/.github#84; design: [authorization](../architecture/authorization.md), [organization](organization.md)

## In short
People who manage others post short announcements to the people they manage: a team, a department, or the whole company. Everyone sees the announcements meant for them, newest first, and marks them read; the people who posted can see who has read each one. The text is plain text with **bold** as the only formatting, and it is never treated as HTML, so an announcement cannot carry a script to the people who read it.

## Who can use it

| Role | Can | Permission | Scope |
|---|---|---|---|
| Everyone | read the announcements whose audience includes them; mark them read | none (signed in) | their own audiences |
| Manager | post, edit, and archive announcements for the department or team they manage; see who has read them | `announcement.create` | their assignment's scope |
| Owner, Administrator | the same, for any team or department, or the whole company | `announcement.create` | company |

These are the starting roles' defaults ([authorization](../architecture/authorization.md#starting-roles)): Employees do not get `announcement.create`; companies can change what their roles grant.

## How it works

```mermaid
sequenceDiagram
    participant M as Manager
    participant A as API
    participant E as Employee
    M->>A: POST /api/announcements {audience, title, body}
    A->>A: authorize: announcement.create covers the audience
    A->>A: save; audit announcement.posted
    E->>A: GET /api/announcements
    A-->>E: announcements whose audience includes them, newest first
    E->>A: POST /api/announcements/{id}/read
    M->>A: GET /api/announcements/{id}/reads
    A-->>M: who has read it, and who has not yet
```

1. A manager writes a title and a message and picks the **audience**: one team or one department they manage. Owners and administrators may also pick the whole company.
2. The announcement appears at once for everyone in the audience, on their home screen and the announcements page, newest first. Unread ones are marked.
3. Opening an announcement marks it read for that person.
4. The poster (and anyone else whose `announcement.create` covers the audience) sees how many people have read it, and who.
5. The text can be corrected later; the announcement then shows it was edited. When it is no longer needed, it is archived: it disappears for readers and stays for history.

---
## Details

### States and rules

```mermaid
stateDiagram-v2
    [*] --> Posted: posted
    Posted --> Posted: edited
    Posted --> Archived: archived
```

**Audience**
- Exactly one of: the **company**, one **department**, or one **team** of the poster's company (an unknown one, or another company's: 422, like any unknown reference in a body).
- Posting needs `announcement.create` whose scope covers the audience, by the usual scope rules ([authorization](../architecture/authorization.md#scope-resolvers)): a company-wide assignment covers every audience; a department assignment covers that department and its teams; a team assignment covers that team. A company audience needs a company-wide assignment. Anything else: 403.
- The audience is fixed once posted, so an announcement never moves to people it was not written for. To reach other people, post a new one.
- **Who is in it** is worked out when someone reads, not when it is posted, so a person who joins the team later also sees it: for a team, its members; for a department, the people whose home department it is; for the company, everyone. Deactivated people are in no audience.
- An archived department or team takes no new announcements (409), and its announcements stop reaching anyone, as archived scopes cover nothing ([organization](organization.md#states-and-rules)).

**Text**
- A **title** of 1 to 120 characters and a **body** of 1 to 4,000 characters, surrounding spaces removed. Line breaks in the body are kept.
- The only formatting is **bold**, written as `**like this**`, as the report plan sets out for cross-site scripting. The API stores and returns the text exactly as typed; it never contains or accepts HTML. A pair of `**` marks is shown as bold; anything else, including a lone `**`, is shown as typed.
- The frontend builds the bold parts as `<strong>` elements whose content is set with `textContent`, and everything else as text nodes; it never uses `innerHTML` (threat T5). So `<script>` or `<img onerror=...>` in an announcement shows up as those characters, harmlessly.
- Text is a value only, never a template (threat I7).

**Editing and archiving**
- Anyone whose `announcement.create` covers the audience may edit the title and body, or archive the announcement, not only its author, so a manager's successor can tidy up. Each edit sets `edited_at`, and readers see "edited".
- Editing does not reset who has read it.
- Archived announcements cannot be edited (409) and are not shown to readers. They are never deleted ([0020](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0020-status-over-deletion.md)).

**Read marks**
- `POST /announcements/{id}/read` records that the signed-in person has read it. Doing it again changes nothing (still 204), and the first read time stays. Only people in the audience of an active announcement can mark it (otherwise 404, as if it did not exist for them), so a manager who covers an audience they are not in cannot mark it read. Two marks sent at the same moment both answer 204 and one mark is kept: the primary key refuses the second, and that refusal is not an error for the person (`scripts/check_migrations.py` tries this race on MySQL).
- The read list (`GET /announcements/{id}/reads`) shows the people in the audience now, each with when they read it, or not yet. Only people whose `announcement.create` covers the audience may see it. Someone who can read the announcement but does not manage it (an employee) gets 403; for anyone who cannot even read it, it does not exist (404).
- The read counts, the read list, and the check on one person use one definition of the audience (`_with_audience()` in `repository.py`), so `read_count` and `audience_count` always match the read list. The reader's own list asks the same question from the other end (from one person to their announcements), and a test compares the two for every person and audience.
- The read list is paged like every other list ([0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md)): `?cursor=&limit=`, `limit` 1 to 200 (default 50), in name order (display name, then ID), so a company-wide announcement never answers with everyone at once. The cursor is the last person's ID; if that person is no longer in the audience, the cursor is refused (422), so a cursor cannot be used to learn where someone outside the audience sorts. The totals come from `read_count` and `audience_count` on the announcement, not from counting pages.
- Reads are not audited: they are a record of the feature, not a security action, and every page view would otherwise grow the audit chain.

### Backend

**Endpoints** (all under `/api`, following [0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md)):

| Method and path | Permission | Does |
|---|---|---|
| `GET /announcements?cursor=&limit=` | signed in | page through the active announcements whose audience includes you, newest first, each with `read` (true or false) |
| `GET /announcements/managed?cursor=&limit=&include_archived=` | `announcement.create` (scope filter) | page through the announcements whose audience your assignments cover, with read counts |
| `GET /announcements/audiences` | `announcement.create` (anywhere) | the audiences you may post to, for the posting form (#177) |
| `GET /announcements/{id}` | in the audience, or `announcement.create` covering it | one announcement |
| `POST /announcements` `{audience_type, department_id?, team_id?, title, body}` | `announcement.create` covering the audience | post (201) |
| `PATCH /announcements/{id}` `{title?, body?}` | `announcement.create` covering the audience | correct the text |
| `POST /announcements/{id}/archive` | `announcement.create` covering the audience | archive |
| `POST /announcements/{id}/read` | in the audience | mark read (204) |
| `GET /announcements/{id}/reads?cursor=&limit=` | `announcement.create` covering the audience | page through the people in the audience by name, each with when they read it, or not yet |

An announcement in an answer: `id`, `audience` (`{type, department_id, department_name, team_id, team_name}`; `department_id` is null for a team audience), `title`, `body`, `author` (`{id, display_name}`), `posted_at`, `edited_at`, `archived`, and for readers `read`, for managers `read_count` and `audience_count`. The reader's list answers `{items, next_cursor}` with `read` and no counts. `GET /announcements/{id}` answers `read` for everyone (whether the signed-in person has read it) and `read_count` and `audience_count` when their `announcement.create` covers the audience, null otherwise, so a reader never learns how many others have read it; the people who manage it also see it once archived. The read list answers `{items, next_cursor}`, each item `{id, display_name, read_at}` (`read_at` null: not read yet). `audience_count` is the people in the audience now (an archived team's audience is empty); `read_count` is how many of them have read it, so it matches the read list. The managed list's answer to someone whose only `announcement.create` assignment is for an archived department or team is 403, as for any list without a permission.

**Where you may post** (`GET /announcements/audiences`, #177): the session lists permission names only, not their scopes, and managers cannot read what roles grant, so the posting form asks the API which audiences to offer. The answer is `{items}`: the company first (if allowed), then each active department, then each active team, by name. Each item is `{type, department_id, team_id, name, department_name}`: `type` and the two IDs are exactly what the `POST` body needs (for a team, `department_id` is null), `name` is the department's or team's (null for the company), and `department_name` is a team's department, for the screens only. Each candidate is checked with `authorize()` on an unsaved announcement for that audience, the same check posting makes (`postable_audiences()` in `service.py`), so the form offers exactly what posting allows and the scope rules stay in one place. Archived departments and teams are left out, as posting to them is refused (409). Without `announcement.create` anywhere it answers 403. It is a convenience: posting still checks everything (E11).

**Table: `announcements`** (feature table)

| Column | Type | Rules |
|---|---|---|
| `id` | `BINARY(16)` | primary key |
| `company_id` | `BINARY(16)` | required |
| `author_id` | `BINARY(16)` | required; company-aware foreign key to `users` |
| `audience_type` | `VARCHAR(10)` | `company`, `department`, or `team` |
| `department_id` | `BINARY(16)` | required for `department`, null otherwise; company-aware foreign key to `departments` |
| `team_id` | `BINARY(16)` | required for `team`, null otherwise; company-aware foreign key to `teams` |
| `title` | `VARCHAR(120)` | required |
| `body` | `TEXT` | required; at most 4,000 characters, checked by the API |
| `edited_at` | `DATETIME(6)` | null until edited |
| `archived_at` | `DATETIME(6)` | null while active |

A `CHECK` keeps the audience columns consistent: exactly the ID its type needs, and no other. An index on (`company_id`, `created_at`) serves the newest-first lists.

**Table: `announcement_reads`** (feature table)

| Column | Type | Rules |
|---|---|---|
| `company_id` | `BINARY(16)` | required |
| `announcement_id` | `BINARY(16)` | part of the primary key; company-aware foreign key to `announcements` |
| `user_id` | `BINARY(16)` | part of the primary key; company-aware foreign key to `users` |
| `read_at` | `DATETIME(6)` | required |

| From | To | How many | Enforced by | Meaning |
|---|---|---|---|---|
| users | announcements | one to many | company-aware foreign key | A person can post many announcements |
| departments, teams | announcements | one to many | company-aware foreign keys | An announcement's audience is one department or one team (or the company) |
| announcements | announcement_reads | one to many | company-aware foreign key | Each read mark belongs to one announcement |
| users | announcement_reads | one to many | company-aware foreign key, primary key (one per person) | A person reads an announcement at most once |

**Scope resolver:** an announcement belongs to its audience: a department audience to that department; a team audience to the team and its department; a company audience to no department, so only a company-wide assignment covers it. It belongs to no employee, so no self permission applies to it.

**Managed list filter:** the managed list uses the scope filter (`scope_filter()`, [authorization](../architecture/authorization.md#lists-the-scope-filter)) so it shows exactly the announcements a direct request would allow. Today `ScopeColumns` only knows a department column and an employee column, and `condition_for()` only matches team assignments through team members' IDs, so a team audience could not be matched. AN1 extends the helper rather than writing a filter of its own:
- `ScopeColumns` gets a third, optional `team` column. Announcements are listed with `ScopeColumns(department=Announcement.department_id, team=Announcement.team_id)` and no employee column.
- A **team** assignment matches rows whose team column is its team (as well as, for tables that have an employee column, the team's members, as now).
- A **department** assignment matches rows whose department column is its department, and also rows whose team column is one of the department's teams. Those team IDs are looked up first in the company's session, like a department's people today, because the company filter refuses subqueries.
- A **company** assignment matches every row, so only it reaches company audiences (both columns are null, so no department or team assignment can match them).
- Existing callers pass no team column and keep their current conditions.

Scope tests for the filter, added with AN1: for every pair of an assignment (company, each department, each team) and an announcement (company, department, team, team of another department), the managed list contains the announcement exactly when `authorize()` allows it; a department assignment lists its teams' announcements; a team assignment lists neither its department's announcements nor another team's; a team audience whose team or department is archived is listed for nobody below company scope ([organization](organization.md#states-and-rules)).

**Audience filter:** the reader's list is limited in the database to the company, the reader's home department, and the teams they are on, with the same tenancy filter as every other query ([tenancy](../architecture/tenancy.md)); announcements for other audiences are never loaded. The reader's active teams (and whether their home department is active) are looked up first, because the company filter refuses subqueries; the list then asks for `team_id IN (those teams)`, as the scope filter does. One query joins each announcement to its author, its department and team names, and the reader's own read mark (`list_for_reader()` in `repository.py`, explained there for the presentation). A test counts the rows the query returns for one reader in a company with many audiences.

The audience is worked out the same way everywhere: deactivated people are in no audience, an archived team reaches nobody, and so does an archived department. The organization rules already keep an archived department empty, so the last is a second guard; the read counts check it too.

### Demo data

The seed script adds, in each demo company, through the same service the application uses (audited as `announcement.posted` under the poster's name):
- a company-wide announcement from the owner;
- a Kitchen announcement from the Kitchen manager, and a Weekend Crew one from the crew lead;
- one archived announcement, and one edited;
- an announcement whose body includes `**bold**` and text that would run if shown unsafely (for example `<img src=x onerror=alert(1)>`), so the demo shows both the bold and the plain-text display;
- read marks for some readers, so the read counts differ.

Built in AN3 as `DEMO_ANNOUNCEMENTS` in `scripts/seed_demo.py`, the same in both companies (in Northwind Cafe):

| Title | From | To | Read by | Afterwards |
|---|---|---|---|---|
| Holiday hours | the owner | the company | 3 of 10 | archived by the owner |
| Welcome to the new schedule | the owner | the company | 6 of 10 | |
| New allergen labels | the Kitchen manager | Kitchen | 2 of 4 | (has the bold text and the `<img>` tag) |
| Sunday brunch rush | the Weekend Crew lead | Weekend Crew | 1 of 3 | corrected by the crew lead |

They are posted in that order, so the last is the newest, and read before any is archived (an archived announcement cannot be marked read). Their posted times are the moment the script runs; the script does not backdate them, so the posted time always matches the audit entry. Added once per company; a step the application refuses stops the script and keeps none of that company's announcements (`tests/unit/test_seed_demo.py`).

### Audit and security

**Audit events:** `announcement.posted` (details: audience type and ID), `announcement.edited` (details: which fields), `announcement.archived`. The text itself is not copied into the audit log.

**Threats** ([threat model](../security/threat-model.md)): E11 (posting to people outside your scope), T5 (stored XSS in the text), I9 (reading announcements meant for others, or who read what), I1 and T3 (other companies), T2 (setting the author or audience directly), I7 (text used as a template), D2 (oversized text).

**Security tests:**
- Every endpoint, requested as a user of the other demo company, answers 404; an audience naming another company's department or team answers 422.
- A team manager cannot post to their department or the company, and a department manager cannot post to another department or the company (403); employees cannot post at all.
- A person outside an announcement's audience does not see it in their list, gets 404 for it and for marking it read, and cannot see its read list.
- Text with `<script>`, `<img onerror=...>`, and `{0.__class__}` is stored and returned exactly as typed (the frontend test checks it is shown as text).
- The author, audience, and dates cannot be set or changed through the request body (422).
- An archived department's announcements reach nobody.
- The managed list agrees with `authorize()` for every assignment and audience pair (the scope tests under Managed list filter).
- The audiences offered for posting agree with posting itself for every manager and audience; employees get 403; another company's departments and teams, and archived ones, are never offered (#177).
- The read list answers at most 200 people per page, refuses a larger `limit` (422), and refuses a cursor naming someone outside the audience (422).
- A deactivated person, someone taken off a team, and everyone in an archived department or team are in no audience; archived announcements disappear for readers; read marks cannot point across companies.
- The reader's list query returns only the reader's announcements, in a company with many audiences.

### Slices

Filed under tracker workforce-ops-app/.github#84 once this design merges: the backend slices as sub-issues of #120, the screens under workforce-ops-app/workforce-ops-frontend#65. Each is one pull request.

| ID | Repository | Slice | Depends on |
|---|---|---|---|
| AN1 | backend | `announcements` and `announcement_reads` tables (one migration), `announcement.create` with the starting roles, the scope resolver, the `team` column in `ScopeColumns` with its scope tests, posting, editing, archiving, and the managed list | this design |
| AN2 | backend | reading: the audience filter, one announcement, read marks, and the paged read list | AN1 |
| AN3 | backend | announcements in the demo data | AN2 |
| AN4 | frontend | reading announcements on the home screen and the announcements page, with the bold display built safely | AN2 |
| AN5 | frontend | posting, editing, and archiving, and the read list | AN1, AN4 |

### Known limitations
- No notifications: people see new announcements when they open the application (notifications are stretch, 0038).
- No attachments, images, or links that open automatically; links are shown as text.
- No scheduling an announcement for later, and no expiry: it stays until archived.
- An audience is one team, one department, or the company; several at once means several announcements.
