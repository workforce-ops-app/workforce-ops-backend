# Company structure, people, and access

- **Status:** tables built (`app/modules/org/models.py`, migration `0002`); demo companies, structure, people, and their roles seeded by `scripts/seed_demo.py`; this module's permissions declared (`app/modules/org/permissions.py`); departments, teams, and team members built (Z3 part 1, #54); people endpoints planned (Z3 part 2, #54); remaining endpoints planned (core tier)
- **Related:** workforce-ops-app/workforce-ops-backend#8; frontend page: administration screens (workforce-ops-app/workforce-ops-frontend#3); design: [data model](../architecture/data-model.md), [authorization](../architecture/authorization.md), [authentication](../architecture/authentication.md)

## In short
Administrators set up their company in the application: its departments and teams, the people who work there, what role each person has and where it applies, and who reports to whom. People are never deleted, only deactivated, so the history stays complete. For testing and the demos, a seed script creates two made-up companies with everything already filled in.

## Who can use it

| Role | Can | Permission | Scope |
|---|---|---|---|
| Owner, Administrator | create, rename, and archive departments and teams; move people between them | `org.manage` | company |
| Owner, Administrator | create accounts, create setup and reset links, change a person's details, deactivate and reactivate, unlock, sign out | `user.manage` | people they are above |
| Owner, Administrator | create roles and change them when every holder is below them | `role.manage` | company, with [delegation limits](../architecture/authorization.md#delegation-limits) |
| Owner, Administrator | give and remove roles; a role at their own level needs approval from above | `role.assign` | people they are above |
| Owner, Administrator | add and end reporting lines | `reporting_line.manage` | pairs of people they are above |
| Owner | propose adding or removing an owner | `company.transfer_ownership` | company |
| Manager | see the people in their scope and the roles they hold | `user.view` | their assignment's scope |
| Everyone | see their own name, department, teams, roles, and managers | none | own account |
| Everyone | ask to change their own display name (core) or email (next tier); it takes effect once approved from above | `account.change_self` | own account |

These are the starting roles' defaults ([authorization](../architecture/authorization.md#starting-roles)); companies can change what their roles grant.

## How it works

```mermaid
flowchart LR
    S["Seed script creates<br/>the company and its owner"] --> D["Owner or administrator<br/>creates departments and teams"]
    D --> U["Creates accounts<br/>(name, email, home department)"]
    U --> L["Creates a setup link,<br/>passes it on"]
    L --> P["Person sets their password"]
    U --> R["Gives roles with a scope"]
    U --> RL["Adds reporting lines"]
```

1. The company and its first owner exist already: in the core tier, only the seed script creates companies.
2. An administrator creates departments (for example Kitchen, Front of House) and teams inside them (Weekend Crew).
3. They create an account for each person: name, email, and **home department**. The account has no password yet.
4. They create a **setup link** and give it to the person, who opens it and chooses a password ([authentication](../architecture/authentication.md#setup-and-reset-links)).
5. They give the person roles with a scope. Everyone normally gets the Employee role for their home department; a manager gets the Manager role for the department or team they run.
6. They add **reporting lines**: who reports to whom. These decide who reviews whose requests and who can change whose access.

---
## Details

### States and rules

**Departments and teams**
- Names are unique within the company (departments) or within the department (teams), ignoring case, archived ones included, so an old name cannot be confused with a new one in history (409). Surrounding spaces are removed; a name is 1 to 120 characters.
- A department's time zone is an IANA name such as `America/Chicago`, or none (the company's applies). Changing it does not move existing shifts: each keeps the zone it was created with ([schedules](schedules.md#states-and-rules)).
- A team belongs to one department for good: renaming is the only change.
- Archiving instead of deleting ([0020](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0020-status-over-deletion.md)). An archived department or team cannot be changed, and nothing new goes into it: no teams, members, or shifts (409).
- A department cannot be archived while it is the home department of anyone not deactivated, has upcoming shifts, or still has active teams (409); move the people and shifts, and archive the teams, first. Its row is locked while this is checked, and creating a team locks it too, so neither can slip in between. Each check is a locking read, so it sees a person, shift, or team that another request committed while this one waited for the lock (under MySQL's REPEATABLE READ an ordinary read would not).
- Archiving a department or team ends its role assignments' effect (archived scopes cover nothing, `app/authz/check.py`): the assignments stay for history but grant nothing. A team keeps its member list for history.
- A deactivated person cannot be added to a team (409); nobody is on a team twice (409).
- Every change to a team (rename, archive, add or remove a member) locks the team's row first and reads it fresh, so a change that waited for an archive is refused (409) instead of changing an archived team.
- Two requests saving the same name or the same membership at the same moment: the database's unique key refuses the second, and the answer is 409, never 500, wherever the database refuses it (when the row is sent, with the audit entry, or at the commit).
- A person on an archived team is no longer eligible for that department's shifts through it ([schedules](schedules.md#states-and-rules)).
- Known limitation: creating a shift does not lock the department, so a shift created at the very moment the department is archived can still be saved. Both are rare administrator actions; the shift can be cancelled afterwards.

**People**

```mermaid
stateDiagram-v2
    [*] --> Invited: account created
    Invited --> Active: setup link used
    Active --> Deactivated: deactivate
    Invited --> Deactivated: deactivate
    Deactivated --> Invited: reactivate (new setup link)
```

- **Invited:** no password yet; cannot sign in.
- **Deactivated:** cannot sign in; all sessions end and unused links are cancelled ([authentication](../architecture/authentication.md#sessions)). Upcoming shifts stay assigned and are listed for the administrator to reassign. Their records, roles, and reporting lines stay for history.
- **Reactivating** puts the person back to *Invited*: they set a new password with a fresh setup link.
- Every person has exactly one **home department** and may be on several **teams**. Changing the home department changes which department-scoped roles cover them.
- **Email addresses** are unique across the platform and stored in lowercase. When an address is taken, the answer is "this email can't be used" without saying where ([0016](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0016-tenant-isolation.md)).
- Nobody deactivates, unlocks, or signs out themselves through these actions, and the last owner cannot be deactivated.

**Changing your own name or email** ([0032](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0032-delegation-limits.md))
- A person asks for the change; nothing changes until it is approved.
- **Who approves:** the nearest person above them who holds `user.manage` (usually an administrator), walking up the chain and ending at the Owner.
- **Owners:** with several owners, another owner approves. A sole owner's request goes to platform staff; until platform staff screens exist, the platform operators decide with a command-line tool, recorded in the platform audit chain.
- **Email (next tier):** the password must be re-entered when asking; the address must not be taken (checked when asked and again when approved, with the generic answer if taken); when the change takes effect, the person's other sessions end. A confirmation link to the new address can be added once email delivery exists.
- Requests not decided within 7 days expire.
- Administrators with `user.manage` who are above the person can still change the name or email directly.

**Roles, assignments, reporting lines, and owners** follow the [authorization](../architecture/authorization.md) page: rules AZ1 to AZ15, the delegation limits, and the approval requests for same-level grants and owner changes. Actions marked *sensitive* there need the password re-entered.

### Backend

**Endpoints** (all under `/api`, following [0026](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0026-api-conventions.md)):

| Method and path | Permission | Does |
|---|---|---|
| `GET /departments?cursor=&limit=` | signed in | page through active departments by name (built early in #88) |
| `GET /teams?department_id=&cursor=&limit=` | signed in | page through active teams by name, optionally of one department |
| `POST /departments`, `PATCH /departments/{id}`, `POST /departments/{id}/archive` | `org.manage` | create, rename or set the time zone, archive |
| `POST /teams`, `PATCH /teams/{id}`, `POST /teams/{id}/archive` | `org.manage` | create, rename, archive |
| `POST /teams/{id}/members` `{user_id}`, `DELETE /teams/{id}/members/{user_id}` | `org.manage` | add (201) or remove (204) a team member |
| `GET /users`, `GET /users/{id}` | `user.view` (scope filter) | list and view people |
| `POST /users` | `user.manage` | create an account (name, email, home department) |
| `PATCH /users/{id}` | `user.manage`, above the person | change name, email, or home department |
| `POST /users/{id}/deactivate`, `POST /users/{id}/reactivate` | `user.manage`, above the person | change account state |
| `GET /roles` | `role.view` (company) | list roles and everything each grants |
| `POST /roles`, `PATCH /roles/{id}`, `POST /roles/{id}/archive` | `role.manage` (delegation limits) | create, change, archive |
| `GET /role-assignments?user_id=` | `user.view`, the person in scope | a person's roles and scopes |
| `POST /role-assignments` | `role.assign`, above the person | give a role; answers **201** when it takes effect, **202** with an approval request when it needs approval from above |
| `DELETE /role-assignments/{id}` | `role.assign`, above the person | remove a role |
| `GET /reporting-lines?user_id=` | `user.view` | a person's managers and reports |
| `POST /reporting-lines`, `POST /reporting-lines/{id}/end` | `reporting_line.manage`, above both people | add or end a line |
| `POST /owners`, `POST /owners/{user_id}/remove` | Owner | propose an owner change (an approval request) |
| `POST /me/account-changes` `{display_name}` or `{email}` | `account.change_self` (email: next tier, password re-entry) | ask to change your own name or email; answers 202 with an approval request |
| `GET /approval-requests` | signed in | requests you made and requests waiting for you |
| `POST /approval-requests/{id}/approve`, `.../deny`, `.../cancel` | the eligible approver, or the requester for cancel | decide or withdraw |

Setup links, reset links, unlocking, and signing someone out are on the [authentication](../architecture/authentication.md#endpoints) page.

**Tables:** `companies`, `departments`, `teams`, `users`, `team_members`, `roles`, `role_permissions`, `role_assignments`, `reporting_lines`, `approval_requests`, `approval_decisions` ([data model](../architecture/data-model.md)).

**Scope resolver:** a person belongs to their home department, their teams, and themselves.

### Demo data

The seed script (`python -m scripts.seed_demo`) creates the demo data for local use, CI, and the demos. Running it again changes nothing; the only thing that differs between databases is the dates of the demo shifts, which are counted from the day the shifts are first added ([0031](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0031-demo-environment-and-data.md)):

- **Two companies**, for example *Northwind Cafe* (America/Chicago) and *Summit Outfitters* (America/Denver), built alike on purpose: same department names and similar people, so a leak between companies is obvious in tests and demos.
- In each company: two or three departments, a team or two in each, and people in every starting role. Each company gets the four starting roles; everyone holds Employee for their home department, owners and administrators their role for the whole company, and managers Manager for their home department, except the Weekend Crew lead (Felix Grant, Owen Park), who is Manager of that one team only (built, Z1).
- **Reporting lines** that exercise the rules (built, Z2), the same in both companies: a chain of several levels (Cara Lund reports to the Weekend Crew lead, who reports to the Kitchen manager, who reports to the administrator, who reports to the owner), someone with two managers (Ben Okafor: the Kitchen manager and the crew lead), an administrator over another administrator (Sofia Reyes and Theo Walsh, a second administrator in each company, report to the first), and someone with no manager (Ella Novak and Nora Quinn), whom only the Owner can manage. Each line is added through the same service the application uses, as the system, and audited as `reporting_line.added`. A database seeded before the second administrators joined the demo data cannot get its lines; the script says to reset it and seed again.
- **Two weeks of shifts** (built, SD1): from the day the script runs, in each company's time zone, for 14 days, so the demo always has a schedule ahead. The same weekly pattern in both companies: 21 shifts a week in Kitchen and Front of House, three of them open, one with a note and one with an event in the first week, nobody booked twice at the same time. Each shift is created the way a manager creates it on the website: through the schedules service (`create_shift`), as the manager who plans it, so it passes the same `authorize()` check and the same rules ([schedules: states and rules](schedules.md#states-and-rules)) and is written to the audit log as `shift.created` under that manager's name. The department managers plan their departments; the Weekend Crew lead plans the crew's Saturday Kitchen shifts (an open shift is outside one team's scope, so the Kitchen manager plans Sunday's). If the application refuses a demo shift, the script stops, names the shift and the reason, and keeps none of that company's shifts. A shift that has already ended when the script runs is skipped, and the shifts wait until `DEMO_PASSWORD` has given everyone they need a password, since shifts only go to people who have set up their account. A company that already has shifts gets no more; a company seeded before shifts existed, or before it had passwords, gets them on the next run. A company seeded before someone the shifts need joined the demo data (such as the Weekend Crew lead) is not changed; the script says to reset the database and seed again.
- **Security events** (built, DT6), so the security page has something to show in the demo before any real traffic exists ([detection](detection.md)): in each company, attacks of every type by five people over the last 30 days (so the 7 and 30 day counts differ), including `<img src=x onerror=alert(1)>`, which would run if the page showed it unsafely; and one burst of 25 from one person within a minute, which the rate cap writes as 20 rows and one `detection.summary` row of 5. Each value is run through the real detector, so its pattern and excerpt are exactly what the application would store, and the events go through the application's own writer with its clock set to the demo moments. Three events from people not signed in and one `detection.dropped` count go to `platform_security_events`, once. A company that already has security events gets no more.
- A few time-off requests in each state (after the midterm, SD2).
- Emails use the reserved `example.com` and `example.org` domains. Demo passwords come from an environment variable, never from the repository.
- The script refuses to run against a production database.

### Audit and security

**Audit events:** `department.created`, `department.updated`, `department.archived`, `team.created`, `team.updated`, `team.archived`, `team_member.added`, `team_member.removed`, `user.created`, `user.updated` (details: which fields), `user.deactivated`, `user.reactivated`, `user.change_requested` (details: which field); approved changes are recorded as `user.updated` with the approver; plus the role, reporting-line, ownership, and approval events on the [authorization](../architecture/authorization.md#audit-events) page.

**Threats** ([threat model](../security/threat-model.md)): I1 and T3 (other companies' people), I2 (people outside scope), I3 (email already taken), E1 to E6 and E9 (access changes).

**Security tests:**
- Every endpoint above, requested as a user of the other demo company, answers 404; a body that names another company's record (a team's department, a new member) answers 422, like any unknown ID (built for departments, teams, and members: `tests/security/test_org_structure.py`).
- Only `org.manage` changes departments, teams, and members: managers and employees get 403 on every one, and a request without the CSRF token changes nothing.
- A role for an archived department or team grants nothing.
- A manager cannot list or view people outside their scope (403).
- Every escalation rule AZ1 to AZ15 has a test.
- Deactivation ends the person's sessions and cancels their links.
- Creating an account with an email used by the other company gives the generic answer.
- A person's own name change does not take effect before approval; the approver must hold `user.manage` and be above them; nobody approves their own change.
- (Next tier) An email change without a recent password re-entry is refused; an address taken between request and approval is refused at approval.

### Known limitations
- No screen for creating companies or platform staff accounts yet; the seed script does it.
- No bulk import of people.
- Changing your own email arrives with the next tier; until then an administrator changes it.
- A sole owner's name change waits for the platform operators' command-line tool until platform staff screens exist.
