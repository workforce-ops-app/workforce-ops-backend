# Glossary

**In short:** the words this project uses with a specific meaning.

| Term | Meaning |
|---|---|
| **Company / tenant** | One customer organization. Its data is isolated from every other company. |
| **Role** | A named set of permissions, defined per company. |
| **Permission** | A single allowed action, for example `schedule.edit`. |
| **Scope** | The employees, departments, or teams a permission applies to for a given user. |
| **Candidate** | A coworker's answer to a coverage request (accept, or swap with one of their own shifts), waiting for the manager to choose. |
| **Audit log** | Append-only, tamper-evident record of security-relevant actions. |
| **Role assignment** | Giving a user a role together with its scope: the whole company, one department, one team, or one employee. |
| **Reporting line** | A record that one person reports to another. A person can report to several managers, and a manager can have many reports. |
| **Reporting chain / above** | Everyone reached by following reporting lines upwards. If C reports to B and B reports to A, both A and B are *above* C. The Owner counts as above everyone. Being above someone decides whom you may act on; permissions decide what you may do. |
| **Direct manager** | Someone a person reports to directly, with no one in between. Direct managers review that person's requests first. |
| **Nearest shared manager** | The lowest person above all of a group of managers in the reporting chain. Receives a request when its direct managers disagree. |
| **Sensitive action** | An action risky enough to need the password re-entered, such as transferring ownership or changing a role's permissions. |
| **Open shift** | A shift with nobody assigned yet, for example after the employee's time off was approved. |
| **Current company** | The company of the signed-in user, taken from the server-side session. Every query is filtered to it. |
| **Session** | A signed-in browser, kept on the server. The browser only holds a random key to it in a cookie. |
| **Setup / reset link** | A one-time link an administrator creates so a person can set their password: for a new account, or after a forgotten password. |
| **Password re-entry** | Typing the password again shortly before a sensitive action, even while signed in. |
| **Lockout** | A short period in which an account cannot sign in after repeated wrong passwords; never longer than 1 hour. |
| **Audit chain** | One company's audit entries, each signed together with the previous entry's signature, so tampering is detectable. |
| **Workplace zone** | The time zone a shift is scheduled in: the department's zone if set, otherwise the company's. |
| **Deactivated / archived** | Records are switched off instead of deleted: users are deactivated; companies, departments, teams, and roles are archived. |
| **Support access** | Time-limited, logged, revocable access to one company's data granted to platform personnel. |
