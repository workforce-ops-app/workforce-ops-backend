# Glossary

**In short:** the words this project uses with a specific meaning.

| Term | Meaning |
|---|---|
| **Company / tenant** | One customer organization. Its data is isolated from every other company. |
| **Role** | A named set of permissions, defined per company. |
| **Permission** | A single allowed action, for example `schedule.edit`. |
| **Scope** | The employees, departments, or teams a permission applies to for a given user. |
| **Stewardship** | An explicitly stored manager-to-employee/department/team relationship that defines a manager's scope. |
| **Candidate** | A coworker's accepted coverage or agreed swap, waiting for manager approval. |
| **Audit log** | Append-only, tamper-evident record of security-relevant actions. |
| **Role assignment** | Giving a user a role together with its scope: the whole company, one department, one team, or one employee. |
| **Current company** | The company of the signed-in user, taken from the server-side session. Every query is filtered to it. |
| **Audit chain** | One company's audit entries, each signed together with the previous entry's signature, so tampering is detectable. |
| **Workplace zone** | The time zone a shift is scheduled in: the department's zone if set, otherwise the company's. |
| **Deactivated / archived** | Records are switched off instead of deleted: users are deactivated; companies, departments, teams, and roles are archived. |
| **Support access** | Time-limited, logged, revocable access to one company's data granted to platform personnel. |
