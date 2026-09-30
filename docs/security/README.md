# Security

**In short:** what we protect, what we protect it from, how, and what our audits have found. This supports the project's security study.

| Document | Status |
|---|---|
| [Threat model](threat-model.md) (data flows, attacker profiles, STRIDE threats and protections) | design, core tier |
| Security controls (every protection, where it lives in the code, and its test) | to do: filled in as the security foundation is built (Phase 2), starting from the threat model |
| Findings log | to do: starts with the backend audit before the midterm; entries are added only after a finding's fix merges ([security policy](https://github.com/workforce-ops-app/.github/blob/main/SECURITY.md)) |
| Detection study (pattern-based detection results) | to do: next tier ([0030](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0030-security-study-method.md)) |

## Scope (from the project proposal)

- Prevent unauthorized cross-tenant access
- Prevent unauthorized privilege escalation
- Protect credentials and authentication mechanisms
- Protect customer and employee data
- Detect unauthorized activity
- Maintain trustworthy audit records
- Maintain service availability and recoverability
- Minimize the impact of compromised accounts
- Identify vulnerabilities before deployment
- Establish repeatable security processes
