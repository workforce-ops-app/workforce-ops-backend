# Security

**In short:** what we protect, what we protect it from, how, and what our audits have found. This supports the project's security study.

| Document | Status |
|---|---|
| [Threat model](threat-model.md) (data flows, attacker profiles, STRIDE threats and protections) | design, core tier |
| [Security controls](security-controls.md) (every protection, where it lives in the code, and its test; keys, algorithms, and logs) | current for the midterm backend |
| [Midterm audit](audit-midterm.md) (the backend checked against OWASP ASVS 5.0 Level 2, with its findings) | done 2026-10-12; batch shift changes checked when they merge |
| [Findings log](findings-log.md) (fixed findings only; entries are added after a finding's fix merges, [security policy](https://github.com/workforce-ops-app/.github/blob/main/SECURITY.md)) | started; no fixes merged yet |
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
