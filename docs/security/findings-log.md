# Security findings log

**In short:** every security weakness our audits found, once it has been fixed. A finding is added here only after the pull request that fixes it has merged, so this page never tells anyone about a weakness that still works. Open findings are tracked as issues (and, while exploitable, in a private advisory) as the [security policy](https://github.com/workforce-ops-app/.github/blob/main/SECURITY.md) describes.

- **Status:** started by the [midterm audit](audit-midterm.md) (#67); no fixes merged yet
- **Related:** [midterm audit](audit-midterm.md), [security controls](security-controls.md), [threat model](threat-model.md), tracker workforce-ops-app/.github#56 (AU2)

## How an entry is added

1. The finding has an issue from the security-finding template (or a private advisory first, if it could be exploited).
2. Its fix merges, with a regression test in `tests/security/` where possible.
3. The same pull request, or the next one, adds a row below: the audit that found it, the threat ID from the [threat model](threat-model.md), and the issue and fix.

## Findings

| Finding | Found by | Threat | Severity | Issue | Fixed in |
|---|---|---|---|---|---|
| none yet | | | | | |
