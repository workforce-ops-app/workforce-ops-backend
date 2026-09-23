# Audit log

**In short:** every security-relevant action (sign-ins, permission changes, approvals, schedule changes, automatic expirations) is written to a log that cannot be quietly edited. Each entry is linked to the previous one and signed with a secret key that is kept outside the database, so any change, removal, or insertion is detected when the log is checked.

Decision: [0018](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0018-audit-log-chains.md).

> **Status:** design. Code references will be added when the audit module is built.

## How an entry is written

```mermaid
sequenceDiagram
    participant S as Service code
    participant A as audit module
    participant DB as MySQL
    S->>A: record(action, target, details)
    A->>DB: SELECT head FOR UPDATE (company's chain)
    DB-->>A: last_seq, last_signature
    A->>A: seq = last_seq + 1<br/>signature = HMAC-SHA256(key, canonical_json(entry) + last_signature)
    A->>DB: INSERT audit_events row
    A->>DB: UPDATE head (seq, signature)
    Note over S,DB: all in the same transaction as the action itself
```

- The entry is written **in the same transaction** as the action it records, so an action cannot succeed without its audit entry (and vice versa).
- Each company has its own chain. Actions by platform personnel go to a separate platform chain.
- Automatic actions use actor `system`.

## What an entry contains

| Field | Notes |
|---|---|
| `seq` | 1, 2, 3… per chain, no gaps; `(chain_id, seq)` is a unique key |
| `chain_id` | which log: the company's ID, or the all-zero UUID for the platform chain |
| `company_id` | null for the platform chain |
| `actor_type`, `actor_id` | `user`, `platform_user`, or `system` (no ID for `system`) |
| `action` | dotted name, e.g. `time_off.approved`, `role.permission_added` |
| `target_type`, `target_id` | what was acted on |
| `occurred_at` | UTC |
| `details` | JSON: before/after values where useful. No passwords, tokens, or secrets |
| `key_id` | which signing key was used |
| `prev_signature`, `signature` | the chain links |

**Canonical JSON:** the signed bytes are the entry's fields as JSON with sorted keys, no extra whitespace, UTF-8, and timestamps in one fixed format, so verification always recomputes identical bytes.

## Verification

- **Nightly job:** re-verifies every chain from the start (or from the last verified checkpoint), and records the result as an audit event.
- **On demand:** owners (through a dedicated audit permission) can run verification for their company.
- **Outside copy:** each night the latest head signature per chain is written to the application log, so a database rollback to an older state can also be detected.

A verification failure names the first bad `seq` and raises a security event.

## Protection in the database

| Database user | Audit tables |
|---|---|
| application | `INSERT`, `SELECT` on `audit_events`; `SELECT`, `UPDATE` on `audit_chain_heads` |
| migrations | schema changes only, not used by the running application |

## The signing key

- Provided through the environment or a secret store, **never** stored in the database or the repository.
- Has an ID; rotating the key starts using a new ID while old entries keep theirs. Old keys are kept (read-only) for verification.
- Losing a key means entries signed with it can no longer be verified; leaking it reduces the protection to a plain hash chain. Its handling will be covered by an operations runbook.

## Relation to blockchains

**In short:** the audit log borrows the core idea of a blockchain, where each entry is linked to the one before it so that changing history breaks the chain, but it is not a blockchain. The accurate name is an **HMAC-signed hash chain**, or a tamper-evident log.

**What it borrows:** every entry stores the previous entry's signature, and its own signature covers that value. Editing, removing, or inserting an entry therefore invalidates every entry after it, just as altering a block invalidates the blocks that follow it.

**Where it differs:**

| | Blockchain (e.g. Bitcoin) | This audit log |
|---|---|---|
| Storage | Copied across many independent computers | One database the application controls |
| Who adds entries | Many parties agree (consensus, mining) | The application alone |
| What seals an entry | A public hash anyone can recompute | HMAC-SHA256 with a secret key kept outside the database |
| Who can verify | Anyone | Whoever holds the key (the verification job, and owners through it) |
| Protects against | Distrust between many independent parties | Someone quietly editing or deleting the organization's own records |

**Why a secret key instead of a plain hash:** with a plain hash chain, anyone with database access could change an entry and recompute every hash after it, leaving a chain that still looks valid. Without the key they cannot produce valid signatures. A blockchain solves the same problem differently, by keeping many independent copies. That is unnecessary here, and would add infrastructure the project does not need.

**Wording for reports:** describe it as a "tamper-evident, HMAC-signed hash chain". Calling it a blockchain overstates it, because there is no network of independent copies and no consensus.

## What to log

Log actions that change access, data belonging to others, or configuration: authentication events, role and permission changes, scope changes, approvals and denials, schedule changes, policy changes, support access, and automatic actions. Feature pages list their audit events.
