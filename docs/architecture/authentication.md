# Authentication and sessions

**In short:** people sign in with their email and a password of at least 15 characters. Passwords are stored only as Argon2id hashes. Signing in creates a session kept on the server; the browser holds just a random key to it in a tightly locked cookie. Sessions end after an hour without activity, or 30 days after sign-in at the latest. Every change is protected against forged requests, repeated wrong guesses cause short lockouts, and risky actions ask for the password again. New employees and forgotten passwords use one-time links that an administrator passes on.

Decisions: [0027 authentication and sessions](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0027-authentication-and-sessions.md) · [0025 sensitive actions and security settings](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0025-sensitive-actions-and-security-settings.md) · [0003 one address for pages and API](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0003-same-origin-deployment.md) · Threats: S1 to S5, I3, D1 in the [threat model](../security/threat-model.md)

> **Status:** passwords (`app/auth/passwords.py`) and sign-in with sessions (`app/auth/sessions.py`, the `sessions` endpoints, migration `0004`) are built; CSRF, lockouts, links, and re-entry follow in the next Phase 2 slices. Until lockouts (S4) exist, an account with `locked_until` in the future is refused, but failures are not counted yet.

## Passwords

| Rule | Value | Why |
|---|---|---|
| Length | at least 15 characters, at most 128 | NIST SP 800-63B rev. 4 for password-only sign-in; the upper limit keeps hashing cost predictable |
| Characters | any printable characters, including spaces and emoji; Unicode is normalized (NFKC) first | passphrases work; the same password typed on another device matches |
| No truncation | the whole password is hashed | long passphrases keep their strength |
| No composition or rotation rules | no "must contain a digit", no forced changes | these make passwords weaker and more predictable; change only when compromised |
| Blocklist | rejected if it is one of the 100,000 most common passwords (from a public list, compared ignoring case), or contains the company's name or the person's email name or display name | stops the guesses attackers try first |
| Stored as | **Argon2id**, tuned to about 0.5 s on the server (starting point: 64 MiB memory, 3 passes); the settings are saved inside each hash | slow and memory-hard, so a stolen database is expensive to crack |

The blocklist is `app/auth/common-passwords.txt`: the UK National Cyber Security Centre's 100,000 most-used passwords (as published in SecLists, MIT License), keeping only the 327 entries of 15 characters or more, since shorter ones are already refused by length and the minimum can only be raised. A password also may not contain the company's name, the email name, the display name, or any word of 4 letters or more from them, compared ignoring case, spaces, and punctuation.

The starting settings take about 0.1 s per hash on a developer laptop; they are raised towards 0.5 s once there is a server to measure on, and existing passwords are re-hashed at their next sign-in (`needs_rehash`).

Companies may raise the minimum length (up to 64), never lower it ([0025](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0025-sensitive-actions-and-security-settings.md)). When the hashing settings are raised later, each password is re-hashed with the new settings the next time its owner signs in.

**Why a slow hash for passwords but a fast one for tokens?** Passwords are short and chosen by people, so an attacker with the hashes could try billions of guesses; Argon2id makes each guess expensive. Session and link tokens are 256-bit random values that cannot be guessed, so a fast SHA-256 is enough to keep them useless if the database leaks.

## Signing in

```mermaid
sequenceDiagram
    participant B as Browser
    participant A as API
    participant DB as MySQL
    B->>A: POST /api/sessions {email, password}
    A->>A: rate limit per address
    A->>DB: find user by email (lowercase)
    alt no such user, deactivated, no password yet, or locked
        A->>A: run a dummy Argon2id check (same timing)
        A-->>B: same error as a wrong password
    else user found
        A->>A: Argon2id verify
        alt wrong password
            A->>DB: count the failure, maybe lock; audit
            A-->>B: "email or password is incorrect"
        else correct
            A->>DB: reset failures; new session (token hash, expiry); audit
            A-->>B: Set-Cookie __Host-session=token; user, permissions, CSRF token
        end
    end
```

- **One message for every failure.** An unknown email, a wrong password, a locked, deactivated, or not-yet-set-up account all get the same answer in the same time: "Email or password is incorrect. After several failed attempts, sign-in is paused for a while." Otherwise the sign-in form would tell an attacker which emails have accounts (threat I3). A locked account is refused even with the correct password until the lock ends.
- Emails are unique across the platform, so an email and a password identify exactly one account and one company ([data model](data-model.md#users)).
- The session's company is the user's company; it is never taken from the request ([tenancy](tenancy.md)).
- **Finding the account before the company is known.** Every company table is filtered by the session's company, but at sign-in there is none yet. Two lookups, and only these, are allowed to look across companies with `cross_company_read()`: the account by email at sign-in, and the session by its token's hash on each request. Each reads only the ID and company; everything after that runs for the company found. A security test fails if any other file uses it ([tenancy](tenancy.md)).
- **No planted sessions (session fixation).** Sign-in always creates a new random token; a token the browser already carried is never turned into a signed-in session. If that earlier token still belonged to a working session, the session is ended, so a copy of the old token stops working.
- **The same time for every failure.** Each failure does exactly one Argon2id check (against a dummy hash when there is no real one), and a failed sign-in also waits until at least 0.5 s have passed (`FAILED_SIGN_IN_SECONDS`, kept above the Argon2id time). That hides the few milliseconds a failure for an existing account spends writing its audit entry.
- Failed sign-ins for unknown emails are logged without the email, which might be a password typed into the wrong field.

## Sessions

| Part | Rule |
|---|---|
| **Token** | 32 random bytes from the operating system's secure generator, sent to the browser once; the database stores only its SHA-256 ([`sessions`](data-model.md#sessions)) |
| **Cookie** | `__Host-session=<token>; Secure; HttpOnly; SameSite=Strict; Path=/`, with `Max-Age` set to the time left until the maximum session length |
| **Idle timeout** | 1 hour without a request ends the session (`last_seen_at`, updated at most once a minute) |
| **Maximum length** | 30 days after sign-in, however active (`expires_at`) |
| **New session ID** | at sign-in, when the password changes, and after using a reset link; the old session row is deleted |
| **Signing out** | deletes the session row and clears the cookie; "sign out everywhere" deletes all of the user's sessions |
| **Ended sessions** | deleted when their token is next presented, and at each sign-in of the same person; a regular cleanup of sessions nobody returns to follows with the first scheduled job |

What each cookie attribute does:
- `__Host-` prefix: the browser only accepts the cookie over HTTPS, for this exact host, with `Path=/`, so a subdomain cannot plant or overwrite it.
- `Secure`: never sent over plain HTTP.
- `HttpOnly`: JavaScript cannot read it, so an XSS bug cannot steal it.
- `SameSite=Strict`: the browser does not send it with requests started by other sites (first defense against CSRF).

Companies may shorten both time limits within the platform's bounds ([0025](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0025-sensitive-actions-and-security-settings.md)). Permissions are read on every request, so a role change takes effect immediately without a new session.

**What ends sessions early:**

| Event | Sessions ended |
|---|---|
| The user changes their password | all their other sessions (the current one gets a new ID) |
| A reset link is used | all of that user's sessions |
| The user is deactivated | all of that user's sessions; their unused links are cancelled |
| An administrator signs the user out | all of that user's sessions |

## Forged requests (CSRF)

Three defenses, so one mistake is not enough:

1. **`SameSite=Strict` cookie:** requests started by other sites arrive without the session.
2. **Origin check:** every request that changes something (`POST`, `PUT`, `PATCH`, `DELETE`) must carry an `Origin` header equal to the application's own address. This also covers the sign-in request, which has no session yet.
3. **CSRF token:** every request that changes something must send the header `X-CSRF-Token`. The token is `HMAC-SHA256(csrf_key, session token hash)`: it changes with every session, needs no database column, and cannot be computed without the server's `csrf_key` (a secret in the environment, separate from the audit key). The API returns it at sign-in and from `GET /api/sessions/current`; `js/api/client.js` adds it to every request.

`GET` requests never change anything, so they need no token.

## Lockouts and rate limits

| Limit | Value | Kept in |
|---|---|---|
| Wrong passwords for one account | 5 → locked 15 min; 10 → 30 min; 15 or more → 1 hour each time (the maximum) | `users.failed_sign_ins`, `users.locked_until` |
| Counter reset | after a successful sign-in, or 24 hours without failures | `users` |
| Sign-in attempts per address | 20 per minute | memory of the API process |
| Requests per session | 300 per minute | memory of the API process |

- A locked account gets the same answer as any failed sign-in (see [signing in](#signing-in)), so a lock does not reveal that the account exists. Only the per-address and per-session rate limits answer **429**, since they do not depend on which account was tried.
- An administrator can unlock an account (`user.manage`, above the person); it is audited.
- Repeated lockouts are recorded as security events for detection (next tier).
- The 1 hour maximum means an attacker can delay a real user, but never lock them out for good (threat D1).
- Rate limits are kept in memory, which is correct for one API server; they reset if it restarts. Several servers would need a shared store ([0012](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0012-extensibility-patterns.md)).
- Failed password re-entries (below) count toward the same lockout.

## Setup and reset links

There is no email service in the core tier, so an administrator creates the link and passes it on in person or by text ([0027](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0027-authentication-and-sessions.md)).

```mermaid
sequenceDiagram
    participant Ad as Administrator
    participant A as API
    participant P as New employee
    Ad->>A: POST /api/users/{id}/setup-link (user.manage, above the person)
    A->>A: token = 32 random bytes; store SHA-256, expiry, purpose; cancel older links; audit
    A-->>Ad: https://<host>/set-password.html#token=... (shown once)
    Ad->>P: passes the link on
    P->>A: POST /api/password-links/redeem {token, new password}
    A->>A: hash matches, not used, not expired; password rules
    A->>A: set password, mark link used, end the person's sessions; audit
    A-->>P: password set; sign in normally
```

- **The token is in the part after `#`.** Browsers never send that part to a server, so it does not end up in server logs or in the `Referer` header of other sites. The page reads it, sends it in the request body, and removes it from the address bar.
- Valid for 48 hours by default (companies may shorten it, not below 1 hour), and works once. A new link cancels the person's earlier unused links.
- Only someone with `user.manage` who is above the person may create a link ([authorization](authorization.md)). Nobody creates a link for themselves.
- A new account has no password until its setup link is used, so it cannot be signed into before then.

## Password re-entry for sensitive actions

Sensitive actions ([list](authorization.md#sensitive-actions)) need the password re-entered in the last **5 minutes**:

1. The action's request fails with **403** and the problem type `reauth-required`.
2. The interface asks for the password and sends `POST /api/sessions/current/reauth {password}`.
3. On success the session's `reauth_at` is set, and the interface repeats the original request.

This limits the damage from a session left open on a shared computer or stolen by an attacker who does not know the password (threat S2). Wrong passwords here count toward the lockout.

## Endpoints

| Method and path | Who | Does |
|---|---|---|
| `POST /api/sessions` | anyone | sign in |
| `GET /api/sessions/current` | signed in | current user (with their home `department_id`), their company, their effective permissions (empty until Z1), CSRF token (from S3) |
| `DELETE /api/sessions/current` | signed in | sign out |
| `DELETE /api/sessions` | signed in | sign out everywhere (own sessions) |
| `POST /api/sessions/current/reauth` | signed in | re-enter the password |
| `PUT /api/me/password` | signed in | change your own password (current and new password) |
| `POST /api/users/{id}/setup-link`, `POST /api/users/{id}/reset-link` | `user.manage`, above the person | create a one-time link |
| `POST /api/password-links/redeem` | anyone with a valid link | set a password with a link |
| `POST /api/users/{id}/unlock` | `user.manage`, above the person | clear a lockout |
| `DELETE /api/users/{id}/sessions` | `user.manage`, above the person | sign the person out everywhere |

## Audit events

| Action | When |
|---|---|
| `auth.signed_in` | successful sign-in |
| `auth.sign_in_failed` | a failed sign-in for an existing account; `details.reason` is `wrong_password`, `no_password`, `deactivated`, or `locked`. The actor is `system` (nobody is signed in) and the target is the account tried |
| `auth.locked`, `auth.unlocked` | an account is locked by the schedule, or unlocked by an administrator |
| `auth.password_changed` | a user changes their own password |
| `auth.link_created`, `auth.link_used` | a setup or reset link is created or used |
| `auth.sessions_ended` | an administrator signs someone out, or deactivation ends their sessions |
| `auth.reauth_failed` | a wrong password at re-entry |

Entries never contain passwords, tokens, or hashes. Failed sign-ins for emails that do not exist have no company, so they go to the application log and the security events, not an audit chain.

## Security tests

| # | Test | Threat |
|---|---|---|
| AU1 | Passwords shorter than 15, on the blocklist, or containing the company or person's name are rejected; long passphrases with spaces are accepted | S1 |
| AU2 | Lockouts start at 5, 10, and 15 failures, never exceed 1 hour, and reset after success or 24 hours | S1, D1 |
| AU3 | Unknown email, wrong password, and locked, deactivated, or not-yet-set-up accounts give the same response in similar time | I3 |
| AU4 | The cookie has every attribute listed above; the session ID changes at sign-in | S2, S3 |
| AU5 | Sessions end after the idle timeout and the maximum length | S2 |
| AU6 | Changes without a CSRF token, with a wrong one, or with a foreign `Origin` are refused | S4 |
| AU7 | Links work once, expire, are cancelled by a newer link, and cannot be created for oneself or for someone not below the creator | S5, E3 |
| AU8 | Password change, reset, and deactivation end the sessions listed above | S2 |
| AU9 | Sensitive actions fail with `reauth-required` without a re-entry in the last 5 minutes | S2 |
| AU10 | No response, log line, or audit entry contains a password, token, or hash | I5 |

## Where the code lives

| Part | Location |
|---|---|
| Password rules, hashing, blocklist | `app/auth/passwords.py` |
| Sessions, cookie, idle and maximum limits, re-entry | `app/auth/sessions.py` (rules), `app/auth/models.py` (`UserSession`, the `sessions` table) |
| Requiring a signed-in person in an endpoint | `app/auth/dependencies.py`: a parameter typed `SignedInPerson` loads the session (401 without one) and sets its company on the request's database session; `Database` is the request's database session |
| The session endpoints | `app/modules/sessions/` (router and response shapes) |
| CSRF and Origin checks | `app/auth/csrf.py` |
| Lockouts and rate limits | `app/auth/limits.py` |
| Setup and reset links | `app/auth/links.py` |
| Tests | `tests/unit/test_sessions_api.py`, `tests/security/test_sign_in.py` (AU3, AU4, AU5, and companies), `tests/unit/test_passwords.py`, `tests/security/test_password_rules.py` (AU1) |
