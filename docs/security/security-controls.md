# Security controls

**In short:** every protection the backend has today, where it lives in the code, and the test that proves it works. It starts from the [threat model](threat-model.md): each row names the threats it answers. It also lists every key and algorithm the application uses, and every place it writes logs. When a protection is added or changed, this page changes in the same pull request.

- **Status:** current for the midterm backend (2026-10-12), checked by the [midterm audit](audit-midterm.md)
- **Related:** [threat model](threat-model.md), [findings log](findings-log.md), [authentication](../architecture/authentication.md), [authorization](../architecture/authorization.md), [tenancy](../architecture/tenancy.md), [audit log](../architecture/audit-log.md)

## Protections

Tests are in `tests/security/` unless another folder is named.

### Company separation

| Protection | Threats | Where | Tests |
|---|---|---|---|
| Automatic company filter on every query and save; refuses bulk statements and raw table access it cannot make safe | I1, T3 | `app/tenancy/filter.py` | `test_cross_company.py` |
| Last guard at the database connection: company data that skipped the filter is refused | I1, T3 | `app/tenancy/filter.py` (`_guard_connection`) | `test_cross_company.py::test_the_raw_connection_cannot_reach_company_data`, `test_legacy_bulk_methods_cannot_reach_another_company` |
| The company comes from the session, never from the request | I1 | `app/tenancy/context.py`, `app/auth/sessions.py` | `test_cross_company.py::test_a_session_cannot_switch_companies`, `test_sign_in.py::test_a_session_works_only_for_its_own_company` |
| Only sign-in and links may read across companies (finding a person by email, a session by token, a setup or reset link by token) | I1 | `cross_company_read` in `app/tenancy/filter.py` | `test_sign_in.py::test_only_sign_in_uses_the_cross_company_read`, `test_the_cross_company_read_is_only_a_select_before_a_company_is_set` |
| Company-aware foreign keys: a row cannot point at another company's row | I1, T3 | the models and migrations (`company_id` in composite keys) | `test_org_company_links.py` |
| Another company's record answers 404, exactly like a missing one | I1, I3 | `authorize()` step 1; the filter hides the row first | `test_shifts.py::test_another_companys_shift_does_not_exist_on_any_endpoint`, `test_departments.py` |

### Permissions and scopes

| Protection | Threats | Where | Tests |
|---|---|---|---|
| `authorize()` before every action and every read of one record | I2, E8 | `app/authz/check.py`, called in each `service.py` | `test_authorization.py`, `test_shifts.py` |
| Lists show only rows in the person's scopes, by the same rules | I2 | `scope_filter()` in `app/authz/check.py`, `app/authz/scope.py` | `test_authorization.py::test_the_list_filter_agrees_with_authorize_for_every_pair` |
| Acting on a person needs a place above them: the Owner, or above them through current reporting lines; peers and people below get nothing | E3, E4 | `is_above()` in `app/authz/check.py`, `app/authz/chain.py` | `test_reporting_chain.py` |
| Reporting lines never join two companies' people, nobody reports to themselves, there is one current line per pair, and loops are refused (and a loop that slipped in still ends the walk), even when two requests change lines at the same moment | E3, E4, I2 | company-aware keys, `CHECK`, and the `current_line` unique key in migration `0007`; `add_reporting_line()` locks the company and checks with fresh reads | `test_org_company_links.py::test_a_reporting_line_cannot_join_people_of_two_companies`, `test_reporting_chain.py`, `check_migrations.py` |
| Permissions are read fresh on every request; deactivated people and archived roles get nothing | E1, E8 | `grants()` in `app/authz/check.py` | `test_a_role_change_takes_effect_at_once`, `test_a_deactivated_person_may_do_nothing_even_as_owner`, `test_an_archived_role_grants_nothing` |
| An unknown permission or a record without a scope resolver is an error, never a yes | E8 | `get_permission()`, `resolve()` | `test_an_unknown_permission_is_a_bug_not_a_yes`, `test_a_record_without_a_scope_resolver_is_a_bug_not_a_yes` |
| A manager cannot move a shift out of their scope (checked before and after the change) | E8, I2 | `assign_shift()` in `app/modules/schedules/service.py` | `test_shifts.py::test_a_manager_cannot_see_or_change_another_departments_shifts` |
| Account actions need `user.manage` and a place above the person; a new account reports to the creator or someone below them; nobody creates or moves a person where their own `user.manage` does not reach; owners cannot be deactivated | E3, E6, E8 | `app/modules/org/people.py`, `covers_department()` in `app/authz/check.py` | `test_people.py::test_user_manage_without_a_place_above_is_refused`, `test_a_new_account_cannot_be_hung_under_someone_out_of_reach`, `test_nobody_moves_a_person_out_of_their_own_reach`, `test_users_api.py::test_an_owner_cannot_be_deactivated` |
| Roles: nobody makes a role grant what they do not hold (AZ3); only someone above every holder, or an owner, changes, renames, or archives a role (AZ13); the Owner role never changes (AZ9); changing what a role grants needs the password re-entered; checked on fresh reads under the company's lock (the actor's access, the holders and chain, the role's grants, the role count) | E2, E6, E9 | `app/modules/roles/service.py`, `app/authz/delegation.py`, `fresh=True` in `app/authz/check.py` | `test_roles.py`; `_role_race_problems` in `scripts/check_migrations.py` (MySQL) |
| A taken email gets the same answer whichever company has it (no lookup across companies) | I3 | `create_person()`, `change_person()` in `app/modules/org/people.py` | `test_people.py::test_a_taken_email_never_says_which_company_has_it` |
| Request bodies accept only listed fields (no `company_id`, status, or anything else) | T2 | `extra="forbid"` in `app/modules/schedules/schemas.py` and `app/modules/org/schemas.py` | `test_shifts.py::test_fields_outside_the_rules_cannot_be_set`, `test_users_api.py::test_account_input_is_checked` |
| Company settings can only be stricter than the platform, within its limits (AZ10); a weaker value written straight into the table is ignored; a company reads and changes only its own; every change is audited | E7, I2 | `app/settings/registry.py`, `app/settings/service.py` | `tests/security/test_company_settings.py`, `tests/unit/test_company_settings.py` |

### Sign-in and sessions

| Protection | Threats | Where | Tests |
|---|---|---|---|
| Passwords: 15 to 128 characters (or the company's longer minimum, up to 64), any characters, common-password blocklist, no names | S1 | `app/auth/passwords.py`, `app/auth/common-passwords.txt`, `password_min_length()` in `app/settings/service.py` | `test_password_rules.py`, `test_company_settings.py::test_the_company_minimum_applies_to_new_passwords`, `test_reauth.py::test_a_password_change_follows_the_companys_own_minimum` |
| Argon2id password hashes (64 MiB, 3 passes), upgraded at sign-in when settings rise | S1, I5 | `app/auth/passwords.py` | `test_password_rules.py::test_the_stored_hash_never_contains_the_password`, `tests/unit/test_passwords.py` |
| Every failed sign-in gets the same answer, does the same work, and takes at least 0.5 seconds | I3 | `sign_in()` in `app/auth/sessions.py` | `test_sign_in.py::test_every_failed_sign_in_gets_exactly_the_same_answer`, `..._does_the_same_work`, `..._takes_at_least_the_same_minimum_time` |
| Random 256-bit session token; only its SHA-256 is stored | S2, I5 | `new_token()` in `app/auth/sessions.py` | `test_each_sign_in_gets_a_new_unguessable_token`, `test_no_answer_contains_a_password_hash_or_token_hash` |
| A new token at every sign-in; the browser's previous session ends | S3 | `sign_in()`, `end_previous_session()` | `test_a_planted_token_never_becomes_a_signed_in_session`, `test_signing_in_again_ends_the_browsers_previous_session` |
| `__Host-session` cookie: `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` | S2, S4 | `_set_cookie()` in `app/modules/sessions/router.py` | `test_the_cookie_has_every_protective_attribute` |
| Sessions end after 1 hour idle or 30 days; deactivation ends them; sign out deletes the row | S2 | `load_session()`, `sign_out()`, `sign_out_everywhere()` | `test_a_session_ends_after_an_hour_without_requests`, `test_activity_keeps_a_session_alive_but_never_past_30_days`, `test_deactivating_a_person_ends_their_session`, `test_signing_out_everywhere_cannot_reach_another_companys_sessions`, `test_users_api.py::test_deactivating_ends_every_session_and_lists_upcoming_shifts`, `test_signing_someone_out_everywhere` |
| Sensitive actions need the password entered in this session within 5 minutes; a re-entry counts only in its own session | S2 | `require_reauth()` in `app/auth/reauth.py`; `holds_admin_level()` in `app/authz/check.py` decides whether deactivating someone, or creating a setup or reset link for them, is sensitive | `test_reauth_api.py::test_sensitive_actions_need_a_reentry_in_the_last_five_minutes`, `test_reauth.py::test_a_reentry_counts_only_in_its_own_session`, `test_users_api.py::test_deactivating_an_admin_level_holder_needs_the_password_again`, `test_a_custom_role_with_an_admin_level_permission_counts_too`, `test_deactivating_an_ordinary_employee_needs_no_reentry`, `test_password_links.py::test_a_link_for_an_administrator_needs_the_password_entered_again`, `test_a_link_for_someone_without_admin_rights_needs_no_reentry` |
| Changing your password needs the current one, ends every session, and rotates this browser's token without extending it | S2, S3 | `change_password()` in `app/auth/reauth.py` | `test_reauth.py::test_a_copied_cookie_stops_working_when_the_password_changes`, `test_a_session_alone_cannot_change_the_password`, `test_reauth_api.py::test_changing_the_password_signs_out_every_other_browser` |
| Lockouts at 5, 10, and 15+ wrong passwords (15 min, 30 min, 1 hour, never longer), reset by success or a day without failures; no password is tried while locked; re-entry failures count too; parallel guesses are each counted | S1, D1 | `app/auth/limits.py`, `_check_and_start()` in `app/auth/sessions.py`, `app/auth/reauth.py` | `test_lockouts.py` (AU2), `test_limits.py`, `check_migrations.py` (`_lockout_race_problems`) |
| 20 sign-in attempts a minute per address (link redemptions count too, and sign-up requests once sign-up is built), 300 requests a minute per session, then 429 with `Retry-After`; a made-up `X-Forwarded-For` changes nothing | S1, D1 | `RateLimit` in `app/auth/limits.py`; `FORWARDED_ALLOW_IPS` in `docker-compose.yml` | `test_lockouts.py::test_twenty_sign_in_attempts_a_minute_from_one_address`, `test_a_made_up_forwarded_header_does_not_escape_the_limit`, `test_a_session_may_make_300_requests_a_minute`, `test_password_links.py::test_twenty_tries_a_minute_from_one_address` |
| Setup and reset links: random 256-bit token after the `#`, only its SHA-256 stored, 48 hours, works once, a newer link cancels the older; one answer for every link that does not work; the new password follows the company's minimum length; using one ends every session of the person | S5, I5 | `app/auth/links.py`, `app/modules/password_links/router.py` | `test_password_links.py` (AU7, AU8), `check_migrations.py` (`_link_race_problems`) |
| Links only from someone with `user.manage` who is above the person, never for oneself | E3 | `create_link()` calls `authorize()` | `test_password_links.py::test_nobody_creates_a_link_for_themselves`, `test_an_administrator_creates_links_only_for_people_below_them` |

### Forged requests (CSRF)

| Protection | Threats | Where | Tests |
|---|---|---|---|
| Origin check on every POST, PUT, PATCH, and DELETE, sign-in included | S4 | `CsrfMiddleware` in `app/auth/csrf.py` | `test_csrf.py::test_forged_changes_are_refused`, `test_a_forged_sign_in_from_another_site_is_refused`, `test_the_configured_application_address_is_the_only_accepted_origin` |
| CSRF token: `HMAC-SHA256(csrf_key, session token hash)` in `X-CSRF-Token`, compared in constant time | S4 | `csrf_token()`, `CsrfMiddleware` | `test_another_sessions_token_does_not_work`, `test_the_token_comes_with_the_session_and_cannot_be_made_without_the_key` |
| Sign-in and link redemption act outside any session, so they get the Origin check only: a leftover session cookie never blocks them | S4 | `ORIGIN_ONLY` in `app/auth/csrf.py` | `test_signing_in_again_works_with_a_leftover_cookie_and_no_token`, `test_password_links.py::test_a_link_works_in_a_browser_with_an_old_session_cookie`, `test_a_redemption_from_another_site_is_still_refused` |
| `SameSite=Strict` session cookie | S4 | as above | `test_the_cookie_has_every_protective_attribute` |
| GET never changes anything | S4 | every router | `test_reading_needs_neither_token_nor_origin` |

### Input, output, and errors

| Protection | Threats | Where | Tests |
|---|---|---|---|
| Database access only through SQLAlchemy with bound parameters, never SQL text | T1 | every `repository.py` ([0022](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0022-sqlalchemy-and-alembic.md)) | `test_shifts.py::test_text_fields_come_back_exactly_as_written` |
| Typed request fields with maximum lengths; lists limited to 31 days and 200 items | T2, D2 | `schemas.py`, `list_shifts()` | `test_shifts.py::test_oversized_or_malformed_list_requests_are_refused`, `test_thirty_one_days_is_allowed` |
| One error format; a 422 never echoes the submitted value; a 500 shows only an `error_id` | I4, T5 | `app/core/errors.py` | `tests/unit/test_errors.py` |
| API answers are never stored by browsers or proxies (`Cache-Control: no-store`) | I6 | `app/core/caching.py` | `test_no_store.py` |
| Security headers on every answer, API included: CSP (`default-src 'self'`, `frame-ancestors 'none'`), `nosniff`, Referrer-Policy, HSTS over HTTPS | T5 | frontend `nginx/nginx.conf` (set for the whole server, so `/api` answers get them too) | frontend `tests/integration/smoke.spec.js` (checks a page's headers) |
| API docs only outside production | I4 | `create_app()` in `app/main.py` | `tests/unit/test_main.py` |
| Detection records attack-like input and never blocks, changes, or delays a request or its answer; inspection runs after the answer, in a worker thread (DE1, DE2) | R4 | `app/modules/security/layer.py`, `app/modules/security/worker.py` | `test_detection_layer.py::test_an_attack_string_gets_the_same_answer`; `tests/unit/test_detection_layer.py::test_a_failure_in_the_layer_never_reaches_the_request` |
| Secrets never enter detection: no headers, credential routes marked `detection_skip`, secret-named fields left out at any depth, credential fields typed `SecretStr` (DE3) | I8 | `collect()` and `detection_skip` in `app/modules/security/layer.py` | `test_detection_layer.py::test_headers_are_never_collected`, `test_sign_in_is_never_inspected`, `test_secret_named_fields_are_left_out_at_any_depth`; `tests/unit/test_detection_layer.py::test_every_credential_field_is_kept_out_of_detection` |
| A queue of 200 copies that drops and counts instead of waiting; values capped while copying (DE4, DE11) | D4, D5 | `DetectionWorker` in `app/modules/security/worker.py` | `test_detection_layer.py::test_a_full_queue_never_slows_a_request`, `test_one_session_cannot_fill_the_table` |
| An event goes to a company only through a session `signed_in()` checked; the address is the sender's (DE8, DE9) | I1, S6 | `note_identity()` in `app/modules/security/layer.py`, `signed_in()` in `app/auth/dependencies.py` | `test_detection_layer.py::test_a_request_without_a_session_lands_only_in_the_platform_table`, `test_a_signed_in_request_lands_only_in_the_sessions_company`, `test_the_address_is_the_senders` |

### Audit log

| Protection | Threats | Where | Tests |
|---|---|---|---|
| Each action and its entry are saved in one transaction | R1 | `record()` in `app/audit/record.py`, called by each service | `tests/unit/test_audit_record.py` |
| HMAC-signed chain per company; the key is outside the database | T4, R2 | `app/audit/signing.py` | `test_audit_log.py::test_editing_an_entry_in_the_database_is_detected`, `test_removing_an_entry_is_detected`, `test_a_plain_hash_cannot_repair_an_edited_chain` |
| The chain comes from the session's company, never from the caller | T4, I1 | `record()` | `test_audit_log.py::test_a_company_cannot_write_into_another_companys_chain` |
| No passwords, tokens, secrets, or hashes in entries | I5 | `_check_details()` | `test_audit_log.py::test_no_entry_can_contain_a_password_token_or_hash` |
| Verification: numbering, links, signatures, and the chain's end against its head; the first bad entry is named | T4, R2 | `verify_chain()` in `app/audit/verify.py` | `tests/unit/test_audit_verify.py` (edited, removed, inserted, cut-off entries; older keys) |
| On-demand check of one's own company's chain only, with `audit.verify`; a failure becomes a security event, shown on the security page, even when the head is damaged | T4, I1 | `POST /api/audit/verify`, `app/modules/audit_log/service.py` | `tests/security/test_audit_verify.py` |
| Nightly check of every chain, and each head copied to the application log; a damaged chain never stops the others | T4, R2 | `app/jobs/verify_audit_log.py` (scheduled on the host, runs in the API image) | `test_audit_verify.py::test_the_nightly_check_covers_every_chain_and_copies_the_heads`, `test_the_nightly_check_reports_a_damaged_head_and_goes_on`, `test_a_chain_that_cannot_be_checked_fails_without_stopping_the_others`; `test_compose.py::test_the_nightly_audit_check_runs_in_the_api_image` |
| Separate database users: the application user may only read and write data, per table, and only add to the audit log; the migrations user changes the structure and is never given to the API | T4, R2, D3, P4 | `app/db/grants.py`, `migrations/env.py`, `docker/mysql/init/01-users.sh`, the `migrate` tool in `docker-compose.yml` | `check_migrations.py` (`_grant_problems`), `tests/unit/test_grants.py`, `tests/integration/test_compose.py` |

## Cryptography

Every key, algorithm, and random value the backend uses (ASVS V11.1.2).

| What | Algorithm | Key or secret | Where it is kept | Used for |
|---|---|---|---|---|
| Password hashes | Argon2id, 64 MiB, 3 passes, 4 lanes, random salt per hash | none | hashes in `users.password_hash` | checking passwords at sign-in |
| Session tokens | 32 random bytes (`secrets.token_bytes`); SHA-256 of the token stored | none | token in the browser's cookie only; hash in `sessions.token_hash` | finding the session on each request |
| CSRF tokens | HMAC-SHA256 over the session token's hash | `CSRF_KEY`, at least 32 characters | environment only; the API refuses to start without it, or with the audit key's value | proving a changing request came from our pages |
| Audit log signatures | HMAC-SHA256 over each entry's canonical JSON plus the previous signature | `AUDIT_SIGNING_KEY`, at least 32 characters, with `AUDIT_KEY_ID` | environment only; the key ID is stored with each entry | making changes to the log detectable |
| Record IDs | UUIDv7 ([0019](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0019-uuidv7-ids.md)) | none | the database | identifying records; never used as secrets |
| List cursors | base64url-encoded JSON (not encrypted, not secret) | none | the answer | the next page of a list |

Keys are generated with `python -c "import secrets; print(secrets.token_urlsafe(32))"` (`.env.example`). How keys are rotated and retired is not written down yet (audit finding A2, #93).

## Logs

Where the backend writes logs, and what goes into each (ASVS V16.1.1).

| Log | Format and place | What goes in | Never in it | Who can read it | Kept for |
|---|---|---|---|---|---|
| Application log | one JSON object per line on standard output (`app/core/logging.py`); Docker keeps it with the container | unexpected errors (type, `error_id`, file and line), sign-ins for unknown emails (without the email); uvicorn's start-up messages and one line per request (method, path, status, the proxy's address) | personal details, passwords, tokens, exception messages outside development ([0035](https://github.com/workforce-ops-app/.github/blob/main/docs/decisions/0035-logging-unexpected-errors.md)) | whoever runs the containers | until the container is removed (hosting will decide) |
| Audit log | `audit_events` table, one signed chain per company plus a platform chain ([audit log](../architecture/audit-log.md)) | who did what to which record, when; sign-ins and failed sign-ins; every shift change | passwords, tokens, secrets, hashes, shift text (only the names of changed fields) | nobody through the API yet (the viewer needs `audit.view`, Phase 4); the database account | forever |
| Security events (filled by the detection layer, DT4) | `security_events` and `platform_security_events` tables ([detection](../features/detection.md)) | attack-like input the detector matched: type, pattern, field, route, sender, address, a 200 character excerpt; later refused requests (#92) | passwords, tokens, cookies, the CSRF and `Authorization` headers | owners and administrators of the company (`security.view`); platform events (`platform_security_events`, no company or person): nobody through the API yet (`GET /api/security-events` reads only `security_events`, through the company filter; `test_security_events_api.py`) | 1 year |
| nginx access log | standard output of the frontend container | each request's method, path, status, and address | request bodies, cookies | whoever runs the containers | until the container is removed |

Refused requests (403, cross-company 404, forged requests) are not logged yet (audit finding A1, #92).
