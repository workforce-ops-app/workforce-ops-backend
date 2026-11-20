"""Approval requests: changes that wait for someone above the requester to agree
(data-model.md, approval_requests; decisions 0029 and 0032).

A shared layer, like the audit log, because several features use the same record: a role
given at the granter's own level (now), owner changes and account changes (later), and
time off and coverage requests (their own slices). Each feature says what its kind of
request does once approved.
"""
