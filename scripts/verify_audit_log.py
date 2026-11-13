"""Check every audit chain, and copy each chain's head to the application log
(docs/architecture/audit-log.md, verification).

    python -m scripts.verify_audit_log

Run nightly. Until the application has its own background jobs, schedule it on the host
like scripts/remove_old_security_events.py: a cron line, once a night, that changes into
the backend folder (the one with docker-compose.yml) and then runs

    docker compose exec -T api python -m scripts.verify_audit_log

Each chain is checked from its first entry (app/audit/verify.py), and the result is
recorded in that chain as `audit.verified`. Each chain's head is written to the log as one
JSON line ("audit chain head", with chain_id, last_seq, and last_signature): keep those
lines outside the database, because comparing them with an earlier night's shows if the
database was ever put back to an older state. A failed chain also writes an error line
and a platform security event.

Exits with 1 if any chain failed (so cron or a monitor can raise the alarm), 0 otherwise.
Needs AUDIT_SIGNING_KEY (and AUDIT_PREVIOUS_KEYS after a key change).
"""

import sys

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.db.session import get_engine
from app.modules.audit_log.service import verify_every_chain


def main() -> int:
    # JSON lines, as the API writes them, so the head copies land in the same log.
    configure_logging(get_settings().log_level)
    results = verify_every_chain(get_engine())
    failed = [result for result in results if not result.ok]
    print(f"checked {len(results)} audit chains: {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
