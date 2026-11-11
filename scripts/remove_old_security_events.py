"""Remove security events older than a year (data model, retention).

    python -m scripts.remove_old_security_events

Run nightly. Until the application has its own background jobs (the first one is planned
in Phase 2, docs/architecture/README.md), schedule it on the host: for example a cron
line, once a night, that changes into the backend folder (the one with
docker-compose.yml; cron starts in the home folder) and then runs

    docker compose exec -T api python -m scripts.remove_old_security_events

Running it more often, or twice, is harmless: it only removes rows past the year, from
both security event tables (app/modules/security/writer.py, remove_old_events).
"""

import sys

from app.db.session import get_engine
from app.modules.security.writer import remove_old_events


def main() -> int:
    # Each company's rows are removed in that company's own session (the company filter
    # adds its condition to the delete), then the platform's rows.
    company_rows, platform_rows = remove_old_events(get_engine())
    print(f"removed {company_rows} company and {platform_rows} platform security events")
    return 0


if __name__ == "__main__":
    sys.exit(main())
