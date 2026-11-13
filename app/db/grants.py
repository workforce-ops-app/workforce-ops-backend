"""What the application's database user may do with each table (T2, #43).

The application and the migrations use two different MySQL users:

- the **migrations user** changes the structure (CREATE, ALTER, DROP) and hands out the
  rights below; only Alembic uses it, never the running API;
- the **application user** may only read and write data, and only as listed here.

So a break-in through the API gets the application user: it cannot drop or change a
table, and it cannot edit or remove audit entries (audit-log.md, protection in the
database). The signatures already make such an edit detectable; the grants prevent it.

Why one list per table, and not one grant for the whole database: MySQL cannot take a
right away from a single table once it was granted for the whole database. The audit
tables must not allow UPDATE or DELETE, so every table gets its own grant.

How a new table gets its rights: add it to APP_RIGHTS in the same pull request as its
migration. migrations/env.py calls grant_app_rights() at the end of every
`alembic upgrade`, which makes the database match this list. A table missing from the
list stops the upgrade with an error and has no rights at all (closed, not open), and
tests/unit/test_grants.py fails before that, as soon as the model exists.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy import Connection

# The data rights of an ordinary table. DELETE is included: sessions, team memberships,
# and similar rows are removed by the app. That records are archived instead of deleted
# (decision 0020) is a rule of the code, not of these grants.
DATA = frozenset({"SELECT", "INSERT", "UPDATE", "DELETE"})

# Every table the application uses, with exactly the rights it gets. Keep it in the
# order of the migrations that created the tables.
APP_RIGHTS: dict[str, frozenset[str]] = {
    "companies": DATA,
    "departments": DATA,
    "users": DATA,
    "teams": DATA,
    "team_members": DATA,
    "permissions": DATA,
    "roles": DATA,
    "role_permissions": DATA,
    "role_assignments": DATA,
    "sessions": DATA,
    # The audit log: entries are only added and read, never changed or removed.
    "audit_events": frozenset({"SELECT", "INSERT"}),
    # A chain's head is added with its first entry, then moved on with each new entry
    # (UPDATE; also needed to lock it with SELECT ... FOR UPDATE). Never removed.
    "audit_chain_heads": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "shifts": DATA,
    "reporting_lines": DATA,
    # Security events are added and read, and removed after a year by the clean-up job
    # (scripts/remove_old_security_events.py); never changed.
    "security_events": frozenset({"SELECT", "INSERT", "DELETE"}),
    "platform_security_events": frozenset({"SELECT", "INSERT", "DELETE"}),
}

# Alembic's own bookkeeping: only the migrations user needs it.
NOT_FOR_THE_APP = frozenset({"alembic_version"})

# Every right MySQL can give on one table. Whatever a table's entry does not list is
# taken away, so a right granted by hand (or left over from an older setup) is removed.
TABLE_RIGHTS = frozenset(
    {
        "ALTER", "CREATE", "CREATE VIEW", "DELETE", "DROP", "INDEX", "INSERT",
        "REFERENCES", "SELECT", "SHOW VIEW", "TRIGGER", "UPDATE",
    }
)  # fmt: skip

# Names go into the SQL text itself (MySQL cannot take a table or user name as a bound
# parameter), so only plain names are accepted: letters, digits, and underscores.
_PLAIN_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")


def _plain(name: str, what: str) -> str:
    """The name unchanged if it is a plain name; otherwise refuse it."""
    if not _PLAIN_NAME.fullmatch(name):
        raise ValueError(f"the {what} name {name!r} is not a plain name")
    return name


def grant_statements(database: str, app_user: str, tables: set[str]) -> list[str]:
    """The SQL that gives the application user exactly APP_RIGHTS on these tables.

    For each table: first grant what is listed, then take away every other right, so
    the app never loses a right it needs, not even for a moment while this runs. Last,
    take away any right on the whole database (an older setup gave one), which would
    otherwise still allow everything below it.
    """
    db = _plain(database, "database")
    user = f"'{_plain(app_user, 'user')}'@'%'"
    statements = []
    for table in sorted(tables):
        rights = APP_RIGHTS[table]
        target = f"`{db}`.`{_plain(table, 'table')}`"
        statements.append(f"GRANT {', '.join(sorted(rights))} ON {target} TO {user}")
        others = TABLE_RIGHTS - rights
        # IF EXISTS: a right the user does not have is skipped instead of being an error.
        statements.append(f"REVOKE IF EXISTS {', '.join(sorted(others))} ON {target} FROM {user}")
        statements.append(f"REVOKE IF EXISTS GRANT OPTION ON {target} FROM {user}")
    statements.append(f"REVOKE IF EXISTS ALL PRIVILEGES ON `{db}`.* FROM {user}")
    statements.append(f"REVOKE IF EXISTS GRANT OPTION ON `{db}`.* FROM {user}")
    return statements


def grant_app_rights(connection: Connection, app_user: str) -> list[str]:
    """Make the application user's rights match APP_RIGHTS; return the tables granted.

    Runs as the migrations user at the end of every upgrade (migrations/env.py). Refuses
    with an error when the database has a table the list does not mention: that table
    then has no rights for the app at all, and the person adding it learns why.
    """
    database = connection.execute(text("SELECT DATABASE()")).scalar_one()
    # Every table of this database (the migrations user can see all of them).
    existing = set(
        connection.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'"
            )
        ).scalars()
    )
    unlisted = existing - set(APP_RIGHTS) - NOT_FOR_THE_APP
    if unlisted:
        raise RuntimeError(
            "these tables have no entry in APP_RIGHTS (app/db/grants.py), so the "
            f"application user gets no rights on them: {', '.join(sorted(unlisted))}"
        )
    granted = existing & set(APP_RIGHTS)
    for statement in grant_statements(database, app_user, granted):
        connection.execute(text(statement))
    return sorted(granted)
