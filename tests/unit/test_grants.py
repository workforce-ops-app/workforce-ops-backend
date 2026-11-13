"""The application user's rights (app/db/grants.py, #43), checked without a database.

scripts/check_migrations.py tries the rights on a real MySQL; these tests catch the
mistakes earlier: a new table without an entry, an audit table that allows changes, or a
name that could change the GRANT statements themselves.
"""

import subprocess
import sys

import pytest

from app.db.grants import APP_RIGHTS, TABLE_RIGHTS, grant_statements


def test_every_table_has_an_entry_and_every_entry_a_table() -> None:
    """A new table without an entry would get no rights; an entry without a table is
    left over from a table that is gone.

    Read in a fresh Python: other tests add their own example tables to Base.metadata
    (for example the tenancy tests' notes), which the app does not have.
    """
    script = (
        "from app.db.base import Base; from app.db.registry import import_all_models; "
        "import_all_models(); print(' '.join(sorted(Base.metadata.tables)))"
    )
    # A fixed command with this same Python; nothing comes from input.
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    assert set(APP_RIGHTS) == set(result.stdout.split())


def test_the_audit_log_cannot_be_changed_or_emptied() -> None:
    assert APP_RIGHTS["audit_events"] == {"SELECT", "INSERT"}
    assert APP_RIGHTS["audit_chain_heads"] == {"SELECT", "INSERT", "UPDATE"}


def test_security_events_are_never_changed() -> None:
    for table in ("security_events", "platform_security_events"):
        assert APP_RIGHTS[table] == {"SELECT", "INSERT", "DELETE"}


def test_no_table_gets_a_structure_right() -> None:
    structure = {"ALTER", "CREATE", "CREATE VIEW", "DROP", "INDEX", "REFERENCES", "TRIGGER"}
    for table, rights in APP_RIGHTS.items():
        assert rights <= TABLE_RIGHTS, table
        assert not rights & structure, table


def test_the_statements_grant_then_take_away_the_rest() -> None:
    statements = grant_statements("workforce_ops", "workforce_app", {"audit_events"})
    assert statements == [
        "GRANT INSERT, SELECT ON `workforce_ops`.`audit_events` TO 'workforce_app'@'%'",
        "REVOKE IF EXISTS ALTER, CREATE, CREATE VIEW, DELETE, DROP, INDEX, REFERENCES, "
        "SHOW VIEW, TRIGGER, UPDATE ON `workforce_ops`.`audit_events` FROM 'workforce_app'@'%'",
        "REVOKE IF EXISTS GRANT OPTION ON `workforce_ops`.`audit_events` FROM 'workforce_app'@'%'",
        # Last: a right on the whole database (from an older setup) is taken away.
        "REVOKE IF EXISTS ALL PRIVILEGES ON `workforce_ops`.* FROM 'workforce_app'@'%'",
        "REVOKE IF EXISTS GRANT OPTION ON `workforce_ops`.* FROM 'workforce_app'@'%'",
    ]


@pytest.mark.parametrize(
    ("database", "user"),
    [
        ("workforce_ops", "x'@'%' IDENTIFIED BY 'p"),  # a quote would end the user name
        ("workforce_ops`.* TO evil; --", "workforce_app"),  # a backtick ends the database
        ("workforce_ops", ""),
    ],
)
def test_names_that_could_change_the_sql_are_refused(database: str, user: str) -> None:
    with pytest.raises(ValueError, match="not a plain name"):
        grant_statements(database, user, {"users"})
