"""Add the company_locks table.

Revision: 0015
Revises: 0014

As in app/modules/org/models.py (CompanyLock) and #198: the company's lock, taken by
chain.lock_reporting_lines(), moves from the company's row in companies to a row of its
own. Every audit entry refers to the companies row by a foreign key, and MySQL takes a
shared lock on that row for each such insert, so a request writing its audit entry used to
wait for whoever held the company's lock, and two requests could deadlock. Nothing refers
to a company_locks row.

One row per company: the table's key is the company's ID. Every company that exists now
gets its row here; new companies get theirs when they are created (_add_company_lock in
the model file).

Types are written out here instead of importing them from the app, so this migration keeps
working even if the app's code changes later.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "company_locks",
        sa.Column("company_id", sa.BINARY(16), nullable=False),
        sa.PrimaryKeyConstraint("company_id"),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
    )
    # A lock row for every company made before this migration.
    op.execute("INSERT INTO company_locks (company_id) SELECT id FROM companies")


def downgrade() -> None:
    op.drop_table("company_locks")
