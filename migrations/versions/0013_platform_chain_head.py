"""Create the platform audit chain's head, empty, so it always exists.

Revision: 0013
Revises: 0012

Company sign-up (docs/features/organization.md) makes sign-ups take turns by locking the
platform chain's head row (SELECT ... FOR UPDATE) before it counts this hour's new
companies. A lock needs a row to hold: on a new platform, before the first platform
entry, there was no head yet, and MySQL then lets sign-ups sent together all pass the
lock, and stops all but one as deadlocks (scripts/check_migrations.py tries this). So the
head is created here, empty: entry number 0 and the all-zero signature, exactly the head
app/audit/record.py creates before a chain's first entry, and one the audit check
accepts (app/audit/verify.py: a head at 0 with no entries is an empty chain).

Values are written out here (the all-zero ID, 32 zero bytes) instead of importing them
from the app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The platform chain's ID (app/audit/models.py PLATFORM_CHAIN_ID: the all-zero UUID, as
# 16 bytes) and the signature a chain starts from (NO_SIGNATURE: 32 zero bytes).
PLATFORM_CHAIN_ID = bytes(16)
NO_SIGNATURE = bytes(32)


def upgrade() -> None:
    connection = op.get_bind()
    # Only if the platform has no head yet: on a platform that already recorded platform
    # entries, the head is in use and must not change.
    exists = connection.execute(
        sa.text("SELECT 1 FROM audit_chain_heads WHERE chain_id = :id"),
        {"id": PLATFORM_CHAIN_ID},
    ).first()
    if exists is None:
        now = datetime.now(UTC).replace(tzinfo=None)
        connection.execute(
            sa.text(
                "INSERT INTO audit_chain_heads"
                " (chain_id, company_id, last_seq, last_signature, created_at, updated_at)"
                " VALUES (:id, NULL, 0, :signature, :now, :now)"
            ),
            {"id": PLATFORM_CHAIN_ID, "signature": NO_SIGNATURE, "now": now},
        )


def downgrade() -> None:
    # Only an empty head goes: one with entries belongs to the audit log, which is kept.
    op.get_bind().execute(
        sa.text("DELETE FROM audit_chain_heads WHERE chain_id = :id AND last_seq = 0"),
        {"id": PLATFORM_CHAIN_ID},
    )
