"""Baseline: the starting point of the migration history; creates no tables.

Revision: 0001
Revises: (none)

Every later migration builds on this one. Tables arrive with the features that need them
(Phase 2 onward), one migration per pull request (contributor guide, modularity).
"""

from collections.abc import Sequence

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
