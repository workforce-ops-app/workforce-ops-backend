"""Add asking coworkers for cover or a swap on a time-off request.

Revision: 0015
Revises: 0014

As in docs/features/coverage.md and app/modules/time_off/models.py:

1. time_off_requests gains offers_close_at and sent_up_at, and the status "collecting"
   (the CHECK is dropped and added again with the new list).
2. coverage_offers: one coworker's answer about one shift of a request. Company-owned:
   the request, both shifts, and the coworker are linked through (company_id, <x>_id), so
   an offer can never point into another company (tenancy layer 2). A CHECK keeps a swap
   shift on swaps only.
3. The permission coverage.respond_self, given to the four starting roles of every company
   that already exists (new companies get it from app/authz/roles.py).

Types are written out here (BINARY(16), DATETIME(6)) instead of importing them from the
app, so this migration keeps working even if the app's code changes later.
"""

from collections.abc import Sequence
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_STATUSES = "status IN ('pending', 'escalated', 'approved', 'denied', 'cancelled')"
NEW_STATUSES = "status IN ('collecting', 'pending', 'escalated', 'approved', 'denied', 'cancelled')"

PERMISSION = "coverage.respond_self"
DESCRIPTION = "Offer to cover or swap a coworker's shift during their time off"
STARTING_ROLES = ("owner", "administrator", "manager", "employee")


def _moment(name: str, nullable: bool) -> sa.Column:
    """A moment in UTC with microseconds: DATETIME(6) in MySQL (decision 0021)."""
    return sa.Column(
        name, sa.DateTime().with_variant(mysql.DATETIME(fsp=6), "mysql"), nullable=nullable
    )


def upgrade() -> None:
    # Step 1: the request's new columns and status.
    with op.batch_alter_table("time_off_requests") as table:
        table.add_column(_moment("offers_close_at", True))
        table.add_column(_moment("sent_up_at", True))
        table.drop_constraint("time_off_requests_status", type_="check")
        table.create_check_constraint("time_off_requests_status", NEW_STATUSES)

    # Step 2: the offers.
    op.create_table(
        "coverage_offers",
        sa.Column("id", sa.BINARY(16), primary_key=True),
        sa.Column("company_id", sa.BINARY(16), nullable=False, index=True),
        sa.Column("time_off_request_id", sa.BINARY(16), nullable=False),
        sa.Column("shift_id", sa.BINARY(16), nullable=False),
        sa.Column("offered_by", sa.BINARY(16), nullable=False),
        sa.Column("answer", sa.String(8), nullable=False),
        sa.Column("swap_shift_id", sa.BINARY(16), nullable=True),
        sa.Column("status", sa.String(10), nullable=False),
        _moment("created_at", False),
        _moment("updated_at", False),
        sa.ForeignKeyConstraint(["company_id"], ["companies.id"]),
        sa.UniqueConstraint("company_id", "id"),
        sa.ForeignKeyConstraint(
            ["company_id", "time_off_request_id"],
            ["time_off_requests.company_id", "time_off_requests.id"],
        ),
        sa.ForeignKeyConstraint(["company_id", "shift_id"], ["shifts.company_id", "shifts.id"]),
        sa.ForeignKeyConstraint(["company_id", "offered_by"], ["users.company_id", "users.id"]),
        sa.ForeignKeyConstraint(
            ["company_id", "swap_shift_id"], ["shifts.company_id", "shifts.id"]
        ),
        sa.UniqueConstraint(
            "company_id",
            "time_off_request_id",
            "shift_id",
            "offered_by",
            name="uq_coverage_offers_answer",
        ),
        sa.Index("ix_coverage_offers_company_shift", "company_id", "shift_id"),
        sa.Index("ix_coverage_offers_company_offered_by", "company_id", "offered_by"),
        sa.Index("ix_coverage_offers_company_swap_shift", "company_id", "swap_shift_id"),
        sa.CheckConstraint("answer IN ('cover', 'swap', 'decline')", name="coverage_offers_answer"),
        sa.CheckConstraint(
            "status IN ('offered', 'chosen', 'not_chosen', 'dropped')",
            name="coverage_offers_status",
        ),
        sa.CheckConstraint(
            "(answer = 'swap') = (swap_shift_id IS NOT NULL)", name="coverage_offers_swap"
        ),
    )

    # Step 3: the new permission, then a grant of it on every company's starting roles
    # that does not have it yet (so running this on a fresh database is harmless too).
    connection = op.get_bind()
    known = connection.execute(
        sa.text("SELECT 1 FROM permissions WHERE code = :code"), {"code": PERMISSION}
    ).first()
    if known is None:
        connection.execute(
            sa.text(
                "INSERT INTO permissions (code, module, description) "
                "VALUES (:code, 'time_off', :description)"
            ),
            {"code": PERMISSION, "description": DESCRIPTION},
        )
    now = datetime.now(UTC).replace(tzinfo=None)
    connection.execute(
        sa.text(
            "INSERT INTO role_permissions "
            "(role_id, permission_code, company_id, created_at, updated_at) "
            "SELECT r.id, :code, r.company_id, :now, :now FROM roles r "
            "WHERE r.built_in IN :roles AND NOT EXISTS ("
            "SELECT 1 FROM role_permissions rp "
            "WHERE rp.role_id = r.id AND rp.permission_code = :code)"
        ).bindparams(sa.bindparam("roles", expanding=True)),
        {"code": PERMISSION, "now": now, "roles": list(STARTING_ROLES)},
    )


def downgrade() -> None:
    # The grants and the permission go first (the permission is referenced by them).
    connection = op.get_bind()
    connection.execute(
        sa.text("DELETE FROM role_permissions WHERE permission_code = :code"),
        {"code": PERMISSION},
    )
    connection.execute(sa.text("DELETE FROM permissions WHERE code = :code"), {"code": PERMISSION})
    op.drop_table("coverage_offers")
    # Requests still collecting cannot keep a status the old CHECK refuses: they go up.
    connection.execute(
        sa.text("UPDATE time_off_requests SET status = 'pending' WHERE status = 'collecting'")
    )
    with op.batch_alter_table("time_off_requests") as table:
        table.drop_constraint("time_off_requests_status", type_="check")
        table.create_check_constraint("time_off_requests_status", OLD_STATUSES)
        table.drop_column("sent_up_at")
        table.drop_column("offers_close_at")
