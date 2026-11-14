"""Shared setup for the people tests: the shift setup (tests/shift_data.py) plus an
Administrator and reporting lines, since acting on someone's account needs a place above
them in the chain (AZ5).

Company A ("Northwind"), on top of the people in tests/shift_data.py:
    admin   Administrator (company), home Front, reports to the owner

    Reporting lines:   owner
                         └ admin
                             └ chef
                                 ├ ana
                                 ├ cara
                                 ├ newbie
                                 ├ gone
                                 └ lead
                                     └ ben
    dana has no manager: only the owner is above her.

Company B ("Summit") is as in tests/shift_data.py: b_chef and b_ana, no lines.
"""

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import select

from app.audit import Actor
from app.audit.models import AuditEvent
from app.auth.passwords import hash_password
from app.authz.chain import add_reporting_line
from app.authz.models import Role
from app.authz.roles import assign_role
from app.modules.org.models import User
from tests.shift_data import PASSWORD, ShiftSetup, shifts

__all__ = ["people", "shifts"]

# (manager, employee) for every line in company A, in the order they are added.
LINES = [
    ("owner", "admin"),
    ("admin", "chef"),
    ("chef", "ana"),
    ("chef", "cara"),
    ("chef", "newbie"),
    ("chef", "gone"),
    ("chef", "lead"),
    ("lead", "ben"),
]


@pytest.fixture
def people(shifts: ShiftSetup) -> Iterator[ShiftSetup]:
    """The shift setup with an Administrator and the reporting lines above."""
    with shifts.db() as db:
        admin = User(
            email="admin@northwind.example",
            display_name="Admin",
            department_id=shifts.ids["front"],
            password_hash=hash_password(PASSWORD),
        )
        db.add(admin)
        db.flush()
        shifts.ids["admin"] = admin.id
        role = db.scalars(select(Role).where(Role.built_in == "administrator")).one()
        assign_role(
            db, Actor.system(), user_id=admin.id, role=role, scope_type="company", scope_id=None
        )
        for manager, employee in LINES:
            add_reporting_line(
                db,
                Actor.system(),
                manager_id=shifts.ids[manager],
                employee_id=shifts.ids[employee],
            )
        db.commit()
    yield shifts


def actions(setup: ShiftSetup, prefix: str, company_id: uuid.UUID | None = None) -> list[str]:
    """The company's audit actions starting with prefix, oldest first."""
    chain = company_id or setup.company_a
    with setup.db(chain) as db:
        return list(
            db.scalars(
                select(AuditEvent.action)
                .where(AuditEvent.chain_id == chain, AuditEvent.action.like(f"{prefix}%"))
                .order_by(AuditEvent.seq)
            )
        )


def person(setup: ShiftSetup, name: str) -> User:
    """A person of company A (or B, for names starting b_) as they are in the database."""
    company = setup.company_b if name.startswith("b_") else setup.company_a
    with setup.db(company) as db:
        found = db.get(User, setup.ids[name])
        assert found is not None
        db.expunge(found)
        return found
