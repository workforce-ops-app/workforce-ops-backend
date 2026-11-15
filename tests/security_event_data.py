"""Shared setup for the security page tests: the shift setup (tests/shift_data.py), an
Administrator, and security events in both companies.

Company A ("Northwind", America/Chicago), events by age:
    ana    detection.xss            1 hour ago    excerpt <img src=x onerror=alert(1)>
    ana    detection.summary        2 days ago    count 15 (the rate cap held 15 back)
    chef   detection.sql_injection  10 days ago
    ana    detection.path_traversal 40 days ago   (outside both summary windows)
Company B ("Summit"):
    b_ana  detection.xss            1 hour ago    excerpt THEIRS-<script>
Platform (nobody signed in):
            detection.command_injection, 1 hour ago, excerpt PLATFORM-ONLY

Events are inserted with the security module's own insert functions, as the writer does,
so the company filter and the (company_id, user_id) key apply to them.
"""

import uuid
from collections.abc import Iterator
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.audit import Actor
from app.auth.passwords import hash_password
from app.authz.models import Role
from app.authz.roles import assign_role
from app.db.base import utcnow
from app.modules.org.models import User
from app.modules.security import repository
from tests.shift_data import PASSWORD, ShiftSetup, shifts

__all__ = ["events", "shifts"]

XSS_EXCERPT = "<img src=x onerror=alert(1)>"
THEIR_EXCERPT = "THEIRS-<script>"
PLATFORM_EXCERPT = "PLATFORM-ONLY"


def _row(kind: str, user_id: uuid.UUID, age: timedelta, **extra: object) -> dict:
    """One event row as the writer builds it."""
    return {
        "kind": kind,
        "user_id": user_id,
        "occurred_at": utcnow() - age,
        "pattern_id": extra.pop("pattern_id", None),
        "field": "body.note",
        "method": "PATCH",
        "route": "/api/shifts/{shift_id}",
        "client_address": "203.0.113.7",
        "request_id": "req-1",
        "excerpt": extra.pop("excerpt", "' OR 1=1 --"),
        "count": extra.pop("count", 1),
    }


@pytest.fixture
def events(shifts: ShiftSetup) -> Iterator[ShiftSetup]:
    """The shift setup with an Administrator and the events above."""
    ids = shifts.ids
    with shifts.db() as db:
        admin = User(
            email="admin@northwind.example",
            display_name="Admin",
            department_id=ids["front"],
            password_hash=hash_password(PASSWORD),
        )
        db.add(admin)
        db.flush()
        ids["admin"] = admin.id
        role = db.scalars(select(Role).where(Role.built_in == "administrator")).one()
        assign_role(db, Actor.system(), user_id=admin.id, role=role, scope_type="company")
        db.commit()

    hour, day = timedelta(hours=1), timedelta(days=1)
    repository.insert_company_events(
        shifts.engine,
        shifts.company_a,
        [
            _row("detection.xss", ids["ana"], hour, pattern_id="XSS-02", excerpt=XSS_EXCERPT),
            _row("detection.summary", ids["ana"], 2 * day, excerpt=None, count=15),
            _row("detection.sql_injection", ids["chef"], 10 * day, pattern_id="SQLI-01"),
            _row("detection.path_traversal", ids["ana"], 40 * day, pattern_id="PATH-01"),
        ],
    )
    repository.insert_company_events(
        shifts.engine,
        shifts.company_b,
        [_row("detection.xss", ids["b_ana"], hour, pattern_id="XSS-01", excerpt=THEIR_EXCERPT)],
    )
    platform = _row("detection.command_injection", ids["ana"], hour, excerpt=PLATFORM_EXCERPT)
    del platform["user_id"]  # the platform table has no person
    repository.insert_platform_events(shifts.engine, [platform])
    yield shifts
