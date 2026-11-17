"""Setup and reset links take turns: which rows they lock, and in which order.

The tests run on SQLite, which has no row locks, so the locks themselves are tried on
MySQL (scripts/check_migrations.py, _link_race_problems). Here: that the code asks for
them, person first and link second, the same order in both creating and redeeming, so
two requests for one person wait for each other instead of deadlocking.
"""

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.auth.links import link_address
from app.auth.models import OneTimeToken
from app.modules.org.models import User
from tests.shift_data import BASE_URL, ShiftSetup, shifts

__all__ = ["shifts"]  # the fixture, imported so pytest finds it here


@pytest.fixture
def locks(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every row lock asked for with Session.get, in order, as "User" or "OneTimeToken"."""
    taken: list[str] = []
    real_get = Session.get

    def get(self: Session, entity: Any, ident: Any, **options: Any) -> Any:
        if options.get("with_for_update"):
            # A lock must also read the row fresh, or it could act on an old copy.
            assert options.get("populate_existing"), entity
            taken.append(entity.__name__)
        return real_get(self, entity, ident, **options)

    monkeypatch.setattr(Session, "get", get)
    return taken


def test_creating_a_link_locks_the_person(shifts: ShiftSetup, locks: list[str]) -> None:
    owner = shifts.browser("owner")
    locks.clear()  # signing in is not part of this
    assert owner.post(f"/api/users/{shifts.ids['newbie']}/setup-link").status_code == 201
    assert locks == [User.__name__]


def test_redeeming_locks_the_person_then_the_link(shifts: ShiftSetup, locks: list[str]) -> None:
    created = shifts.browser("owner").post(f"/api/users/{shifts.ids['newbie']}/setup-link")
    token = created.json()["link"].split("#token=", 1)[1]
    locks.clear()
    anonymous = TestClient(shifts.app, base_url=BASE_URL, headers={"Origin": BASE_URL})  # type: ignore[arg-type]
    response = anonymous.post(
        "/api/password-links/redeem",
        json={"token": token, "new_password": "a brand new long passphrase"},
    )
    assert response.status_code == 204
    assert locks == [User.__name__, OneTimeToken.__name__]


def test_the_link_address_puts_the_token_after_the_hash() -> None:
    address = link_address("https://workforce.example/", "abc")
    assert address == "https://workforce.example/set-password.html#token=abc"
