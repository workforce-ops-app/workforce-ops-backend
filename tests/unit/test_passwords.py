"""How the password module behaves for the application's own code (app/auth/passwords.py).

The attacker's view (AU1: refused guesses) is in tests/security/test_password_rules.py.
"""

import unicodedata

import pytest
from argon2 import PasswordHasher

from app.auth import passwords
from app.auth.passwords import (
    MAX_LENGTH,
    PasswordRejected,
    check_password,
    common_passwords,
    hash_password,
    needs_rehash,
    normalize,
    verify_password,
)

PERSON = {
    "company_name": "Northwind Cafe",
    "email": "ana.diaz@example.com",
    "display_name": "Ana Diaz",
}


def test_verify_accepts_the_right_password_only() -> None:
    stored = hash_password("a calm river bends at dusk")

    assert verify_password(stored, "a calm river bends at dusk")
    assert not verify_password(stored, "a calm river bends at dusk!")
    assert not verify_password(stored, "A calm river bends at dusk")


def test_a_damaged_hash_simply_does_not_match() -> None:
    assert not verify_password("not a hash", "anything at all here")


def test_the_same_password_typed_differently_matches() -> None:
    # "é" as one character, or as "e" plus a combining accent: NFKC makes them one.
    composed = "café au lait every morning"
    decomposed = unicodedata.normalize("NFD", composed)
    assert composed != decomposed

    assert verify_password(hash_password(composed), decomposed)
    assert normalize(decomposed) == composed


def test_the_whole_password_is_hashed() -> None:
    # No truncation: two long passwords that differ only at the very end do not match.
    base = "word " * 25
    stored = hash_password(base + "a")

    assert not verify_password(stored, base + "b")


def test_too_long_passwords_are_refused_with_a_reason() -> None:
    with pytest.raises(PasswordRejected, match=str(MAX_LENGTH)):
        check_password("x" * (MAX_LENGTH + 1), **PERSON)


def test_reasons_are_plain_language() -> None:
    with pytest.raises(PasswordRejected, match="at least 15 characters"):
        check_password("too short", **PERSON)


def test_short_name_parts_do_not_block_passwords() -> None:
    # Words under 4 letters are not checked on their own ("Ana" is fine inside "banana"),
    # but the whole name still is.
    check_password("bananas are a great snack food", **PERSON)


def test_the_blocklist_is_loaded_lowercase_without_comments() -> None:
    entries = common_passwords()

    assert len(entries) > 300
    assert all(entry == entry.casefold() and not entry.startswith("#") for entry in entries)
    assert all(len(entry) >= 15 for entry in entries)


def test_hashes_made_with_older_settings_need_rehashing(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hash made with weaker settings (as if from an earlier version) is flagged, so
    # sign-in can re-hash it with the current ones.
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1).hash("a calm river bends")

    assert needs_rehash(weak)
    assert not needs_rehash(hash_password("a calm river bends"))
    # And it still verifies, so nobody is locked out by the change of settings.
    assert verify_password(weak, "a calm river bends")
    assert passwords._hasher.time_cost == 3
