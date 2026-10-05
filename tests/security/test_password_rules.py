"""AU1: the passwords attackers guess first are refused (authentication.md, threat S1).

An attacker trying to break into an account starts with short passwords, the most common
ones, and ones built from the person's or company's name. Each test tries such a password
and expects it refused; long passphrases, which are hard to guess, are accepted.
"""

import pytest

from app.auth.passwords import PasswordRejected, check_password, hash_password

PERSON = {
    "company_name": "Northwind Cafe",
    "email": "ana.diaz@example.com",
    "display_name": "Ana Diaz",
}


def refused(password: str, **overrides: object) -> bool:
    """Whether the rules refuse a password for Ana Diaz at Northwind Cafe."""
    try:
        check_password(password, **{**PERSON, **overrides})  # type: ignore[arg-type]
    except PasswordRejected:
        return True
    return False


@pytest.mark.parametrize("password", ["password", "Summer2026!", "fourteen chars"])
def test_short_passwords_are_refused(password: str) -> None:
    # Under 15 characters: quick to try every possibility.
    assert refused(password)


# Real entries of the list: a keyboard walk, a famous name, and a number pattern.
@pytest.mark.parametrize("password", ["asdfghjklzxcvbnm", "cristianoronaldo", "111222333444555"])
def test_common_passwords_are_refused_in_any_case(password: str) -> None:
    # From the most-used passwords list, also typed in capitals.
    assert refused(password)
    assert refused(password.upper())


@pytest.mark.parametrize(
    "password",
    [
        "Northwind Cafe forever and ever",  # the company's name
        "i love NorthwindCafe so much",  # the company's name without the space
        "my name is ana diaz and hi",  # the display name
        "ana.diaz@example.com is me",  # the email name
        "the diaz family garden plot",  # a word of the display name
    ],
)
def test_passwords_built_from_names_are_refused(password: str) -> None:
    assert refused(password)


def test_a_company_can_only_raise_the_minimum() -> None:
    # A company asking for 20 characters gets 20; asking for 8 still gets 15.
    assert refused("seventeen letters", min_length=20)
    assert refused("fourteen chars", min_length=8)


@pytest.mark.parametrize(
    "password",
    [
        "a calm river bends at dusk",  # a passphrase with spaces
        "Tacos on the 3rd floor at noon",  # no "must contain" rules either way
        "café olé ☕ before the morning rush",  # accents and emoji are fine
    ],
)
def test_long_passphrases_are_accepted(password: str) -> None:
    assert not refused(password)


def test_the_stored_hash_never_contains_the_password() -> None:
    # What is stored is an Argon2id hash with its settings and a random salt, never the
    # password itself.
    password = "a calm river bends at dusk"
    stored = hash_password(password)

    assert password not in stored
    assert stored.startswith("$argon2id$v=19$m=65536,t=3,")
    # The same password hashed twice gives two different hashes (different salts), so
    # equal passwords cannot be spotted in a stolen database.
    assert hash_password(password) != stored
