"""Passwords: which ones are allowed, and how they are stored (authentication.md, decision 0027).

Rules (NIST SP 800-63B rev. 4 for password-only sign-in):
- 15 to 128 characters (a company may raise the minimum, up to 64, never lower it);
- any characters, spaces and emoji included; Unicode is normalized (NFKC) first, so the
  same password typed on another device or keyboard matches;
- no "must contain a digit" rules and no forced changes; these make passwords weaker;
- refused if it is a common password, or contains the company's name or the person's
  email name or display name (compared ignoring case).

Storage: Argon2id, a deliberately slow, memory-hard hash (64 MiB, 3 passes). Each hash
carries its own random salt and its settings, so raising the settings later only means
re-hashing each password the next time its owner signs in (needs_rehash).

Why slow here but SHA-256 for session tokens: people choose short, guessable passwords,
so an attacker with a stolen database would try billions of guesses per second against a
fast hash; Argon2id makes every guess cost real time and memory. Session tokens are 32
random bytes that cannot be guessed at all, so a fast hash is enough for them.
"""

import re
import unicodedata
from functools import lru_cache
from importlib import resources

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_LENGTH = 15
MAX_LENGTH = 128

# Argon2id with the documented starting settings: 64 MiB of memory and 3 passes (about
# half a second on the server). The parallelism and output length are the library's
# defaults. The settings are written into every hash.
_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)


class PasswordRejected(ValueError):
    """A password that breaks the rules; the message explains why in plain words."""


def normalize(password: str) -> str:
    """The password in Unicode normal form NFKC, so different ways of typing the same
    character (for example a full-width letter, or an accented letter typed as two
    keystrokes) become the same text before checking and hashing."""
    return unicodedata.normalize("NFKC", password)


@lru_cache
def common_passwords() -> frozenset[str]:
    """The blocklist: common passwords of 15 characters or more, lowercase (read once).

    From the UK National Cyber Security Centre's 100,000 most-used passwords; shorter
    entries are left out of the file because the length rule already refuses them
    (app/auth/common-passwords.txt says where it comes from).
    """
    text = resources.files("app.auth").joinpath("common-passwords.txt").read_text("utf-8")
    return frozenset(line for line in text.splitlines() if line and not line.startswith("#"))


def _squash(text: str) -> str:
    """Lowercase without spaces or punctuation, so "Northwind Cafe" also catches
    "northwindcafe" and "Northwind-Cafe!" inside a password."""
    return re.sub(r"[\W_]+", "", normalize(text).casefold())


def _personal_words(company_name: str, email: str, display_name: str) -> set[str]:
    """The names a password may not contain: the company's name, the email name (the part
    before @), the display name, and each of their words of 4 letters or more."""
    email_name = email.split("@", 1)[0]
    words = {company_name, email_name, display_name}
    for name in (company_name, email_name, display_name):
        words.update(part for part in re.split(r"[\W_]+", name) if len(part) >= 4)
    # Compared squashed (lowercase, no spaces or punctuation); empty results are dropped.
    return {squashed for word in words if (squashed := _squash(word))}


def check_password(
    password: str,
    *,
    company_name: str,
    email: str,
    display_name: str,
    min_length: int = MIN_LENGTH,
) -> None:
    """Raise PasswordRejected if the password breaks a rule; return quietly if it is fine.

    min_length is the company's minimum (its own setting may raise it; never below 15).
    """
    # Lengths are counted after normalizing, on what will actually be hashed.
    text = normalize(password)
    minimum = max(min_length, MIN_LENGTH)
    if len(text) < minimum:
        raise PasswordRejected(
            f"Use at least {minimum} characters; a few words with spaces work well."
        )
    if len(text) > MAX_LENGTH:
        raise PasswordRejected(f"Use at most {MAX_LENGTH} characters.")

    # One of the passwords attackers try first.
    if text.casefold() in common_passwords():
        raise PasswordRejected("This password is too common; choose one that is less predictable.")

    # Easy to guess for anyone who knows the company or the person.
    squashed = _squash(text)
    if any(word in squashed for word in _personal_words(company_name, email, display_name)):
        raise PasswordRejected("Do not use your name, your email name, or the company's name.")


def hash_password(password: str) -> str:
    """The Argon2id hash to store, e.g. "$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>".

    The whole normalized password is hashed (no truncation, so long passphrases keep their
    strength). Check the rules first with check_password.
    """
    return _hasher.hash(normalize(password))


def verify_password(stored_hash: str, password: str) -> bool:
    """Whether a password matches a stored hash. Never raises for a wrong password or a
    damaged hash: both simply do not match."""
    try:
        return _hasher.verify(stored_hash, normalize(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Whether a hash was made with older (weaker) settings than the current ones. Sign-in
    (S2) re-hashes the password then, while it has the plain password in hand."""
    return _hasher.check_needs_rehash(stored_hash)
