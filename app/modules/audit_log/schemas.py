"""The answer shape of a verification (docs/architecture/audit-log.md, verification)."""

from pydantic import BaseModel


class VerificationOut(BaseModel):
    """What checking the company's audit chain found.

    ok is true only if every entry and the end of the chain checked out. When it is
    false, first_bad_seq is the first entry that failed (or, when the newest entries are
    missing, the entry the chain head expected) and problem says what was wrong there.
    """

    ok: bool
    checked: int
    last_seq: int
    first_bad_seq: int | None
    problem: str | None
