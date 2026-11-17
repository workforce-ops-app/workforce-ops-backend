"""Request and response shapes for setup and reset links (authentication.md)."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class LinkCreated(BaseModel):
    """The answer of POST /api/users/{id}/setup-link and /reset-link.

    The address is shown once, to the administrator who passes it on; it is never stored
    or shown again (only the token's hash is kept).
    """

    purpose: Literal["setup", "reset"]
    # https://<host>/set-password.html#token=<the token>
    link: str
    # When the link stops working, in UTC.
    expires_at: datetime


class RedeemRequest(BaseModel):
    """POST /api/password-links/redeem. Both fields are SecretStr, so they are hidden when
    the request is printed or logged. The limits only stop oversized requests; the real
    checks are the link itself and the password rules."""

    model_config = ConfigDict(extra="forbid")

    token: SecretStr = Field(max_length=100)
    new_password: SecretStr = Field(max_length=1024)
