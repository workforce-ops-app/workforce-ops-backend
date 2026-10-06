"""Request and response shapes for signing in and out (authentication.md, decision 0026)."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class SignInRequest(BaseModel):
    """POST /api/sessions. The limits only stop oversized requests; the real checks are the
    password rules (when a password is set) and the sign-in itself."""

    email: str = Field(max_length=254)
    password: str = Field(max_length=1024)


class SessionUser(BaseModel):
    id: uuid.UUID
    display_name: str
    email: str
    # The person's home department; the department week shows it by default.
    department_id: uuid.UUID


class SessionCompany(BaseModel):
    id: uuid.UUID
    name: str
    timezone: str


class SessionInfo(BaseModel):
    """The answer of POST /api/sessions and GET /api/sessions/current."""

    user: SessionUser
    company: SessionCompany
    # The person's effective permissions. Empty until permissions exist (Z1).
    permissions: list[str]
    # When the session ends at the latest (the 30-day maximum), in UTC.
    expires_at: datetime
