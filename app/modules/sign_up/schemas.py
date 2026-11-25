"""The sign-up form (docs/features/organization.md, company sign-up: fields).

Strict: any other field (company_id, role, password_hash, ...) is refused with 422
(threat T2), so a request cannot choose anything the sign-up decides itself.
"""

from typing import Annotated

from pydantic import AfterValidator, Field, SecretStr, StringConstraints

from app.modules.org.schemas import Email, Name, Strict, _known_zone

# The company's name: 1 to 200 characters (the column), surrounding spaces removed. Not
# unique: two businesses may share a name, and a unique name would let anyone test which
# companies use the platform.
CompanyName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]

# A real IANA time zone, required here (the shared Zone allows null for "the company's").
RequiredZone = Annotated[str, Field(max_length=64), AfterValidator(_known_zone)]


class SignUpRequest(Strict):
    """POST /api/sign-up."""

    company_name: CompanyName
    timezone: RequiredZone
    display_name: Name
    email: Email
    # SecretStr: never shown in a repr, an error, or a log line, and marks the field as a
    # credential for detection (rule DE3). The password rules are checked in the service;
    # this limit only stops oversized requests before any work (as at sign-in).
    password: SecretStr = Field(max_length=1024)
