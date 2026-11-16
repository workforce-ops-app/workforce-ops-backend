"""Verifying the company's audit log over HTTP (docs/architecture/audit-log.md). HTTP
only: the permission check and the work are in service.py.

    POST /api/audit/verify    200  check the company's chain now; returns what was found

POST, not GET: a check is an action with a result of its own. It writes an audit entry
(audit.verified), and a failure also writes a security event, so it changes data and
needs the CSRF token like every other change.

Errors: 401 not signed in, 403 without audit.verify. There is no chain parameter: the
chain is always the signed-in person's own company's.
"""

from fastapi import APIRouter

from app.auth.dependencies import Database, SignedInPerson
from app.modules.audit_log import service
from app.modules.audit_log.schemas import VerificationOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.post("/verify")
def verify(current: SignedInPerson, db: Database) -> VerificationOut:
    """Check every entry of the company's audit chain and its end; see service.py."""
    result = service.verify_company_chain(db, current.user)
    return VerificationOut(
        ok=result.ok,
        checked=result.checked,
        last_seq=result.last_seq,
        first_bad_seq=result.first_bad_seq,
        problem=result.problem,
    )
