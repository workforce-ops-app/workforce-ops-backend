"""Which company a database session works for.

The company is stored on the session itself (session.info), not in a global variable:
each request already gets its own session (app/db/session.py), so the company travels
with it and can never leak into another request. FastAPI runs ordinary functions in
worker threads, and a value set in one thread's context is not reliably visible in the
next, which is why a "current request" global would be fragile here.

The company always comes from the server side: from the signed-in user's session
(sign-in, a later slice) or, for background jobs, set explicitly per unit of work. It is
never taken from a URL, a query string, or a request body (tenancy.md, threat I1).
"""

import uuid

from sqlalchemy.orm import Session

# The key under which the company is stored in session.info (a plain dict SQLAlchemy
# keeps on every session for exactly this kind of extra information).
_COMPANY_KEY = "tenancy.company_id"


def set_company(session: Session, company_id: uuid.UUID) -> None:
    """Make every query and save in this session work for this one company."""
    # A session works for one company for its whole life. Switching to another company
    # halfway would mix rows already loaded for the first company with the second, so it
    # is refused; start a new session instead.
    existing = session.info.get(_COMPANY_KEY)
    if existing is not None and existing != company_id:
        raise RuntimeError("this session already works for another company")

    # Store the company; the filter in filter.py reads it on every query and save.
    session.info[_COMPANY_KEY] = company_id


def get_company(session: Session) -> uuid.UUID | None:
    """The company this session works for, or None if none was set."""
    # .get returns None when the key is missing, so a session nobody set up has no company.
    company: uuid.UUID | None = session.info.get(_COMPANY_KEY)
    return company
