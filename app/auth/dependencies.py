"""What an endpoint adds to require a signed-in person:

    def handler(current: SignedInPerson): ...

signed_in reads the session cookie, loads the session (app/auth/sessions.py), and sets
the person's company on the request's database session, so every query the endpoint makes
afterwards is limited to that company. Without a valid session the answer is 401.
"""

from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.sessions import COOKIE_NAME, Current, load_session
from app.db.session import get_session

# The request's database session, as an endpoint parameter type.
Database = Annotated[Session, Depends(get_session)]


def signed_in(request: Request, db: Database) -> Current:
    """The signed-in person of this request, or 401 Unauthorized."""
    current = load_session(db, request.cookies.get(COOKIE_NAME))
    if current is None:
        raise HTTPException(status_code=401, detail="Sign in first.")
    return current


# The signed-in person, as an endpoint parameter type: 401 without a valid session.
SignedInPerson = Annotated[Current, Depends(signed_in)]
