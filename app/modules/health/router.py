"""Health check: GET /api/health answers 200 {"status": "ok"} while the API is up.

Used by Docker Compose and the smoke tests to know when the API is ready.
"""

from fastapi import APIRouter

# Define the router with the specified prefix and tag #
router = APIRouter(prefix="/api/health", tags=["health"])


# Define the endpoint function that returns the health status #
@router.get("")
def read_health() -> dict[str, str]:
    return {"status": "ok"}
