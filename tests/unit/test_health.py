"""The health endpoint."""

from fastapi.testclient import TestClient


def test_health_answers_ok(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"status": "ok"}


def test_health_only_answers_get(client: TestClient) -> None:
    # Other methods on the same path are refused with 405 Method Not Allowed.
    response = client.post("/api/health")

    assert response.status_code == 405
