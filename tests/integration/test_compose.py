"""The backend as Docker Compose runs it: reachable, healthy, and not running as root.

Run by `python -m scripts.integration_test`, which starts a throwaway Compose project and
sets INTEGRATION_API_URL and INTEGRATION_COMPOSE_PROJECT. Without them (for example a
plain `pytest`), these tests are skipped.
"""

import json
import os
import shutil
import subprocess
import urllib.request

import pytest

API_URL = os.environ.get("INTEGRATION_API_URL")
PROJECT = os.environ.get("INTEGRATION_COMPOSE_PROJECT")

pytestmark = pytest.mark.skipif(
    not (API_URL and PROJECT), reason="run through python -m scripts.integration_test"
)


def compose_exec(service: str, *command: str) -> str:
    docker = shutil.which("docker")
    assert docker, "Docker is needed"
    result = subprocess.run(  # noqa: S603
        [docker, "compose", "--project-name", str(PROJECT), "exec", "-T", service, *command],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def test_health_check_answers_through_the_published_port() -> None:
    with urllib.request.urlopen(f"{API_URL}/api/health", timeout=5) as response:  # noqa: S310
        assert response.status == 200
        assert json.load(response) == {"status": "ok"}


def test_api_reaches_the_database() -> None:
    # The API container connects to MySQL with its own settings, as the app will.
    output = compose_exec(
        "api",
        "python",
        "-c",
        "from sqlalchemy import text; from app.db.session import get_engine; "
        "print(get_engine().connect().execute(text('SELECT 1')).scalar())",
    )
    assert output == "1"


def test_api_container_does_not_run_as_root() -> None:
    # A break-in through the API must not get root inside the container.
    assert compose_exec("api", "id", "-u") != "0"


def test_api_image_contains_no_env_file() -> None:
    # Secrets come from the environment at run time, never baked into the image.
    assert compose_exec("api", "ls", "-a", "/srv").split().count(".env") == 0
