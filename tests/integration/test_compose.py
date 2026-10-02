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

# Where the throwaway API is published, e.g. "http://127.0.0.1:52344", and the name of
# its Compose project. Both are set by scripts/integration_test.py; None otherwise.
API_URL = os.environ.get("INTEGRATION_API_URL")
PROJECT = os.environ.get("INTEGRATION_COMPOSE_PROJECT")

# Skip every test in this file unless both settings are present, so a plain `pytest`
# on a laptop without the containers running does not fail.
pytestmark = pytest.mark.skipif(
    not (API_URL and PROJECT), reason="run through python -m scripts.integration_test"
)


def compose_exec(service: str, *command: str) -> str:
    """Run a command inside one of the running containers and return what it printed.

    For example compose_exec("api", "id", "-u") runs `id -u` inside the API container.
    """
    # Find the docker program (its full path, not just the name).
    docker = shutil.which("docker")
    assert docker, "Docker is needed"

    # docker compose --project-name <ours> exec -T <service> <command...>
    #   exec:  run a command in an already running container
    #   -T:    no interactive terminal, so the output can be captured
    # capture_output and text return what the command printed, as a string.
    # The arguments are fixed by the tests, never user input (hence noqa S603).
    result = subprocess.run(  # noqa: S603
        [docker, "compose", "--project-name", str(PROJECT), "exec", "-T", service, *command],
        capture_output=True,
        text=True,
    )

    # A failed command fails the test, with its own error output in the message, so the
    # reason is visible instead of only "exit status 1".
    assert result.returncode == 0, (
        f"{' '.join(command)} failed in {service}: {result.stderr.strip()}"
    )

    # Remove the trailing newline so tests can compare the output directly.
    return result.stdout.strip()


def test_health_check_answers_through_the_published_port() -> None:
    # Call GET /api/health from outside the containers, the way a browser or nginx
    # would, through the port Compose published on this computer.
    with urllib.request.urlopen(f"{API_URL}/api/health", timeout=5) as response:  # noqa: S310
        # 200 OK, and the body the health module returns.
        assert response.status == 200
        assert json.load(response) == {"status": "ok"}


def test_api_reaches_the_database() -> None:
    # Inside the API container, open a database connection with the app's own
    # settings (DATABASE_URL pointing at the "db" service) and run SELECT 1.
    # Printing 1 proves the network, the user name, and the password all work.
    output = compose_exec(
        "api",
        "python",
        "-c",
        "from sqlalchemy import text; from app.db.session import get_engine; "
        "print(get_engine().connect().execute(text('SELECT 1')).scalar())",
    )
    assert output == "1"


def test_api_container_does_not_run_as_root() -> None:
    # `id -u` prints the user number the container runs as; 0 would be root.
    # A break-in through the API must not get root inside the container.
    assert compose_exec("api", "id", "-u") != "0"


def test_api_image_contains_no_env_file() -> None:
    # List every file in the app's folder inside the container, hidden ones included.
    # Secrets come from the environment at run time, never baked into the image, so
    # no .env file may be there (.dockerignore keeps it out).
    assert compose_exec("api", "ls", "-a", "/srv").split().count(".env") == 0
