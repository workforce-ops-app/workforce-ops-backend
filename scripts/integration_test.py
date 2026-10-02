"""CI check: the backend starts with Docker Compose and answers through its real setup.

    python -m scripts.integration_test

Builds the image, starts the API and MySQL as a separate Compose project with
throwaway passwords and free ports (so it never touches your own running copy or its
data), waits until both are healthy, runs tests/integration against it, then removes
everything it created, including the database volume.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _docker() -> str:
    """The full path of the docker program, so a lookalike elsewhere on PATH is not run."""
    path = shutil.which("docker")
    if not path:
        raise RuntimeError("Docker is needed for the integration test; start Docker Desktop")
    return path


def main() -> int:
    project = f"workforce-ops-it-{secrets.token_hex(4)}"
    api_port = _free_port()
    env = {
        **os.environ,
        "MYSQL_ROOT_PASSWORD": secrets.token_hex(16),  # throwaway, never stored
        "MYSQL_APP_PASSWORD": secrets.token_hex(16),
        "API_PORT": str(api_port),
        "DB_PORT": str(_free_port()),
        "SHARED_NETWORK": f"{project}-shared",
        "APP_ENV": "test",
    }
    compose = [_docker(), "compose", "--project-name", project]
    try:
        # Every argument is fixed or generated here; nothing comes from user input.
        up = subprocess.run(  # noqa: S603
            [*compose, "up", "--detach", "--build", "--wait", "--wait-timeout", "300"],
            env=env,
        )
        if up.returncode != 0:
            subprocess.run([*compose, "logs", "--no-color"], env=env)  # noqa: S603
            print("the containers did not become healthy")
            return 1
        tests = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "tests/integration"],
            env={**env, "INTEGRATION_API_URL": f"http://127.0.0.1:{api_port}",
                 "INTEGRATION_COMPOSE_PROJECT": project},
        )  # fmt: skip
        if tests.returncode != 0:
            subprocess.run([*compose, "logs", "--no-color", "api"], env=env)  # noqa: S603
        return tests.returncode
    finally:
        subprocess.run(  # noqa: S603
            [*compose, "down", "--volumes", "--remove-orphans"], env=env, capture_output=True
        )


if __name__ == "__main__":
    sys.exit(main())
