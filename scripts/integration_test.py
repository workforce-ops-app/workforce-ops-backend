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
    """Ask the operating system for a port number nothing else is using right now."""
    # Open a network socket (one end of a network connection).
    with socket.socket() as sock:
        # Binding to port 0 means "any free port": the operating system picks one.
        # 127.0.0.1 is this computer only, so nothing is opened to the network.
        sock.bind(("127.0.0.1", 0))
        # Read back which port it picked. The socket closes when the `with` block ends,
        # which frees the port again for Docker to use a moment later.
        return int(sock.getsockname()[1])


def _docker() -> str:
    """The full path of the docker program, so a lookalike elsewhere on PATH is not run."""
    # Look the program up the same way the terminal would.
    path = shutil.which("docker")
    # Not found: Docker Desktop is not installed or not running. Stop with a clear
    # message instead of a confusing error later.
    if not path:
        raise RuntimeError("Docker is needed for the integration test; start Docker Desktop")
    return path


def main() -> int:
    """Start a throwaway copy of the backend, run the integration tests, clean up.

    Returns 0 when everything passed, anything else when something failed (CI reads it).
    """
    # A unique Compose project name, for example "workforce-ops-it-3f9a1c2b". Compose
    # prefixes every container, network, and volume with it, so this copy can never
    # mix with your own running copy ("workforce-ops-backend").
    project = f"workforce-ops-it-{secrets.token_hex(4)}"

    # Pick free ports, so this copy also runs while yours is using 8000 and 3307.
    api_port = _free_port()

    # The settings docker-compose.yml reads. Start from the current environment (so
    # PATH and Docker's own settings still work) and add our values on top.
    env = {
        **os.environ,
        # Random passwords for this run only; they are never written anywhere.
        "MYSQL_ROOT_PASSWORD": secrets.token_hex(16),
        "MYSQL_APP_PASSWORD": secrets.token_hex(16),
        # Where this copy is published on this computer.
        "API_PORT": str(api_port),
        "DB_PORT": str(_free_port()),
        # A private name for the shared network, so stopping this copy can never remove
        # the real "workforce-ops" network your frontend may be using.
        "SHARED_NETWORK": f"{project}-shared",
        # Run like CI and production: no full error details in the logs (decision 0035).
        "APP_ENV": "test",
    }

    # The start of every Compose command we run: docker compose --project-name <ours>.
    compose = [_docker(), "compose", "--project-name", project]

    try:
        # Build the API image and start both containers in the background.
        #   --build:  rebuild the image, so the tests run against the current code.
        #   --wait:   return only when both containers report healthy (their health
        #             checks are in the Dockerfile and docker-compose.yml).
        #   --wait-timeout 300:  give up after 5 minutes (MySQL's first start is slow).
        # Every argument is fixed or generated above; nothing comes from user input,
        # which is why the security lint rule about running programs (S603) is silenced.
        up = subprocess.run(  # noqa: S603
            [*compose, "up", "--detach", "--build", "--wait", "--wait-timeout", "300"],
            env=env,
        )

        # A non-zero exit code means a container failed or never became healthy.
        # Print both containers' logs so the reason shows up in the CI output.
        if up.returncode != 0:
            subprocess.run([*compose, "logs", "--no-color"], env=env)  # noqa: S603
            print("the containers did not become healthy")
            return 1

        # Run tests/integration with pytest, in this same Python. The two extra
        # settings tell the tests where the API is and which Compose project to use;
        # without them the tests skip themselves (see tests/integration/test_compose.py).
        tests = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "tests/integration"],
            env={**env, "INTEGRATION_API_URL": f"http://127.0.0.1:{api_port}",
                 "INTEGRATION_COMPOSE_PROJECT": project},
        )  # fmt: skip

        # If a test failed, the API's log lines usually explain why; print them.
        if tests.returncode != 0:
            subprocess.run([*compose, "logs", "--no-color", "api"], env=env)  # noqa: S603

        # Pass pytest's result on: 0 when every test passed.
        return tests.returncode

    finally:
        # Always clean up, even if something above failed or raised an error:
        #   down:             stop and remove both containers and their networks
        #   --volumes:        delete this copy's database (it was throwaway)
        #   --remove-orphans: remove any other container left in this project
        down = subprocess.run(  # noqa: S603
            [*compose, "down", "--volumes", "--remove-orphans"],
            env=env,
            capture_output=True,
            text=True,
        )
        # Cleanup does not change the test result, but a failed cleanup must not go
        # unnoticed: it would leave containers and a database volume behind. Say so, with
        # Docker's own message and the command to remove them by hand.
        if down.returncode != 0:
            print(f"warning: cleanup failed; remove it with: docker compose -p {project} down -v")
            print(down.stderr.strip())


if __name__ == "__main__":
    # Run main() and hand its result to the operating system as the exit code.
    sys.exit(main())
