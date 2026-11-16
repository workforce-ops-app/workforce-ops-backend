"""Commands run on a schedule, not by a request (until the application has its own
background jobs, the host schedules them, for example with cron).

They live in the app package, not in scripts/, because the API image installs only the
app package (Dockerfile, pyproject.toml): a command meant to run in the deployed
container has to be part of it. Each one runs with

    docker compose exec -T api python -m app.jobs.<name>

and its exit code says whether it succeeded. tests/integration runs them in the real
image, so a command that cannot run there fails CI.
"""
