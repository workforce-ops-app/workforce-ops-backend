# The backend API as a container image (decision 0034).
#   docker build -t workforce-ops-backend .
# Settings come from environment variables at run time; nothing secret is copied in
# (.env is excluded by .dockerignore).

# --- Stage 1: build the compiled dependencies with the memory-safety defenses ---------
# The wheels PyPI offers for the dependencies with C code (cffi, argon2-cffi-bindings,
# cryptography, markupsafe, sqlalchemy) are compiled without stack canaries or
# FORTIFY_SOURCE and with only partial RELRO (threat E10,
# docs/security/native-hardening.md). Here they are compiled from source with them, and
# cryptography uses Debian's OpenSSL (hardened, and patched with the base image) instead
# of a copy of its own. The compilers stay in this stage: the final image has none.
FROM python:3.13-slim AS build

# A C compiler and the headers they need; Rust for cryptography.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc libc6-dev libffi-dev libssl-dev pkg-config cargo rustc \
    && rm -rf /var/lib/apt/lists/*

# The defenses, for every C file compiled below:
#   -fstack-protector-strong  a canary before each return address in functions with
#                             buffers: a stack overflow stops the program
#   -D_FORTIFY_SOURCE=3       copies with a size the compiler knows are checked as they run
#   -z relro -z now           the table of library addresses is filled at start-up, then
#                             made read-only (full RELRO)
ENV CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3" \
    LDFLAGS="-Wl,-z,relro,-z,now" \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 1. Wheels for every pinned dependency, in /wheels. The versions come from
#    pyproject.toml, so a Dependabot update changes them here too; the ones with C code
#    are built from source, the rest are downloaded as they are (pydantic-core is pure
#    Rust, which checks its own bounds, so its wheel is used as it is).
#    scripts/check_native_hardening.py fails if a new dependency brings C code that is
#    not listed here.
#    Only pyproject.toml is copied for this step, and only its dependency list is used,
#    so the slow compiling is done again only when pyproject.toml changes, never for a
#    change to the app's code (review of #204).
WORKDIR /build
COPY pyproject.toml ./
RUN python -c "import tomllib; print(*tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies'], sep='\n')" > requirements.txt \
    && pip wheel --wheel-dir /wheels -r requirements.txt \
        --no-binary cffi,argon2-cffi-bindings,cryptography,markupsafe,sqlalchemy

# 2. The app's own wheel, without its dependencies (they are all in /wheels already). A
#    change to the app's code starts again from here, in seconds.
COPY README.md ./
COPY app ./app
RUN pip wheel --wheel-dir /wheels --no-deps .

# --- Stage 2: the image that runs ----------------------------------------------------
# Start from the official Python 3.13 image, "slim" variant: a small Debian Linux
# with Python and little else, so there is less software to patch or attack.
FROM python:3.13-slim

# No .pyc files in the image; log lines are written straight away instead of buffered.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Every following command runs in /srv, the app's folder inside the image.
WORKDIR /srv

# Install the app and its pinned dependencies from the wheels built above, and only from
# them (--no-index): nothing is downloaded here, so no unhardened wheel can slip in. The
# wheels are mounted for this step only and are not kept in the image.
RUN --mount=type=bind,from=build,source=/wheels,target=/wheels \
    pip install --no-index --find-links /wheels workforce-ops-backend

# Migrations travel with the image, so they can be applied with the migrations user
# (Compose's migrate tool, never the running API):
#   docker compose run --rm migrate
COPY alembic.ini ./
COPY migrations ./migrations

# Run as an ordinary user: a break-in through the API does not get root in the container.
RUN useradd --create-home --uid 10001 app
USER app

# Documents that the API listens on port 8000 (Compose decides where it is published).
EXPOSE 8000

# Healthy once GET /api/health answers 200 (slim images have no curl).
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"]

# Start the API: uvicorn (the web server) calls create_app() to build the FastAPI app.
# 0.0.0.0 means "accept connections from outside the container", which Compose needs;
# Compose itself only publishes the port on 127.0.0.1 of your computer.
# First refuse to start if another API already answers as "api" on the shared network
# (app/core/shared_network.py, #213), then hand the process over to uvicorn (exec).
CMD ["sh", "-c", "python -m app.core.shared_network && exec uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000"]
