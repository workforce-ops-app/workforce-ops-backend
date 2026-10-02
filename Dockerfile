# The backend API as a container image (decision 0034).
#   docker build -t workforce-ops-backend .
# Settings come from environment variables at run time; nothing secret is copied in
# (.env is excluded by .dockerignore).

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

# Install the app and its pinned dependencies. Copying pyproject.toml first would not
# help here: setuptools needs the app package to install it.
COPY pyproject.toml README.md ./
COPY app ./app
# pip reads pyproject.toml, installs the exact pinned versions, and installs the app
# itself into Python's packages; the copied source folder is then no longer needed.
RUN pip install . && rm -rf app

# Migrations travel with the image, so they can be applied with
#   docker compose run --rm api alembic upgrade head
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
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
