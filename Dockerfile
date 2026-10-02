# The backend API as a container image (decision 0034).
#   docker build -t workforce-ops-backend .
# Settings come from environment variables at run time; nothing secret is copied in
# (.env is excluded by .dockerignore).

FROM python:3.13-slim

# No .pyc files in the image; log lines are written straight away instead of buffered.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

# Install the app and its pinned dependencies. Copying pyproject.toml first would not
# help here: setuptools needs the app package to install it.
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install . && rm -rf app

# Migrations travel with the image, so they can be applied with
#   docker compose run --rm api alembic upgrade head
COPY alembic.ini ./
COPY migrations ./migrations

# Run as an ordinary user: a break-in through the API does not get root in the container.
RUN useradd --create-home --uid 10001 app
USER app

EXPOSE 8000

# Healthy once GET /api/health answers 200 (slim images have no curl).
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=6 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"]

CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
