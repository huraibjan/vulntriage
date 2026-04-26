FROM python:3.11-slim AS base

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install --no-cache-dir poetry==1.8.4
RUN poetry config virtualenvs.create false

# Copy dependency files first (cache layer)
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --no-interaction --no-ansi

# Copy application code
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .
COPY models/ models/
COPY data/ data/

# Expose FastAPI port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with Uvicorn
CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
