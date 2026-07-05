#!/bin/bash
set -e

echo "Running database migrations..."
alembic upgrade head || echo "WARNING: Migration failed — DB may not be configured yet. Continuing..."

echo "Starting uvicorn on port ${PORT:-8000}..."
exec uvicorn app.api.main:app \
    --host 0.0.0.0 \
    --port "${PORT:-8000}" \
    --workers 1 \
    --timeout-keep-alive 120
