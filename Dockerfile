# ========================================
# Stage 1: Build React Frontend
# ========================================
FROM node:20-alpine AS frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ .
# Bake demo mode into the bundle — disables live OpenAI calls on the public deploy
ENV VITE_DEMO_MODE=true
RUN npm run build

# ========================================
# Stage 2: Python Backend + Frontend Dist
# ========================================
FROM python:3.11-slim AS production

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir poetry==1.8.4
RUN poetry config virtualenvs.create false

# Copy dependency files first for layer caching
COPY pyproject.toml poetry.lock ./

# Install CPU-only PyTorch before poetry to avoid pulling the 2GB+ CUDA variant
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

# Install remaining project dependencies
RUN poetry install --no-root --no-interaction --no-ansi

# Copy application source
COPY app/ app/
COPY alembic/ alembic/
COPY alembic.ini .
COPY models/ models/
COPY data/ data/
COPY start.sh .
RUN chmod +x start.sh

# Copy built React SPA from Stage 1
COPY --from=frontend-build /frontend/dist frontend/dist/

# Verify frontend was built — fail loudly if not
RUN test -f /app/frontend/dist/index.html || (echo "ERROR: frontend/dist/index.html missing" && exit 1)

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

CMD ["./start.sh"]
