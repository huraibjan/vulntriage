.PHONY: up down ingest features train evaluate demo test lint

# ── Infrastructure ─────────────────────────────
up:
	docker compose up -d

down:
	docker compose down

# ── Pipeline commands ──────────────────────────
ingest:
	poetry run vulntriage ingest vuldb --input data/sample_vuldb.json

enrich:
	poetry run vulntriage ingest epss
	poetry run vulntriage ingest kev
	poetry run vulntriage ingest attck --source data/attck/enterprise-attack.json

features:
	poetry run vulntriage build-features --asof 2026-02-25 --leakage-audit

train-tabular:
	poetry run vulntriage train tabular --cutoff 2024-12-31

train-text:
	poetry run vulntriage train text --mode pretrained --cutoff 2024-12-31

evaluate:
	poetry run vulntriage evaluate --cutoff 2024-12-31 --report

demo:
	poetry run vulntriage demo --top-k 3 --asof 2026-02-25 --with-rag

# ── Quality ────────────────────────────────────
test:
	poetry run pytest tests/ -v

lint:
	poetry run ruff check app/ tests/

# ── Full happy path ───────────────────────────
happy-path: up ingest features train-tabular evaluate demo
	@echo "✅ Happy path complete – check /reports"
