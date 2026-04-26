# VulnTriage

> **AI-Driven Vulnerability Intelligence & Exploitability Prediction System**  
> Master's Thesis — MS Information Technology, Montclair State University, Spring 2026  
> Author: **Huraib Jan Sarhandi** · Advisor: Prof. Weitian Wang

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-blue)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue)](https://docs.docker.com/compose)
[![License](https://img.shields.io/badge/License-Academic-lightgrey)](#license)

---

## Overview

VulnTriage is a full-stack, research-grade vulnerability triage platform that addresses a critical gap in cyber threat management: **97% of published CVEs are never exploited, yet security teams treat them all equally**.

This system combines:
- **Machine Learning** — XGBoost Reciprocal Rank Fusion (RRF) ensemble predicting CVE exploitability with PR-AUC **0.3671** (+35.4% over EPSS baseline)
- **Circularity Audit Framework** — Novel 4-layer leakage taxonomy detecting **3.73× metric inflation** from circular feature constructions
- **RAG Intelligence Briefs** — Qdrant + SBERT + GPT-4o-mini generating MITRE ATT&CK-grounded vulnerability briefs
- **SSVC Decision Engine** — 5-tier actionable triage output with explicit SLAs (24h → 1yr)
- **Production Platform** — React + FastAPI + PostgreSQL + Qdrant, fully Dockerized

---

## Table of Contents

- [Key Results](#key-results)
- [System Architecture](#system-architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the System](#running-the-system)
- [CLI Reference](#cli-reference)
- [API Reference](#api-reference)
- [ML Pipeline](#ml-pipeline)
- [RAG Pipeline](#rag-pipeline)
- [Decision Engine](#decision-engine)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [Running Tests](#running-tests)
- [Research Questions](#research-questions)
- [Citation](#citation)
- [License](#license)

---

## Key Results

| Metric | Value | vs. Baseline |
|---|---|---|
| PR-AUC (RRF Ensemble) | **0.3671** | +35.4% over EPSS (0.271) |
| PR-AUC (EPSS baseline) | 0.2710 | — |
| PR-AUC (CVSS baseline) | 0.0110 | — |
| ROC-AUC (RRF Ensemble) | **0.9749** | — |
| Precision@100 | **0.71** | — |
| F1 Score | **0.407** | — |
| Circularity inflation ratio | **3.73×** | PR-AUC 0.8911 → 0.2389 (clean) |
| Dataset size | **180,497 CVEs** | NVD 1999–2025 |
| Positive rate | **0.39%** | CISA KEV-strict labels |
| Temporal train/test split | **June 2024** | No future leakage |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          VulnTriage Platform                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Data Sources                  Ingestion Layer                        │
│   ┌──────────┐                  ┌─────────────────────────────────┐    │
│   │ NVD API  │──────────────────▶  nvd_provider  (async HTTP)     │    │
│   │ EPSS v3  │──────────────────▶  enrichment_providers           │    │
│   │ CISA KEV │──────────────────▶  label_builder (KEV-strict)     │    │
│   │ ExploitDB│──────────────────▶  exploitdb_provider             │    │
│   └──────────┘                  └──────────────┬──────────────────┘    │
│                                                │                        │
│                                                ▼                        │
│   Storage                       ┌─────────────────────────────────┐    │
│   ┌──────────────────┐          │  PostgreSQL (port 5433)         │    │
│   │  vulnerabilities │◀─────────│  7 SQLAlchemy models            │    │
│   │  signal_obs      │          │  Alembic migrations             │    │
│   │  label_obs       │          └─────────────────────────────────┘    │
│   │  feature_snaps   │                                                  │
│   └──────────────────┘                                                  │
│            │                                                            │
│            ▼                                                            │
│   Feature Engineering           ML Pipeline                            │
│   ┌─────────────────────┐       ┌─────────────────────────────────┐    │
│   │ cvss_parser.py      │──────▶│ Model A: XGBoost Tabular        │    │
│   │ builder.py (37 feat)│──────▶│ Model B: XGBoost Tab+Emb        │    │
│   │ leakage_audit.py    │──────▶│ Model C: Text LogReg (SBERT)    │    │
│   │ ablation.py         │       │          │                       │    │
│   └─────────────────────┘       │          ▼                       │    │
│                                 │ RRF Fusion (k=60)                │    │
│   Vector Store                  │ → Exploitation Score [0,1]       │    │
│   ┌──────────────────┐          └──────────────┬──────────────────┘    │
│   │  Qdrant (6333)   │                         │                        │
│   │  attck_text coll │                         ▼                        │
│   │  vuln_text coll  │          Decision Engine (SSVC-inspired)        │
│   └────────┬─────────┘          ┌─────────────────────────────────┐    │
│            │                    │ VEX → Asset → KEV+ML → PoC →    │    │
│            ▼                    │ Risk → PATCH_NOW / ACCEPT / ...  │    │
│   RAG Pipeline                  └─────────────────────────────────┘    │
│   ┌─────────────────────┐                                               │
│   │ retriever.py        │       Frontend                               │
│   │ llm_generator.py    │       ┌─────────────────────────────────┐    │
│   │ verifier.py         │       │ React + Vite → Nginx (port 8080)│    │
│   │ ATT&CK STIX ground  │       │ Dashboard / Explorer / AI Brief │    │
│   └─────────────────────┘       └─────────────────────────────────┘    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.11+ | Tested on 3.11.x |
| Docker Desktop | 24+ | Docker Compose v2 included |
| Poetry | 1.8+ | Dependency management |
| Node.js | 18+ | Only needed for frontend dev outside Docker |
| OpenAI API Key | — | Required for RAG brief generation |
| NVD API Key | — | Free at nvd.nist.gov/developers/request-an-api-key |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/vulntriage.git
cd vulntriage
```

### 2. Install Python dependencies

```bash
# Install Poetry if not already installed
pip install poetry

# Install all dependencies
poetry install

# Activate the virtual environment
poetry shell
```

### 3. Set up environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in the required values:

```bash
# Required
OPENAI_API_KEY=sk-...              # OpenAI API key for RAG brief generation
NVD_API=your_nvd_api_key_here      # NVD API key (free registration)

# Pre-configured defaults (change only if needed)
POSTGRES_USER=vulntriage
POSTGRES_PASSWORD=vulntriage_dev
POSTGRES_DB=vulntriage
POSTGRES_HOST=localhost
POSTGRES_PORT=5433
DATABASE_URL=postgresql://vulntriage:vulntriage_dev@localhost:5433/vulntriage
QDRANT_HOST=localhost
QDRANT_HTTP_PORT=6333
```

### 4. Start infrastructure services

```bash
docker compose up -d postgres qdrant
docker compose ps   # verify both are healthy
```

### 5. Run database migrations

```bash
poetry run alembic upgrade head
```

### 6. Start the full stack

```bash
docker compose up
```

Or run locally for development:

```bash
# Backend
poetry run vulntriage serve --port 8000

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

**Access points:**

| Service | URL |
|---|---|
| React Dashboard | http://localhost:8080 |
| FastAPI Swagger UI | http://localhost:8000/docs |
| FastAPI ReDoc | http://localhost:8000/redoc |
| Qdrant Dashboard | http://localhost:6333/dashboard |

---

## Configuration

All configuration is managed via environment variables loaded from `.env`. See `.env.example` for the full reference.

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | Required for RAG LLM generation |
| `NVD_API` | — | NVD REST API key |
| `DATABASE_URL` | `postgresql://...` | Full PostgreSQL connection string |
| `QDRANT_HOST` | `localhost` | Qdrant server hostname |
| `QDRANT_HTTP_PORT` | `6333` | Qdrant REST port |
| `EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | SBERT model for embeddings |
| `EMBEDDING_DIM` | `384` | Embedding dimension |
| `TRAIN_CUTOFF_DATE` | `2024-12-31` | Temporal train/test split date |
| `RANDOM_SEED` | `42` | Reproducibility seed |
| `TOP_K_VALUES` | `25,50,100` | Top-K values for evaluation |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `SAFETY_NO_EXPLOIT_CODE` | `true` | Block exploit code in RAG output |

---

## Running the System

### One-command full pipeline (recommended for first run)

```bash
make happy-path
```

This sequentially runs: infrastructure → ingest → features → train → evaluate → demo.

### Step-by-step pipeline

```bash
# 1. Start infrastructure
make up

# 2. Ingest sample CVE data (20 CVEs bundled in data/)
make ingest

# 3. Fetch live enrichment from EPSS, CISA KEV, MITRE ATT&CK
make enrich

# 4. Engineer feature vectors (with leakage audit)
make features

# 5. Train XGBoost tabular model
make train-tabular

# 6. Evaluate against EPSS/CVSS baselines and generate reports
make evaluate

# 7. Generate sample RAG intelligence briefs
make demo
```

### Makefile targets

```bash
make up              # Start Docker services (postgres + qdrant)
make down            # Stop all services
make ingest          # Ingest sample VulnDB data
make enrich          # Fetch EPSS, KEV, ATT&CK enrichment
make features        # Build 37-feature vectors with leakage audit
make train-tabular   # Train XGBoost tabular model
make train-text      # Train SBERT text model
make evaluate        # Evaluate all models vs baselines
make demo            # Generate demo RAG briefs (top-3 CVEs)
make test            # Run pytest test suite
make lint            # Run ruff linter
make happy-path      # Full end-to-end pipeline
```

---

## CLI Reference

### Ingestion

```bash
# Ingest CVEs from local VulnDB JSON file
vulntriage ingest vuldb --input data/sample_vuldb.json

# Load MITRE ATT&CK STIX knowledge base into Qdrant
vulntriage ingest attck --source data/attck/enterprise-attack.json

# Fetch live EPSS scores from FIRST.org API
vulntriage ingest epss

# Fetch CISA Known Exploited Vulnerabilities (KEV) catalogue
vulntriage ingest kev

# Fetch NVD CVE data (requires NVD_API key in .env)
vulntriage ingest nvd --start-date 2024-01-01 --end-date 2024-12-31
```

### Feature Engineering

```bash
# Build feature vectors as-of a specific date (temporal integrity)
vulntriage build-features --asof 2024-12-31

# Build features with full 4-layer leakage audit report
vulntriage build-features --asof 2024-12-31 --leakage-audit
```

### Training

```bash
# Train XGBoost tabular model (33 features)
vulntriage train tabular --cutoff 2024-09-01

# Train XGBoost Tab+Emb model (33 tabular + 64-dim PCA SBERT)
vulntriage train tabular --cutoff 2024-09-01 --with-embeddings

# Train text logistic regression on SBERT embeddings
vulntriage train text --mode pretrained --cutoff 2024-12-31

# Fine-tune DistilBERT on CVE descriptions
vulntriage train text --mode finetune --cutoff 2024-12-31
```

### Evaluation

```bash
# Full evaluation: all models vs EPSS/CVSS baselines
vulntriage evaluate --cutoff 2024-12-31

# With report generation (PR curves, ROC, Top-K, ablation heatmap)
vulntriage evaluate --cutoff 2024-12-31 --report

# Run ablation study (6 feature configurations × 7 model types)
vulntriage evaluate --cutoff 2024-12-31 --ablation --report
```

### Prediction & Briefing

```bash
# Predict exploitation likelihood for a single CVE
vulntriage predict --vuln-id CVE-2024-21762

# Predict with temporal as-of date
vulntriage predict --vuln-id CVE-2024-21762 --asof 2024-06-01

# Generate RAG intelligence brief
vulntriage brief --vuln-id CVE-2024-21762

# Demo: top-K CVEs with RAG briefs
vulntriage demo --top-k 5 --asof 2024-12-31 --with-rag
```

### API Server

```bash
vulntriage serve
vulntriage serve --host 0.0.0.0 --port 8000
```

---

## API Reference

Base URL: `http://localhost:8000`  
Interactive docs: `http://localhost:8000/docs`

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | PostgreSQL + Qdrant connectivity check |
| `GET` | `/v1/vulnerabilities` | List CVEs (pagination, filter, sort by ML score) |
| `GET` | `/v1/vulnerabilities/{cve_id}` | Full CVE detail with ML scores + signals |
| `GET` | `/v1/vulnerabilities/search?q=` | Full-text search across descriptions |
| `POST` | `/v1/predict/{cve_id}` | Run RRF ensemble prediction |
| `POST` | `/v1/predict/{cve_id}?asof=YYYY-MM-DD` | Temporal point-in-time prediction |
| `POST` | `/v1/brief/{cve_id}` | Generate ATT&CK-grounded RAG brief |
| `GET` | `/v1/stats` | Aggregate counts, KEV stats, score distribution |
| `GET` | `/v1/reports/latest` | Latest evaluation metrics + figure paths |

### Example requests

```bash
# Health check
curl http://localhost:8000/health

# Get top-50 CVEs sorted by ML exploitation score
curl "http://localhost:8000/v1/vulnerabilities?sort=ml_score&limit=50"

# Predict for a CVE
curl -X POST http://localhost:8000/v1/predict/CVE-2024-21762

# Generate AI brief
curl -X POST http://localhost:8000/v1/brief/CVE-2024-21762
```

RAG brief response schema:
```json
{
  "cve_id": "CVE-2024-21762",
  "executive_summary": "...",
  "affected_products": ["FortiOS 7.x", "FortiProxy 7.x"],
  "attack_techniques": [
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
  ],
  "remediation": "Apply FortiOS 7.4.3 patch immediately...",
  "confidence": "HIGH",
  "sources": ["NVD", "CISA KEV", "MITRE ATT&CK"],
  "safety": "COMPLIANT"
}
```

---

## ML Pipeline

### Feature Groups (37 total)

| Group | Count | Importance |
|---|---|---|
| CVSS Vector Components (AV, AC, PR, UI, S, C, I, A, base score) | 9 | 43.4% |
| Exploit Signals (KEV flag, PoC count, Metasploit flag) | 3 | 18.6% |
| EPSS (score, percentile) | 2 | 15.2% |
| Temporal (days_since_publish, days_to_first_exploit) | 2 | 12.8% |
| Reference Signals (reference_count, vendor_advisory_flag) | 2 | 9.0% |
| CWE Encoding (one-hot top-50 categories) | 19 | 1.0% |

### Base Models & RRF Fusion

| Model | Input | PR-AUC | ROC-AUC |
|---|---|---|---|
| XGBoost Tabular | 33 features | 0.261 | 0.928 |
| XGBoost Tab+Emb | 33 + 64-dim PCA SBERT = 97 | 0.271 | 0.936 |
| Text LogReg | 384-dim SBERT | 0.022 | 0.746 |
| **RRF Ensemble** | Rank fusion of all three | **0.3671** | **0.9749** |

RRF formula: `RRF(d) = Σᵣ 1 / (k + rankᵣ(d))` where `k = 60`

### Circularity Audit (RQ2)

| Leakage Type | Description | Effect |
|---|---|---|
| Temporal | Future labels in training set | Split boundary violation |
| Label | KEV/PoC flag used as input feature | **3.73× PR-AUC inflation** |
| Entity | ID-correlated proxy variables | Variable inflation |
| Correlation | Indirect statistical co-occurrence | Variable inflation |

---

## RAG Pipeline

```
CVE Metadata
     │
     ▼
[Stage 1] Assemble context (description + CVSS + EPSS + KEV status)
     │
     ▼
[Stage 2] Qdrant cosine retrieval — k=5 nearest ATT&CK techniques (SBERT)
     │
     ▼
[Stage 3] STIX 2.1 validation — technique IDs verified against MITRE corpus
     │
     ▼
[Stage 4] GPT-4o-mini generation — structured prompt → JSON brief
     │
     ▼
[Stage 5] Hallucination detection — 10 regex patterns + technique ID check
           → COMPLIANT or FLAGGED
```

Qdrant collections:
- `attck_text` — MITRE ATT&CK technique embeddings
- `vuln_text` — CVE description embeddings

---

## Decision Engine

| Layer | Check | Outcome on Match |
|---|---|---|
| A | Vendor VEX "not-affected" statement | → `ACCEPT` |
| B | Asset inventory CPE match | → deprioritise if no match |
| C | CISA KEV membership OR ML score ≥ threshold | → escalate |
| D | Public PoC exists AND network-reachable service | → escalate |
| E | Composite risk = CVSS × EPSS × ML score | → final tier |

| Tier | SLA | Trigger |
|---|---|---|
| `PATCH_NOW` | 24 hours | KEV + reachable + ML ≥ threshold |
| `MITIGATE_NOW` | 24 hours | Active PoC + high ML score |
| `PATCH_WINDOW` | 30 days | Elevated composite risk |
| `MONITOR` | 90 days | Low probability, low exposure |
| `ACCEPT` | 1 year | VEX not-affected or negligible risk |

---

## Project Structure

```
vulntriage/
├── app/
│   ├── api/main.py                  # FastAPI app — 12 endpoints, CORS, health
│   ├── cli.py                       # Typer CLI entry point
│   ├── core/
│   │   ├── settings.py              # Pydantic settings (env var binding)
│   │   ├── logging.py               # structlog structured logging
│   │   └── policy_config.yaml       # SSVC policy thresholds
│   ├── db/
│   │   ├── models.py                # 7 SQLAlchemy ORM models
│   │   ├── asset_models.py          # Asset inventory models
│   │   └── session.py               # Engine, session factory, init_db
│   ├── features/
│   │   ├── builder.py               # 37-feature engineering pipeline
│   │   ├── cvss_parser.py           # CVSS v3.x AV/AC/PR/UI/S/C/I/A parser
│   │   ├── leakage_audit.py         # 4-layer circularity audit framework
│   │   ├── ablation.py              # Feature group ablation runner
│   │   ├── actionability.py         # Actionability feature builders
│   │   └── policy_engine.py         # SSVC decision tree implementation
│   ├── ingest/
│   │   ├── orchestrator.py          # Ingestion + labelling coordinator
│   │   ├── nvd_provider.py          # NVD REST API v2 async ingestion
│   │   ├── enrichment_providers.py  # EPSS, CISA KEV enrichment
│   │   ├── exploitdb_provider.py    # ExploitDB CSV reference parser
│   │   ├── label_builder.py         # KEV-strict + composite labelling
│   │   ├── qdrant_loader.py         # SBERT embedding + Qdrant upsert
│   │   └── base_provider.py         # Abstract provider interface
│   ├── ml/
│   │   ├── tabular/train.py         # XGBoost training + evaluation
│   │   ├── text/embeddings.py       # SBERT + PCA pipeline
│   │   ├── text/train.py            # Text LogReg / DistilBERT training
│   │   ├── stacking/ensemble.py     # RRF fusion + calibration
│   │   ├── evaluation_slices.py     # CVSS severity slice evaluation
│   │   └── evaluation_actionability.py
│   ├── rag/
│   │   ├── attck_loader.py          # MITRE ATT&CK STIX 2.1 loader
│   │   ├── retriever.py             # Qdrant cosine retrieval (k=5)
│   │   ├── llm_generator.py         # GPT-4o-mini structured generation
│   │   ├── generator.py             # Brief orchestration pipeline
│   │   ├── verifier.py              # Hallucination detection (10 patterns)
│   │   └── structured_extraction.py # JSON brief schema enforcement
│   ├── reports/generator.py         # PR/ROC curves, ablation heatmap
│   └── schemas/
│       ├── models.py                # Pydantic v2 API schemas
│       ├── decision.py              # SSVC decision output schemas
│       ├── llm_structures.py        # RAG brief JSON schemas
│       └── asset_schemas.py         # Asset inventory schemas
├── alembic/versions/                # Database migrations
├── data/
│   ├── sample_vuldb.json            # 20 bundled CVEs for local testing
│   └── attck/enterprise-attack.json # MITRE ATT&CK STIX 2.1 (subset)
├── frontend/
│   ├── src/pages/
│   │   ├── Dashboard.jsx            # Threat overview + top-risk CVEs
│   │   ├── Vulnerabilities.jsx      # CVE explorer with search + filter
│   │   └── VulnDetail.jsx           # Per-CVE detail + AI brief tab
│   ├── src/components/
│   │   ├── Sidebar.jsx
│   │   └── AIPipeline.jsx           # RAG pipeline visualisation
│   └── Dockerfile                   # Nginx production build
├── tests/                           # pytest test suite (8 files)
├── Dockerfile                       # FastAPI production image (python:3.11-slim)
├── docker-compose.yml               # Full stack: postgres + qdrant + api + frontend
├── pyproject.toml                   # Poetry dependencies
├── alembic.ini
├── Makefile                         # Pipeline automation
└── .env.example                     # Environment variable template
```

---

## Database Schema

| Table | Purpose |
|---|---|
| `vulnerabilities` | Core CVE records — UUID pk, CVSS vector, description, published_date, CWE (JSONB), references (JSONB) |
| `signal_observations` | Time-stamped signals — EPSS score, KEV flag, PoC count, Metasploit flag |
| `label_observations` | Ground truth labels — KEV-strict or composite, with provenance |
| `feature_snapshots` | Point-in-time feature vectors — 37-dim JSONB, as_of_date |
| `model_runs` | Training run metadata — hyperparams (JSONB), PR-AUC, ROC-AUC |
| `predictions` | Per-CVE ML scores — exploitation_score, tier, SLA |
| `embedding_meta` | Vector tracking — Qdrant collection, point ID, model version |

---

## Running Tests

```bash
# Full test suite
poetry run pytest tests/ -v

# With coverage
poetry run pytest tests/ --cov=app --cov-report=html
open htmlcov/index.html

# Specific file
poetry run pytest tests/test_leakage_audit.py -v
```

| Test File | Coverage |
|---|---|
| `test_cvss_parser.py` | CVSS v3.x vector string parsing, all 8 metrics |
| `test_features.py` | Feature builder output shape, temporal integrity |
| `test_leakage_audit.py` | 4-layer leakage detection, inflation quantification |
| `test_labels.py` | KEV-strict labelling logic, label provenance |
| `test_verifier.py` | RAG output safety checks, hallucination patterns |
| `test_orchestrator.py` | Ingestion pipeline, provider interface contracts |
| `test_policy_engine.py` | SSVC decision tree, all 5 tier assignments |
| `test_actionability_features.py` | Actionability feature correctness |

---

## Research Questions

| RQ | Question | Result |
|---|---|---|
| **RQ1** | Can an RRF ensemble outperform EPSS under strict temporal evaluation? | PR-AUC 0.3671 vs 0.271 (+35.4%) |
| **RQ2** | How much do circular features inflate metrics, and can this be detected? | 3.73× inflation; 4-layer audit framework |
| **RQ3** | Can RAG produce verifiable, ATT&CK-grounded intelligence briefs? | STIX-validated, hallucination-checked briefs |
| **RQ4** | Can a decision engine deliver auditable triage with explicit SLAs? | 5-tier SSVC output with 24h–1yr SLA |

---

## Citation

```bibtex
@mastersthesis{sarhandi2026vulntriage,
  title   = {VulnTriage: AI-Driven Vulnerability Intelligence and Exploitability Prediction},
  author  = {Sarhandi, Huraib Jan},
  school  = {Montclair State University},
  year    = {2026},
  type    = {Master's Thesis},
  advisor = {Wang, Weitian}
}
```

---

## License

Academic research prototype submitted in partial fulfilment of the requirements for the degree of Master of Science in Information Technology, Montclair State University, Spring 2026.

Made available for research reproducibility. No warranty provided.  
© 2026 Huraib Jan Sarhandi. All rights reserved.
