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

VulnTriage is an open, containerized vulnerability-triage pipeline. Security teams can patch only a small fraction of published CVEs, and most are never exploited. The system connects an exploitability ranking to evidence, asset context and a defensible action, and it audits its own evaluation for leakage.

It combines:
- **Exploitability ranking** — Reciprocal Rank Fusion (RRF) over three rank sources: a leakage-safe XGBoost tabular model, an XGBoost model with SBERT text embeddings, and EPSS. The fused value is a rank, not a calibrated probability.
- **Leakage audit** — a four-layer check (temporal, label, entity-proxy, correlation) and a historical-EPSS sensitivity analysis that shows where apparent gains over EPSS do and do not survive.
- **Grounded ATT&CK briefs** — Qdrant + SBERT retrieval and GPT-4o-mini generation, with every technique ID validated against the ATT&CK v18.1 STIX corpus and every cited URL checked against the CVE's own references. An optional verification pass trades coverage for precision.
- **Asset-aware decisions** — SBOM (CycloneDX, SPDX) and VEX (OpenVEX, CSAF) ingestion, version-range matching against NVD configurations, and an SSVC-inspired engine that assigns one of five action tiers with an SLA and a rationale.
- **Platform** — React, FastAPI, PostgreSQL and Qdrant under Docker Compose.

The accompanying paper is *VulnTriage: Artificial Intelligence-Driven CVE Exploitability Prediction with Reciprocal Rank Fusion and Circularity-Aware Evaluation* (IEEE ISAIA 2026).

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

All numbers are from the accepted paper and regenerate from `results/`. The test partition is 70,831 CVEs published on or after 2024-06-01, with 277 CISA KEV positives (0.39%).

**Ranking against EPSS**

| Setting | RRF PR-AUC | EPSS PR-AUC | Difference |
|---|---|---|---|
| Frozen March 2026 feature snapshot | **0.3671** | 0.2711 | +35.4% (95% CI +0.054 to +0.142) |
| Historical EPSS (first monthly score on or after publication) | **0.2678** | 0.2581 | +3.8% (95% CI −0.031 to +0.052), not significant |

The frozen-snapshot gap is therefore not a deployment-time superiority claim. RRF is an integration choice; EPSS is retained as a rank source and as the principal baseline.

**Frozen-snapshot model comparison**

| Model | PR-AUC | ROC-AUC | P@100 | Role |
|---|---|---|---|---|
| CVSS baseline | 0.011 | 0.750 | 0.06 | severity |
| EPSS baseline | 0.271 | 0.963 | 0.44 | ranker |
| XGBoost tabular (33 features) | 0.251 | 0.925 | 0.53 | ranker |
| XGBoost + SBERT embeddings | 0.309 | 0.930 | 0.66 | ranker |
| Text logistic regression | 0.022 | 0.826 | 0.03 | diagnostic, not fused |
| **RRF (k = 60)** | **0.367** | **0.975** | **0.71** | fusion |

**Other findings**

| Finding | Value |
|---|---|
| Circularity stress test (exploit-derived proxies vs clean tabular) | PR-AUC 1.000 vs 0.268, a 3.73× inflation |
| Removing EPSS from the clean tabular model | PR-AUC 0.268 → 0.034 (−87%) |
| Fabricated ATT&CK IDs in 150 generated briefs | 0 |
| Briefs citing a CVE-listed advisory | 149 of 150 |
| Over-rationalized mappings (GPT-4o judge), standard → verified mode | 27.3% → 12.0%, with abstention 1.3% → 34.7% |
| Dataset | 180,497 NVD CVEs published 2020–2025 |

![Model Comparison — RRF Ensemble vs Baselines](docs/figures/ensemble_comparison_bars.png)
*Figure 1: Frozen-snapshot PR-AUC across model configurations.*

**Asset-context experiment (RQ4): robustness to VEX scope.** The paper reports that synthetic asset evidence changed 23.4% of decisions and reduced the urgent queue by 86% (1,286 → 177); there, a VEX statement recorded for a CVE applies wherever that CVE appears. The engine has since been hardened with a stricter rule, in which a statement applies only to the asset it names or to assets that have the named product installed. Under that conservative rule the same seeded experiment still changes 19.1% of decisions and reduces the urgent queue by 58.6% (1,286 → 533). The paper's artifact is `results/asset_aware_triage.json`; the stricter run is `results/asset_aware_triage_corrected_vex_scope.json`. Both are synthetic-fleet sensitivity results, not enterprise outcomes.

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
│   │ cvss_parser.py      │──────▶│ Rank 1: XGBoost tabular         │    │
│   │ builder.py (33 feat)│──────▶│ Rank 2: XGBoost tab + SBERT     │    │
│   │ leakage_audit.py    │──────▶│ Rank 3: EPSS score              │    │
│   │ ablation.py         │       │          │                       │    │
│   └─────────────────────┘       │          ▼                       │    │
│                                 │ RRF Fusion (k=60)                │    │
│   Vector Store                  │ → fused rank (not a probability) │    │
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

![System Architecture](docs/figures/system_architecture.png)
*Figure 2: End-to-end VulnTriage platform — data ingestion, feature engineering, ML pipeline, RAG intelligence layer, and React dashboard.*

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

![VulnTriage Dashboard](docs/figures/screenshot_dashboard.png)
*Figure 3: React dashboard showing threat overview, top-risk CVEs, and ML exploitation scores.*

![Vulnerability Explorer](docs/figures/screenshot_vulnerabilities.png)
*Figure 4: CVE explorer with search, filtering, and per-vulnerability ML triage scores.*

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
make features        # Build feature vectors with leakage audit
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
| `GET` | `/health` | PostgreSQL and Qdrant connectivity |
| `GET` | `/v1/vulnerabilities` | List CVEs (pagination, search, CVSS and KEV filters) |
| `GET` | `/v1/vulnerabilities/{cve_id}` | CVE detail |
| `POST` | `/v1/predict/{cve_id}` | RRF rank against the held-out reference population, the three source ranks, and an assetless SSVC-inspired decision |
| `POST` | `/v1/brief/{cve_id}` | Retrieval-only ATT&CK brief (no LLM) |
| `POST` | `/v1/brief-llm/{cve_id}` | LLM brief; `?verify=true` enables the high-precision verification pass; results are cached |
| `GET` | `/v1/assets` · `POST` `/v1/assets` | List and register assets |
| `POST` | `/v1/assets/{id}/sbom` | Upload a CycloneDX or SPDX document and rebuild the finding queue |
| `POST` | `/v1/assets/{id}/vex` | Upload OpenVEX or CSAF VEX statements scoped to the asset |
| `POST` | `/v1/assets/{id}/evaluate` | Recompute the finding queue |
| `GET` | `/v1/assets/{id}/findings` | Prioritised findings with version evidence and rationale |
| `GET` | `/v1/assets/{id}/decision/{cve_id}` | Decision for one asset–CVE pair |
| `GET` | `/v1/stats` · `/v1/stats/top-risk` | Dashboard aggregates |
| `GET` | `/v1/policy` | Decision policy description |

When `VULNTRIAGE_API_KEY` is set, write endpoints and `/v1/brief-llm` require an `X-API-Key` header. LLM briefs are rate-limited per client (`LLM_RATE_LIMIT_PER_MINUTE`).

### Example requests

```bash
curl http://localhost:8000/health

# Rank a CVE
curl -X POST http://localhost:8000/v1/predict/CVE-2024-9465

# LLM brief, standard and high-precision
curl -X POST http://localhost:8000/v1/brief-llm/CVE-2024-9465
curl -X POST "http://localhost:8000/v1/brief-llm/CVE-2024-9465?verify=true"

# Register an asset, upload its SBOM, read the queue
ASSET=$(curl -s -X POST http://localhost:8000/v1/assets -H 'Content-Type: application/json' \
  -d '{"name":"web-frontend","asset_type":"container","criticality":"high","is_internet_facing":true}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
curl -X POST http://localhost:8000/v1/assets/$ASSET/sbom -H 'Content-Type: application/json' \
  --data-binary @data/sbom/httpd_2.4.49.cdx.json
curl "http://localhost:8000/v1/assets/$ASSET/findings?limit=10"
```

The rank response states its own semantics:

```json
{
  "rrf": {
    "rank": 18, "n_reference": 70831, "percentile": 99.98, "k": 60,
    "sources": {"xgb_tabular": {"rank": 31}, "xgb_tabemb": {"rank": 50}, "epss": {"rank": 10}},
    "calibrated_probability": false
  }
}
```

---

## ML Pipeline

### Features (33, clean tabular configuration)

15 CVSS core and vector fields, 12 CWE indicators, EPSS, days since publication, two description statistics, and product and reference counts. Exploit-derived signals (KEV flag, PoC and Metasploit indicators) are excluded from the model under the KEV-strict label policy; using them reads the label off the input.

TreeSHAP attribution on the saved model: NVD reference count 33%, EPSS 27%, affected-product count 8%, days since publication 7%, description length 4%. Attribution is not necessity: a leave-one-group-out retraining shows EPSS is the least replaceable input (−87% PR-AUC when removed).

### Rank sources and fusion

| Source | Input | PR-AUC | ROC-AUC |
|---|---|---|---|
| XGBoost tabular | 33 features | 0.251 | 0.925 |
| XGBoost tab + embeddings | 33 + 64 PCA-reduced SBERT components | 0.309 | 0.930 |
| EPSS | published score | 0.271 | 0.963 |
| **RRF (k = 60)** | rank fusion of the three | **0.367** | **0.975** |

`RRF(d) = Σᵣ 1 / (k + rankᵣ(d))`, with `k = 60` (the literature default; a post-hoc sweep over k ∈ [5, 300] moves PR-AUC by 0.034).

**Serving.** A rank needs a population. `vulntriage build-rrf-reference` recomputes the three source scores on the held-out partition, refuses to proceed unless the published PR-AUC values reproduce to five decimals, and stores the sorted score arrays in `models/rrf_reference_v2.npz`. The API ranks a CVE's three scores against that reference and fuses the ranks. The result is reported as a rank and percentile.

![Precision-Recall Curves](docs/figures/ensemble_pr_curves.png)
*Figure 5: Frozen-snapshot precision-recall curves.*

### Leakage audit (RQ2)

| Layer | What it flags |
|---|---|
| Temporal | Features observed after the decision time |
| Label | Direct or derived exploit signals that overlap the KEV outcome |
| Entity | Identifier-correlated proxies |
| Correlation | Feature–label pairs above a statistical threshold |

The proxy-rich stress test reaches PR-AUC 1.000 against 0.268 for the clean configuration (3.73×). It is an intentionally invalid upper bound, not a deployable predictor.

![Circularity Inflation](docs/figures/circularity_inflation.png)

---

## RAG Pipeline

1. Build a query from the CVE description, CWE and affected products.
2. Retrieve the nearest ATT&CK techniques from Qdrant (SBERT cosine similarity).
3. Optional high-precision mode: a Chain-of-Verification pass asks, per candidate, whether the technique describes how this CVE would be exploited, and drops unconfirmed candidates. When none remain the brief asserts no mapping.
4. Generate a JSON brief with GPT-4o-mini. CVE text is passed inside a delimited block and treated as data, so instructions embedded in a description cannot redirect the model.
5. Validate: every technique ID must exist in the pinned ATT&CK v18.1 STIX corpus, and a remediation URL is kept only if it appears verbatim in the CVE's reference list.

Briefs are cached per CVE and mode. The response lists retrieved techniques the model did not use in its own analysis.

Deterministic checks validate identifiers and references. Whether a valid technique is the *right* one is a semantic judgement; the paper's relevance and faithfulness figures are model-judged, not human-rated.

Qdrant collections: `attck_text` (691 ATT&CK techniques) and `vuln_text`.

---

## Decision Engine and Asset Context

Upload an SBOM for an asset and the engine builds its finding queue:

1. **Identity.** Each component is resolved to an NVD vendor/product, from its CPE (Syft, Trivy) or from the package name when it maps to exactly one known vendor.
2. **Version match.** The installed version is compared with the version ranges in the stored NVD configurations. A patched component is reported as *not in range* and accepted; a component inside a range is *version confirmed*.
3. **VEX.** A statement is applied only if it is scoped to the asset or names a product installed on it. A statement about one product never suppresses a finding for another.
4. **Decision.** Affectedness, exploitation evidence (KEV, public PoC), reachability, controls, asset criticality and CVSS/EPSS/ML risk are combined into one tier, with the rationale recorded.

| Tier | SLA |
|---|---|
| `PATCH_NOW` | 24 hours |
| `MITIGATE_NOW` | 24 hours |
| `PATCH_WINDOW` | 30 days |
| `MONITOR` | 90 days |
| `ACCEPT` | 1 year |

Each finding also records the action it would receive with no asset context, so the effect of the asset evidence is visible per CVE.

Three real SBOMs generated with Syft are in `data/sbom/`. On `httpd:2.4.49` registered as an internet-facing, high-criticality asset, the queue places CVE-2021-41773 and CVE-2021-42013 (both in CISA KEV) at `PATCH_NOW` with the matching version as evidence.

**CISA SSVC outcome.** Alongside the five tiers, each decision reports the standard CISA SSVC outcome (Track, Track*, Attend, Act) from the CISA Coordinator v2.0.3 table. Exploitation is observed from KEV and public-PoC signals; Automatable and Technical Impact are derived from the CVSS vector and Mission & Well-being from asset criticality, and every decision point states whether it is observed or inferred. These are not CISA's own assessments.

**Distribution backports (opt-in).** Versions are compared with upstream ranges, so a Debian or Alpine package that received a backported fix can still appear as affected. With `OSV_BACKPORT_CHECK=true` the engine asks OSV whether the distribution lists the installed revision as affected, and accepts a finding only when the distribution tracks that CVE for the package and the revision is outside its affected set. It is off by default because it sends package names and versions to api.osv.dev. A vendor VEX statement resolves the same cases without a lookup.

**CVSS v4.** v4.0 vectors are parsed and projected onto the v3 feature encoding (all 2,210 stored v4 vectors parse). The rank models were trained with these CVEs as featureless, so their live scores come from features unseen in training.

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
│   │   ├── builder.py               # feature engineering (33 clean tabular features)
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
│   │   ├── text/train.py            # diagnostic text model (not fused)
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
| `feature_snapshots` | Feature vectors per (CVE, as-of date), JSONB |
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
| **RQ1** | How does RRF compare with EPSS in a frozen snapshot? | 0.3671 vs 0.2711; with historical EPSS the +3.8% difference is not statistically reliable |
| **RQ2** | Do circular or post-decision features inflate metrics? | 3.73× inflation in the proxy stress test |
| **RQ3** | Do grounding and optional verification reduce unsupported ATT&CK mappings? | 0 fabricated IDs; over-rationalization 27.3% → 12.0% at the cost of 34.7% abstention |
| **RQ4** | How does asset context change action tiers? | Synthetic fleet: 23.4% of decisions change in the paper; 19.1% under the stricter per-asset VEX scope |

## Checks added after publication

| Check | Result | Artifact |
|---|---|---|
| ATT&CK retrieval against MITRE CTID analyst mappings (345 KEV CVEs, no LLM) | top-3 hit rate 0.267 exact, 0.307 with sub-techniques collapsed; exploitation-technique mappings only: 0.222. A constant guess of the three most common techniques scores 0.754 | `results/ctid_attack_eval.json` |
| NIST LEV (CSWP 41) as a baseline, frozen setting, monthly EPSS snapshots | LEV PR-AUC 0.252 vs EPSS 0.271 (difference not significant); RRF minus LEV +0.115 (95% CI +0.063 to +0.164); adding LEV to RRF changes nothing measurable | `results/lev_baseline.json` |
| Asset experiment under the stricter per-asset VEX scope | 19.1% of decisions still change, urgent queue −58.6% (paper, per-CVE scope: 23.4%, −86%) | `results/asset_aware_triage_corrected_vex_scope.json` |

The CTID result means the retriever alone agrees poorly with human analysts. CTID maps exploitation method and impact at parent-technique level, and impact often cannot be inferred from a CVE description, so the comparison is not like for like with the brief-level relevance judged in RQ3; it does show that the LLM-judged relevance figures should not be read as human-validated accuracy.

## Data files not stored in the repository

Two public datasets are downloaded instead of committed; their checksums are in `reports/snapshot_manifest.json`.

- `data/attck/enterprise-attack-full.json`: the MITRE ATT&CK Enterprise v18.1 STIX bundle, from the `mitre-attack/attack-stix-data` repository.
- `data/epss_history/`: FIRST's monthly EPSS score files (`epss_scores-YYYY-MM-DD.csv.gz`, 2024-06 to 2026-03), used by the historical-EPSS analysis.

## Keeping data current

`vulntriage refresh-feeds` appends the day's EPSS scores and CISA KEV listings (including the ransomware-use flag). It is idempotent per score date and never overwrites history, so point-in-time evaluation becomes possible from the stored data. Feature construction only uses signals observed on or before the as-of date. The stored snapshot ends in March 2026; the first refresh adds current scores and changes live ranks.

## Limitations

- Features and KEV labels are a March 2026 snapshot paired with a chronological split. Only EPSS is replaced historically, so no result is a full prospective replay.
- KEV is curated and incomplete; negatives may later be exploited.
- The asset experiment uses a synthetic fleet and synthesized VEX, controls and reachability.
- Brief relevance and faithfulness are judged by LLMs, not by human annotators.
- The stored data ends in March 2026 and EPSS is held for a single date until `refresh-feeds` is scheduled.

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

Academic research submitted in partial fulfilment of the requirements for the degree of Master of Science in Data Science, Montclair State University, Spring 2026.

Made available for research reproducibility. No warranty provided.  
© 2026 Huraib Jan Sarhandi. All rights reserved.
