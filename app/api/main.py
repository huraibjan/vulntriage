"""FastAPI application – backend API for the vulnerability intelligence system."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.logging import get_logger, setup_logging
from app.core.settings import get_settings
from app.db.models import Vulnerability, SignalObservation
from app.db.session import get_db
from app.schemas.models import (
    HealthResponse,
    VulnerabilityBrief,
    VulnerabilityRead,
)

setup_logging()
log = get_logger(__name__)

app = FastAPI(
    title="VulnTriage API",
    description="AI-Driven Vulnerability Intelligence & Exploitability Prediction System",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS Middleware ────────────────────────────────────────────────────────
_extra_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
_origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:8080",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
] + _extra_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API Router ────────────────────────────────────────────────────────────
# All endpoints are defined on this router, then mounted at both / and /api.
# The frontend calls /api/*, nginx (local) and FastAPI (production) both strip
# the /api prefix so the same route handlers serve both deployments.
router = APIRouter()


# ── Health ────────────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse)
def health_check(db: Session = Depends(get_db)):
    """System health check."""
    db_ok = False
    try:
        from sqlalchemy import text as sa_text
        db.execute(sa_text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    qdrant_ok = False
    try:
        from app.ingest.qdrant_loader import get_qdrant_client
        c = get_qdrant_client()
        c.get_collections()
        qdrant_ok = True
    except Exception:
        pass

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        db_connected=db_ok,
        qdrant_connected=qdrant_ok,
    )


# ── Vulnerabilities ──────────────────────────────────────────────────────

@router.get("/v1/vulnerabilities/{vuln_id}", response_model=VulnerabilityRead)
def get_vulnerability(vuln_id: str, db: Session = Depends(get_db)):
    """Get a vulnerability by ID (UUID or CVE ID)."""
    vuln = None
    try:
        uid = UUID(vuln_id)
        vuln = db.query(Vulnerability).filter_by(id=uid).first()
    except ValueError:
        pass

    if not vuln:
        vuln = db.query(Vulnerability).filter_by(cve_id=vuln_id).first()

    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerability not found: {vuln_id}")

    return VulnerabilityRead.model_validate(vuln)


@router.get("/v1/vulnerabilities")
def list_vulnerabilities(
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(25, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search CVE ID, title, or description"),
    min_cvss: Optional[float] = Query(None, ge=0, le=10, description="Minimum CVSS score"),
    max_cvss: Optional[float] = Query(None, ge=0, le=10, description="Maximum CVSS score"),
    sort_by: str = Query("published_at", description="Sort field: published_at, cvss_base_score, cve_id"),
    sort_order: str = Query("desc", description="Sort order: asc or desc"),
    has_kev: Optional[bool] = Query(None, description="Filter KEV-listed vulnerabilities"),
    db: Session = Depends(get_db),
):
    """Paginated vulnerability listing with search and filters."""
    q = db.query(Vulnerability)

    if search:
        pattern = f"%{search}%"
        q = q.filter(
            (Vulnerability.cve_id.ilike(pattern))
            | (Vulnerability.title.ilike(pattern))
            | (Vulnerability.description.ilike(pattern))
        )

    if min_cvss is not None:
        q = q.filter(Vulnerability.cvss_base_score >= min_cvss)
    if max_cvss is not None:
        q = q.filter(Vulnerability.cvss_base_score <= max_cvss)

    if has_kev is not None:
        kev_ids = (
            db.query(SignalObservation.vulnerability_id)
            .filter(SignalObservation.signal_type == "kev")
            .filter(SignalObservation.value_bool == True)
            .distinct()
        )
        if has_kev:
            q = q.filter(Vulnerability.id.in_(kev_ids))
        else:
            q = q.filter(~Vulnerability.id.in_(kev_ids))

    total = q.count()

    sort_col = getattr(Vulnerability, sort_by, Vulnerability.published_at)
    if sort_order == "asc":
        q = q.order_by(sort_col.asc().nullslast())
    else:
        q = q.order_by(sort_col.desc().nullsfirst())

    items = q.offset((page - 1) * per_page).limit(per_page).all()

    return {
        "items": [VulnerabilityRead.model_validate(v) for v in items],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }


# ── Prediction ───────────────────────────────────────────────────────────

@router.post("/v1/predict/{vuln_id}")
def predict_vulnerability(
    vuln_id: str,
    asof: Optional[str] = Query(None, description="As-of date YYYY-MM-DD"),
    db: Session = Depends(get_db),
):
    """Predict exploitability for a vulnerability."""
    from datetime import date

    vuln = _resolve_vuln(vuln_id, db)
    asof_date = date.fromisoformat(asof) if asof else date.today()

    try:
        from app.features.builder import build_features_for_vuln
        from app.ml.tabular.train import load_model, predict

        features = build_features_for_vuln(vuln, db, asof_date)
        model = load_model()
        p_stage1 = predict(model, features)

        return {
            "vuln_id": str(vuln.id),
            "cve_id": vuln.cve_id,
            "asof": str(asof_date),
            "p_stage1": round(p_stage1, 4),
            "p_final": round(p_stage1, 4),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")


# ── RAG Brief ────────────────────────────────────────────────────────────

@router.post("/v1/brief/{vuln_id}")
def generate_brief(
    vuln_id: str,
    asof: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    """Generate a STRICT JSON vulnerability brief with ATT&CK mapping."""
    from datetime import date

    vuln = _resolve_vuln(vuln_id, db)
    asof_date = date.fromisoformat(asof) if asof else date.today()

    try:
        from app.features.builder import build_features_for_vuln
        from app.ml.tabular.train import load_model, predict
        from app.rag.generator import generate_brief as gen_brief
        from app.rag.verifier import verify_brief

        features = build_features_for_vuln(vuln, db, asof_date)
        model = load_model()
        p_stage1 = predict(model, features)

        vuln_dict = {
            "id": str(vuln.id),
            "source": vuln.source,
            "cve_id": vuln.cve_id,
            "vuldb_id": vuln.vuldb_id,
            "published_at": vuln.published_at,
            "title": vuln.title,
            "description": vuln.description,
            "cvss_version": vuln.cvss_version,
            "cvss_vector": vuln.cvss_vector,
            "cvss_base_score": vuln.cvss_base_score,
            "cwe_ids": vuln.cwe_ids,
            "affected_products_json": vuln.affected_products_json,
            "references_json": vuln.references_json,
        }

        scores = {"p_stage1": p_stage1, "p_final": p_stage1}
        brief = gen_brief(vuln_dict, scores, asof_date=str(asof_date))

        is_valid, errors = verify_brief(brief)
        if not is_valid:
            return {"brief": brief.model_dump(), "verification_errors": errors}

        return brief.model_dump()

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Brief generation failed: {e}")


# ── LLM-Powered Brief ───────────────────────────────────────────────────

@router.post("/v1/brief-llm/{vuln_id}")
def generate_llm_brief_endpoint(
    vuln_id: str,
    asof: Optional[str] = Query(None, description="As-of date YYYY-MM-DD"),
    db: Session = Depends(get_db),
):
    """Generate an AI-powered vulnerability brief using GPT-4o-mini + RAG."""
    from datetime import date

    vuln = _resolve_vuln(vuln_id, db)
    asof_date = date.fromisoformat(asof) if asof else date.today()

    settings = get_settings()
    if not settings.openai_api_key:
        raise HTTPException(
            status_code=503,
            detail="OpenAI API key not configured. Set OPENAI_API_KEY in .env.",
        )

    try:
        from app.features.builder import build_features_for_vuln
        from app.ml.tabular.train import load_model, predict
        from app.rag.llm_generator import generate_llm_brief

        features = build_features_for_vuln(vuln, db, asof_date)
        model = load_model()
        p_stage1 = predict(model, features)

        epss_signal = (
            db.query(SignalObservation)
            .filter_by(vulnerability_id=vuln.id, signal_type="epss")
            .order_by(SignalObservation.observed_at.desc())
            .first()
        )
        epss_score = epss_signal.value_num if epss_signal else None

        vuln_dict = {
            "id": str(vuln.id),
            "source": vuln.source,
            "cve_id": vuln.cve_id,
            "vuldb_id": vuln.vuldb_id,
            "published_at": vuln.published_at,
            "title": vuln.title,
            "description": vuln.description,
            "cvss_version": vuln.cvss_version,
            "cvss_vector": vuln.cvss_vector,
            "cvss_base_score": vuln.cvss_base_score,
            "cwe_ids": vuln.cwe_ids,
            "affected_products_json": vuln.affected_products_json,
            "references_json": vuln.references_json,
        }

        scores = {
            "p_stage1": p_stage1,
            "p_final": p_stage1,
            "epss_score": epss_score,
        }

        result = generate_llm_brief(vuln_dict, scores, asof_date=str(asof_date))

        return {
            "cve_id": vuln.cve_id,
            "model": result["usage"]["model"],
            "tokens_used": result["usage"]["total_tokens"],
            "verified": result["verification"]["valid"],
            "brief": result["brief"],
            "llm_analysis": result["llm_analysis"],
            "verification": result["verification"],
        }

    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        log.error("llm_brief_failed", vuln_id=vuln_id, error=str(e))
        raise HTTPException(status_code=500, detail=f"LLM brief generation failed: {e}")


# ── Dashboard Stats ──────────────────────────────────────────────────────

@router.get("/v1/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    """Aggregated statistics for the dashboard."""
    total_vulns = db.query(func.count(Vulnerability.id)).scalar() or 0

    critical = db.query(func.count(Vulnerability.id)).filter(Vulnerability.cvss_base_score >= 9.0).scalar() or 0
    high = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.cvss_base_score >= 7.0, Vulnerability.cvss_base_score < 9.0
    ).scalar() or 0
    medium = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.cvss_base_score >= 4.0, Vulnerability.cvss_base_score < 7.0
    ).scalar() or 0
    low = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.cvss_base_score > 0, Vulnerability.cvss_base_score < 4.0
    ).scalar() or 0

    kev_count = (
        db.query(func.count(func.distinct(SignalObservation.vulnerability_id)))
        .filter(SignalObservation.signal_type == "kev", SignalObservation.value_bool == True)
        .scalar() or 0
    )

    poc_count = (
        db.query(func.count(func.distinct(SignalObservation.vulnerability_id)))
        .filter(SignalObservation.signal_type.in_(["poc_exploitdb", "metasploit"]))
        .scalar() or 0
    )

    from datetime import datetime, timedelta
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    recent_critical = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.cvss_base_score >= 9.0)
        .filter(Vulnerability.published_at >= thirty_days_ago)
        .scalar() or 0
    )

    avg_epss_row = (
        db.query(func.avg(SignalObservation.value_num))
        .filter(SignalObservation.signal_type == "epss")
        .scalar()
    )
    avg_epss = round(float(avg_epss_row), 4) if avg_epss_row else None

    yearly = (
        db.query(
            func.extract("year", Vulnerability.published_at).label("year"),
            func.count(Vulnerability.id).label("count"),
        )
        .filter(Vulnerability.published_at.isnot(None))
        .group_by("year")
        .order_by("year")
        .all()
    )

    return {
        "total_vulnerabilities": total_vulns,
        "severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "kev_listed": kev_count,
        "poc_available": poc_count,
        "recent_critical_30d": recent_critical,
        "avg_epss_score": avg_epss,
        "yearly_distribution": [
            {"year": int(y), "count": c} for y, c in yearly
        ],
        "openai_enabled": bool(get_settings().openai_api_key),
    }


@router.get("/v1/stats/top-risk")
def top_risk_vulnerabilities(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
):
    """Return top-risk vulnerabilities ranked by CVSS × EPSS signal."""
    latest_epss = (
        db.query(
            SignalObservation.vulnerability_id,
            func.max(SignalObservation.value_num).label("epss_score"),
        )
        .filter(SignalObservation.signal_type == "epss")
        .group_by(SignalObservation.vulnerability_id)
        .subquery()
    )

    results = (
        db.query(Vulnerability, latest_epss.c.epss_score)
        .outerjoin(latest_epss, Vulnerability.id == latest_epss.c.vulnerability_id)
        .filter(Vulnerability.cvss_base_score.isnot(None))
        .order_by(
            (Vulnerability.cvss_base_score * func.coalesce(latest_epss.c.epss_score, 0.01)).desc()
        )
        .limit(limit)
        .all()
    )

    return [
        {
            "cve_id": vuln.cve_id,
            "title": vuln.title,
            "cvss_base_score": vuln.cvss_base_score,
            "epss_score": round(float(epss), 4) if epss else None,
            "risk_score": round(vuln.cvss_base_score * (epss or 0.01), 3),
            "published_at": vuln.published_at.isoformat() if vuln.published_at else None,
        }
        for vuln, epss in results
    ]


# ── Reports ──────────────────────────────────────────────────────────────

@router.get("/v1/reports/latest")
def get_latest_report():
    """Return the latest metrics report."""
    settings = get_settings()
    metrics_path = settings.reports_dir / "metrics.json"

    if not metrics_path.exists():
        raise HTTPException(status_code=404, detail="No report found. Run evaluation first.")

    with open(metrics_path) as f:
        return json.load(f)


# ── Asset Decision Endpoints ─────────────────────────────────────────────

@router.get("/v1/assets/{asset_id}/decision/{cve_id}")
def get_asset_decision(
    asset_id: str,
    cve_id: str,
    asof: Optional[str] = Query(None, description="As-of date YYYY-MM-DD"),
    db: Session = Depends(get_db),
):
    """Score a single (asset, CVE) pair through the decision engine."""
    from datetime import date

    asof_date = date.fromisoformat(asof) if asof else date.today()

    try:
        from app.features.policy_engine import score_asset_cve
        uid = UUID(asset_id)
        decision = score_asset_cve(uid, cve_id, db, asof_date, persist=True)
        return {
            "asset_id": asset_id,
            "cve_id": cve_id,
            "asof": str(asof_date),
            "action": decision.action.value if hasattr(decision.action, "value") else decision.action,
            "confidence": decision.confidence,
            "sla_hours": decision.sla_hours,
            "rationale": decision.rationale,
            "evidence_summary": decision.evidence_summary,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decision engine error: {e}")


@router.post("/v1/assets/batch-score")
def batch_score_assets(
    payload: dict,
    asof: Optional[str] = Query(None, description="As-of date YYYY-MM-DD"),
    db: Session = Depends(get_db),
):
    """Score multiple (asset_id, cve_id) pairs.

    Expected payload: {"pairs": [{"asset_id": "...", "cve_id": "..."}]}
    """
    from datetime import date

    asof_date = date.fromisoformat(asof) if asof else date.today()
    pairs_raw = payload.get("pairs", [])

    if not pairs_raw:
        raise HTTPException(status_code=400, detail="No pairs provided")

    try:
        from app.features.policy_engine import score_batch
        pairs = [(UUID(p["asset_id"]), p["cve_id"]) for p in pairs_raw]
        results = score_batch(pairs, db, asof_date, persist=True)
        return {"scored": len(results), "results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch scoring error: {e}")


@router.get("/v1/policy")
def get_policy_info():
    """Return the current decision policy description."""
    from app.schemas.decision import get_policy_description
    return get_policy_description()


# ── Helpers ──────────────────────────────────────────────────────────────

def _resolve_vuln(vuln_id: str, db: Session) -> Vulnerability:
    """Resolve a vulnerability by UUID or CVE ID."""
    vuln = None
    try:
        uid = UUID(vuln_id)
        vuln = db.query(Vulnerability).filter_by(id=uid).first()
    except ValueError:
        pass
    if not vuln:
        vuln = db.query(Vulnerability).filter_by(cve_id=vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerability not found: {vuln_id}")
    return vuln


# ── Mount routes & static files ───────────────────────────────────────────
# Routes registered at root (/) and /api prefix so the frontend's /api/* calls
# reach the same handlers whether proxied by nginx or served directly.
app.include_router(router)
app.include_router(router, prefix="/api")

# Serve the React SPA last so API routes always take precedence.
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _FRONTEND_DIR.exists():
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")
