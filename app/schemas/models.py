"""Pydantic models for vulnerability data, predictions, and reports."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ── Vulnerability IO ──────────────────────────────────────────────────────

class VulnerabilityBase(BaseModel):
    source: str = "vulndb"
    cve_id: Optional[str] = None
    vuldb_id: Optional[str] = None
    published_at: Optional[datetime] = None
    title: Optional[str] = None
    description: Optional[str] = None
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_base_score: Optional[float] = None
    cwe_ids: Optional[List[str]] = None
    references_json: Optional[List[Dict[str, Any]]] = None
    affected_products_json: Optional[List[Dict[str, Any]]] = None


class VulnerabilityCreate(VulnerabilityBase):
    """Schema for creating a vulnerability record."""
    pass


class VulnerabilityRead(VulnerabilityBase):
    """Schema for reading a vulnerability record."""
    id: UUID
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Signal IO ─────────────────────────────────────────────────────────────

class SignalRead(BaseModel):
    signal_type: str
    observed_at: datetime
    value_num: Optional[float] = None
    value_bool: Optional[bool] = None
    value_text: Optional[str] = None
    source: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Prediction IO ─────────────────────────────────────────────────────────

class PredictionRequest(BaseModel):
    vuln_id: UUID
    asof: Optional[date] = None
    with_rag: bool = False


class PredictionResult(BaseModel):
    vuln_id: UUID
    cve_id: Optional[str] = None
    asof: date
    p_stage1: Optional[float] = None
    p_stage2: Optional[float] = None
    p_final: float
    calibration_method: Optional[str] = None


# ── STRICT JSON Brief (RAG output) ───────────────────────────────────────

class EvidenceSnippet(BaseModel):
    source: str
    text: str
    attck_version: Optional[str] = None
    object_ref: Optional[str] = None
    ref: Optional[str] = None


class ATTCKMapping(BaseModel):
    technique_id: str
    technique_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    evidence: List[EvidenceSnippet] = Field(min_length=1)


class RemediationAction(BaseModel):
    action: str
    priority: str = "high"
    evidence: List[EvidenceSnippet] = Field(default_factory=list)


class DataVersions(BaseModel):
    vulndb_snapshot: Optional[str] = None
    epss_date: Optional[str] = None
    attck_version: Optional[str] = None
    kev_version: Optional[str] = None


class ModelVersions(BaseModel):
    tabular_model: Optional[str] = None
    text_model: Optional[str] = None
    stacking_model: Optional[str] = None


class BriefMeta(BaseModel):
    generated_at: datetime
    asof_date: str
    data_versions: DataVersions
    model_versions: ModelVersions


class VulnerabilityScores(BaseModel):
    p_stage1: Optional[float] = None
    p_stage2: Optional[float] = None
    p_final: float
    calibration: Optional[Dict[str, Any]] = None


class AuditInfo(BaseModel):
    leakage_checked: bool = True
    explanations: Optional[Dict[str, Any]] = None


class SafetyInfo(BaseModel):
    no_exploit_code: bool = True
    notes: str = "Signals are metadata only; no exploit instructions or payloads are included."


class VulnerabilityBrief(BaseModel):
    """The full STRICT JSON output for executive / SOAR consumption."""
    meta: BriefMeta
    vulnerability: VulnerabilityRead
    scores: VulnerabilityScores
    attck: List[ATTCKMapping] = Field(default_factory=list)
    remediation: List[RemediationAction] = Field(default_factory=list)
    confidence_notes: Optional[str] = None
    audit: AuditInfo = Field(default_factory=AuditInfo)
    safety: SafetyInfo = Field(default_factory=SafetyInfo)


# ── Report IO ─────────────────────────────────────────────────────────────

class MetricsReport(BaseModel):
    run_id: Optional[str] = None
    cutoff_date: str
    n_train: int
    n_test: int
    baselines: Dict[str, Dict[str, float]]
    model_metrics: Dict[str, float]
    top_k_precision: Dict[str, float]
    top_k_recall: Dict[str, float]
    calibration: Dict[str, float]


# ── Health ────────────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    db_connected: bool = False
    qdrant_connected: bool = False
