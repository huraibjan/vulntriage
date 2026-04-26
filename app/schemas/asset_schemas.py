"""Pydantic schemas for asset-level data models.

These schemas are used for:
- API request/response serialization
- SBOM/VEX import parsing
- Decision engine I/O
- Report generation
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────────

class AssetType(str, Enum):
    SERVER = "server"
    CONTAINER = "container"
    APPLICATION = "application"
    ENDPOINT = "endpoint"
    NETWORK_DEVICE = "network_device"


class Environment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VexStatus(str, Enum):
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VexJustification(str, Enum):
    """VEX justification for not_affected status (per CSAF/OpenVEX)."""
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


# ── Asset schemas ──────────────────────────────────────────────────────

class AssetCreate(BaseModel):
    """Schema for creating a new asset."""
    name: str
    asset_type: AssetType = AssetType.SERVER
    environment: Optional[Environment] = None
    criticality: Criticality = Criticality.MEDIUM
    owner: Optional[str] = None
    is_internet_facing: Optional[bool] = None
    network_zone: Optional[str] = None
    tags: Optional[Dict[str, str]] = None


class AssetResponse(BaseModel):
    """Schema for asset API responses."""
    id: UUID
    name: str
    asset_type: str
    environment: Optional[str] = None
    criticality: str
    owner: Optional[str] = None
    is_internet_facing: Optional[bool] = None
    network_zone: Optional[str] = None
    tags: Optional[Dict[str, str]] = None
    created_at: datetime
    software_count: int = 0
    open_decisions: int = 0

    class Config:
        from_attributes = True


# ── SBOM schemas ───────────────────────────────────────────────────────

class SoftwareComponent(BaseModel):
    """A single software component from an SBOM."""
    vendor: str
    product: str
    version: Optional[str] = None
    cpe: Optional[str] = None       # CPE 2.3 URI
    purl: Optional[str] = None      # Package URL
    install_path: Optional[str] = None
    source: str = "sbom_import"


class SBOMImport(BaseModel):
    """Schema for importing an SBOM (CycloneDX or SPDX simplified)."""
    asset_id: UUID
    format: str = "cyclonedx"   # cyclonedx, spdx
    format_version: Optional[str] = None
    components: List[SoftwareComponent]
    generated_at: Optional[datetime] = None
    tool: Optional[str] = None  # "syft", "trivy", etc.


# ── VEX schemas ────────────────────────────────────────────────────────

class VexStatement(BaseModel):
    """A single VEX statement."""
    cve_id: str
    vendor: str
    product: str
    status: VexStatus
    justification: Optional[VexJustification] = None
    impact_statement: Optional[str] = None
    action_statement: Optional[str] = None
    source: str = "vex_import"


class VexImport(BaseModel):
    """Schema for importing VEX statements."""
    statements: List[VexStatement]
    format: str = "openvex"  # openvex, csaf_vex
    generated_at: Optional[datetime] = None


# ── Reachability schemas ──────────────────────────────────────────────

class ReachabilityEvidence(BaseModel):
    """Evidence of code/network reachability."""
    asset_id: UUID
    cve_id: str
    reachability_type: str  # network, code_path, configuration
    is_reachable: bool
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence_detail: Optional[str] = None
    tool: Optional[str] = None


# ── Control schemas ───────────────────────────────────────────────────

class ControlEvidence(BaseModel):
    """Evidence of a compensating security control."""
    asset_id: UUID
    cve_id: Optional[str] = None
    control_type: str  # waf, ips, edr, network_segmentation, acl
    control_name: Optional[str] = None
    is_active: bool = False
    effectiveness: float = Field(ge=0.0, le=1.0, default=0.0)
    evidence_detail: Optional[str] = None


# ── Decision schemas ──────────────────────────────────────────────────

class DecisionRequest(BaseModel):
    """API request for a triage decision."""
    asset_id: UUID
    cve_id: str
    # Optional overrides (if not provided, values are looked up from DB)
    cvss_override: Optional[float] = None
    epss_override: Optional[float] = None
    ml_prob_override: Optional[float] = None


class DecisionResponse(BaseModel):
    """API response with triage decision."""
    asset_id: UUID
    cve_id: str
    action: str
    confidence: float
    sla_hours: Optional[int] = None
    sla_deadline: Optional[datetime] = None
    rationale: List[str]
    evidence_summary: Dict[str, Any]
    policy_name: str
    policy_version: str
    decided_at: datetime

    class Config:
        from_attributes = True


class DecisionBatchResponse(BaseModel):
    """Batch decision response."""
    total: int
    decisions: List[DecisionResponse]
    distribution: Dict[str, int]  # action → count


# ── Asset Dashboard schemas ──────────────────────────────────────────

class AssetRiskSummary(BaseModel):
    """Risk summary for an asset dashboard."""
    asset_id: UUID
    asset_name: str
    criticality: str
    total_vulns: int = 0
    patch_now_count: int = 0
    mitigate_now_count: int = 0
    patch_window_count: int = 0
    monitor_count: int = 0
    accept_count: int = 0
    highest_cvss: float = 0.0
    highest_epss: float = 0.0
    overdue_count: int = 0
