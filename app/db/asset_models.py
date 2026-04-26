"""Asset-level ORM models for the 5-layer evidence hierarchy.

Layer Architecture
------------------
A. **Affectedness** – Does this software exist on this asset? (SBOM/VEX)
B. **Reachability** – Is the vulnerable code path reachable? (network/call graph)
C. **Weaponization** – Does exploit code / PoC / KEV exist? (already in signal_observation)
D. **Control Efficacy** – Are compensating controls in place? (WAF/EDR/IPS)
E. **Decision** – patch_now / mitigate_now / patch_window / monitor / accept

Tables
------
- asset                  – organizational asset with criticality
- asset_software_obs     – SBOM: which software versions are on which asset
- vex_statement_obs      – VEX: vendor exploitability assessment
- reachability_obs       – network / call-graph reachability evidence
- control_obs            – compensating control observations
- validation_obs         – scanner/pentest validation results
- decision_obs           – final triage decision with evidence chain
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.models import Base


# ── Asset ──────────────────────────────────────────────────────────────

class Asset(Base):
    """An organizational asset (server, container, application, endpoint)."""
    __tablename__ = "asset"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(256), nullable=False)
    asset_type = Column(String(64), nullable=False, default="server")  # server, container, application, endpoint
    environment = Column(String(32), nullable=True)  # production, staging, development
    criticality = Column(String(16), nullable=False, default="medium")  # critical, high, medium, low
    owner = Column(String(128), nullable=True)
    tags_json = Column(JSONB, nullable=True)  # {"team": "backend", "region": "us-east-1"}

    # Network context
    is_internet_facing = Column(Boolean, nullable=True)
    network_zone = Column(String(64), nullable=True)  # dmz, internal, restricted

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    software_observations = relationship("AssetSoftwareObs", back_populates="asset", cascade="all, delete-orphan")
    reachability_observations = relationship("ReachabilityObs", back_populates="asset", cascade="all, delete-orphan")
    control_observations = relationship("ControlObs", back_populates="asset", cascade="all, delete-orphan")
    validation_observations = relationship("ValidationObs", back_populates="asset", cascade="all, delete-orphan")
    decisions = relationship("DecisionObs", back_populates="asset", cascade="all, delete-orphan")


# ── Layer A: Affectedness (SBOM / VEX) ─────────────────────────────────

class AssetSoftwareObs(Base):
    """SBOM observation: which software (CPE/PURL) is on which asset.

    This is Layer A — establishes whether the vulnerability's affected
    products actually exist on the asset.
    """
    __tablename__ = "asset_software_obs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset.id", ondelete="CASCADE"), nullable=False)
    vendor = Column(String(128), nullable=False)
    product = Column(String(128), nullable=False)
    version = Column(String(64), nullable=True)
    cpe = Column(String(256), nullable=True)  # CPE 2.3 string
    purl = Column(String(512), nullable=True)  # Package URL
    install_path = Column(Text, nullable=True)
    observed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    as_of_date = Column(DateTime, nullable=True)  # snapshot date for temporal safety
    confidence = Column(Float, nullable=True)  # 0.0–1.0 match confidence
    source = Column(String(64), nullable=True)  # sbom_scan, manual, cdx_import

    asset = relationship("Asset", back_populates="software_observations")

    __table_args__ = (
        Index("ix_asset_sw_asset", "asset_id"),
        Index("ix_asset_sw_product", "vendor", "product"),
    )


class VexStatementObs(Base):
    """VEX (Vulnerability Exploitability eXchange) statement.

    Vendors publish VEX to say "this vulnerability does not affect our
    product in configuration X" or "affected, fix available".
    """
    __tablename__ = "vex_statement_obs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset.id", ondelete="CASCADE"), nullable=True)  # optional: CVE-level when null
    vendor = Column(String(128), nullable=False)
    product = Column(String(128), nullable=False)

    # VEX status: not_affected, affected, fixed, under_investigation
    status = Column(String(32), nullable=False)
    justification = Column(Text, nullable=True)  # e.g., "vulnerable_code_not_present"
    impact_statement = Column(Text, nullable=True)
    action_statement = Column(Text, nullable=True)

    observed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    source = Column(String(64), nullable=True)  # csaf_vex, openvex, manual

    __table_args__ = (
        Index("ix_vex_vuln", "vulnerability_id"),
        Index("ix_vex_product", "vendor", "product"),
        Index("ix_vex_asset", "asset_id"),
    )


# ── Layer B: Reachability ──────────────────────────────────────────────

class ReachabilityObs(Base):
    """Reachability evidence: can the vulnerable code path be triggered?

    This covers both network reachability (is the port open?) and code
    reachability (is the vulnerable function in an active code path?).
    """
    __tablename__ = "reachability_obs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)

    # Reachability type
    reachability_type = Column(String(32), nullable=False)  # network, code_path, configuration
    is_reachable = Column(Boolean, nullable=False)
    confidence = Column(Float, nullable=True)  # 0.0–1.0

    # Evidence
    evidence_detail = Column(Text, nullable=True)  # "Port 443 open, HTTP/2 enabled"
    tool = Column(String(64), nullable=True)  # nmap, semgrep, codeql
    observed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="reachability_observations")

    __table_args__ = (
        Index("ix_reach_asset_vuln", "asset_id", "vulnerability_id"),
    )


# ── Layer D: Control Efficacy ──────────────────────────────────────────

class ControlObs(Base):
    """Compensating control observation.

    Records whether a security control (WAF rule, IPS signature, EDR
    policy, network segmentation) mitigates the vulnerability on this
    asset.
    """
    __tablename__ = "control_obs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=True)

    control_type = Column(String(64), nullable=False)  # waf, ips, edr, network_segmentation, acl
    control_name = Column(String(128), nullable=True)  # "ModSecurity CRS 3.3"
    is_active = Column(Boolean, nullable=False, default=False)
    effectiveness = Column(Float, nullable=True)  # 0.0–1.0 estimated effectiveness
    evidence_detail = Column(Text, nullable=True)
    observed_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    source = Column(String(64), nullable=True)  # manual, api_query, scanner

    asset = relationship("Asset", back_populates="control_observations")

    __table_args__ = (
        Index("ix_control_asset", "asset_id"),
    )


# ── Validation ─────────────────────────────────────────────────────────

class ValidationObs(Base):
    """Scanner / penetration test validation result.

    Confirms or denies actual exploitability on a specific asset.
    This is the highest-confidence evidence.
    """
    __tablename__ = "validation_obs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)

    validation_type = Column(String(32), nullable=False)  # scanner, pentest, exploit_attempt
    result = Column(String(32), nullable=False)  # confirmed, not_exploitable, inconclusive
    tool = Column(String(64), nullable=True)  # nessus, qualys, nuclei, manual
    evidence_detail = Column(Text, nullable=True)
    observed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="validation_observations")

    __table_args__ = (
        Index("ix_validation_asset_vuln", "asset_id", "vulnerability_id"),
    )


# ── Layer E: Decision ──────────────────────────────────────────────────

class DecisionObs(Base):
    """Final triage decision for a (vulnerability, asset) pair.

    Actions follow SSVC-inspired taxonomy:
    - patch_now:     Apply vendor patch immediately (SLA: 24h)
    - mitigate_now:  Apply compensating control immediately (SLA: 24h)
    - patch_window:  Schedule patch in next maintenance window (SLA: 7-30d)
    - monitor:       Add to watch list, re-evaluate periodically
    - accept:        Risk accepted with documentation
    """
    __tablename__ = "decision_obs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)

    # Decision
    action = Column(String(32), nullable=False)  # patch_now, mitigate_now, patch_window, monitor, accept
    confidence = Column(Float, nullable=True)  # 0.0–1.0

    # Evidence chain (which layers contributed)
    evidence_chain_json = Column(JSONB, nullable=True)
    # Example: {
    #   "affectedness": {"status": "affected", "source": "sbom"},
    #   "reachability": {"is_reachable": true, "type": "network"},
    #   "weaponization": {"kev": true, "poc": false},
    #   "controls": {"waf_active": true, "effectiveness": 0.7},
    #   "policy_inputs": {"asset_criticality": "high", "cvss": 9.8}
    # }

    # Policy that produced this decision
    policy_name = Column(String(64), nullable=True)
    policy_version = Column(String(16), nullable=True)

    # Timing
    decided_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    sla_deadline = Column(DateTime, nullable=True)  # when must the action be completed

    # Human override
    overridden_by = Column(String(128), nullable=True)
    override_reason = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="decisions")

    __table_args__ = (
        Index("ix_decision_asset_vuln", "asset_id", "vulnerability_id"),
        Index("ix_decision_action", "action"),
    )
