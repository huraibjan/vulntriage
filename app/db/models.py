"""SQLAlchemy ORM models for the vulnerability intelligence system.

Tables
------
- vulnerability       – core CVE / VulnDB record
- signal_observation  – time-stamped enrichment signals (EPSS, KEV, PoC…)
- label_observation   – ground-truth labels with provenance
- feature_snapshot    – materialized feature vectors per (vuln, asof)
- model_run           – experiment metadata (git sha, params, metrics)
- prediction          – per-vulnerability scored output
- embedding_meta      – pointer from vuln → Qdrant point
"""

from __future__ import annotations

import uuid
from datetime import datetime, date

from sqlalchemy import (
    Boolean,
    Column,
    Date,
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
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


# ── Core vulnerability record ──────────────────────────────────────────────

class Vulnerability(Base):
    __tablename__ = "vulnerability"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String(32), nullable=False, default="vulndb")
    cve_id = Column(String(32), nullable=True, index=True)
    vuldb_id = Column(String(32), nullable=True, index=True)
    published_at = Column(DateTime, nullable=True, index=True)
    last_modified_at = Column(DateTime, nullable=True)
    title = Column(Text, nullable=True)
    description = Column(Text, nullable=True)

    # CVSS
    cvss_version = Column(String(8), nullable=True)
    cvss_vector = Column(Text, nullable=True)  # CVSS 4.0 vectors can be very long
    cvss_base_score = Column(Float, nullable=True)

    # Structured metadata stored as JSONB
    cwe_ids = Column(JSONB, nullable=True)            # ["CWE-79", ...]
    references_json = Column(JSONB, nullable=True)     # [{"url": ..., "source": ...}]
    affected_products_json = Column(JSONB, nullable=True)  # [{"vendor": ..., "product": ...}]
    raw_source_json = Column(JSONB, nullable=True)     # full original record for audit

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    signals = relationship("SignalObservation", back_populates="vulnerability", cascade="all, delete-orphan")
    labels = relationship("LabelObservation", back_populates="vulnerability", cascade="all, delete-orphan")
    features = relationship("FeatureSnapshot", back_populates="vulnerability", cascade="all, delete-orphan")
    predictions = relationship("Prediction", back_populates="vulnerability", cascade="all, delete-orphan")
    embedding_meta = relationship("EmbeddingMeta", back_populates="vulnerability", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("source", "vuldb_id", name="uq_source_vuldb"),
        Index("ix_vuln_published", "published_at"),
    )


# ── Time-stamped enrichment signals ────────────────────────────────────────

class SignalObservation(Base):
    """Each row is one observation of one signal at a point in time."""
    __tablename__ = "signal_observation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)
    signal_type = Column(String(64), nullable=False)  # epss, kev, poc_exploitdb, metasploit, ...
    observed_at = Column(DateTime, nullable=False, index=True)

    value_num = Column(Float, nullable=True)        # e.g. EPSS score
    value_bool = Column(Boolean, nullable=True)     # e.g. KEV flag
    value_text = Column(Text, nullable=True)        # e.g. ExploitDB reference ID
    source = Column(String(64), nullable=True)
    evidence_ref = Column(Text, nullable=True)      # URL or citation

    vulnerability = relationship("Vulnerability", back_populates="signals")

    __table_args__ = (
        Index("ix_signal_vuln_type", "vulnerability_id", "signal_type"),
    )


# ── Ground-truth labels ───────────────────────────────────────────────────

class LabelObservation(Base):
    """Exploitability label with provenance and temporal anchor."""
    __tablename__ = "label_observation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)
    label_type = Column(String(32), nullable=False, default="exploited")  # exploited | weaponized | …
    label_value = Column(Integer, nullable=False)     # 0 or 1
    label_asof = Column(DateTime, nullable=False)     # when this label was determined
    label_source = Column(String(64), nullable=True)  # kev | exploitdb | composite
    label_rationale = Column(Text, nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="labels")

    __table_args__ = (
        Index("ix_label_vuln", "vulnerability_id", "label_type"),
    )


# ── Materialized feature snapshots ────────────────────────────────────────

class FeatureSnapshot(Base):
    """Pre-computed feature row for a vulnerability as-of a date."""
    __tablename__ = "feature_snapshot"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)
    asof = Column(Date, nullable=False)
    features_json = Column(JSONB, nullable=False)
    feature_version = Column(String(16), nullable=False, default="v1")

    vulnerability = relationship("Vulnerability", back_populates="features")

    __table_args__ = (
        UniqueConstraint("vulnerability_id", "asof", "feature_version", name="uq_feat_vuln_asof"),
    )


# ── Experiment tracking ───────────────────────────────────────────────────

class ModelRun(Base):
    """Metadata for one training / evaluation run."""
    __tablename__ = "model_run"

    run_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime, default=datetime.utcnow)
    code_git_sha = Column(String(40), nullable=True)
    data_versions_json = Column(JSONB, nullable=True)
    params_json = Column(JSONB, nullable=True)
    metrics_json = Column(JSONB, nullable=True)

    predictions = relationship("Prediction", back_populates="model_run", cascade="all, delete-orphan")


class Prediction(Base):
    """Per-vulnerability prediction output from a model run."""
    __tablename__ = "prediction"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(UUID(as_uuid=True), ForeignKey("model_run.run_id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False)
    asof = Column(Date, nullable=False)

    p_stage1 = Column(Float, nullable=True)
    p_stage2 = Column(Float, nullable=True)
    p_final = Column(Float, nullable=True)
    calibration_method = Column(String(32), nullable=True)
    explanation_json = Column(JSONB, nullable=True)

    model_run = relationship("ModelRun", back_populates="predictions")
    vulnerability = relationship("Vulnerability", back_populates="predictions")


# ── Embedding metadata ────────────────────────────────────────────────────

class EmbeddingMeta(Base):
    """Maps a vulnerability to its Qdrant vector point."""
    __tablename__ = "embedding_meta"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerability.id", ondelete="CASCADE"), nullable=False, unique=True)
    collection_name = Column(String(64), nullable=False, default="vuln_text")
    qdrant_point_id = Column(String(64), nullable=False)
    embedding_model = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    vulnerability = relationship("Vulnerability", back_populates="embedding_meta")
