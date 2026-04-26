"""Ingestion orchestrator – loads providers, normalises, persists to Postgres + Qdrant."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.models import (
    EmbeddingMeta,
    LabelObservation,
    SignalObservation,
    Vulnerability,
)

log = get_logger(__name__)


def ingest_vulnerabilities(
    records: List[Dict[str, Any]],
    session: Session,
    *,
    source: str = "vulndb",
) -> int:
    """Persist normalised vulnerability records to Postgres.

    Deduplicates by (source, vuldb_id) or cve_id.
    Returns number of new records inserted.
    """
    inserted = 0
    for rec in records:
        # Check for existing
        existing = None
        if rec.get("cve_id"):
            existing = session.query(Vulnerability).filter_by(cve_id=rec["cve_id"]).first()
        if not existing and rec.get("vuldb_id"):
            existing = (
                session.query(Vulnerability)
                .filter_by(source=source, vuldb_id=rec["vuldb_id"])
                .first()
            )

        if existing:
            log.debug("skipping_duplicate", cve_id=rec.get("cve_id"), vuldb_id=rec.get("vuldb_id"))
            _upsert_signals(existing.id, rec.get("_signals", {}), session)
            continue

        vuln = Vulnerability(
            id=uuid4(),
            source=rec.get("source", source),
            cve_id=rec.get("cve_id"),
            vuldb_id=rec.get("vuldb_id"),
            published_at=rec.get("published_at"),
            last_modified_at=rec.get("last_modified_at"),
            title=rec.get("title"),
            description=rec.get("description"),
            cvss_version=rec.get("cvss_version"),
            cvss_vector=rec.get("cvss_vector"),
            cvss_base_score=rec.get("cvss_base_score"),
            cwe_ids=rec.get("cwe_ids"),
            references_json=rec.get("references_json"),
            affected_products_json=rec.get("affected_products_json"),
            raw_source_json=rec.get("raw_source_json"),
        )
        session.add(vuln)
        session.flush()  # get the id

        # Insert signal observations
        _upsert_signals(vuln.id, rec.get("_signals", {}), session)

        inserted += 1

    session.commit()
    log.info("ingestion_complete", inserted=inserted, total=len(records))
    return inserted


def _upsert_signals(
    vuln_id: Any,
    signals: Dict[str, Any],
    session: Session,
) -> None:
    """Insert signal_observation rows from provider metadata."""
    now = datetime.utcnow()

    signal_mappings = {
        "epss_score": ("epss", "value_num"),
        "kev_flag": ("kev", "value_bool"),
        "poc_exploitdb": ("poc_exploitdb", "value_bool"),
        "metasploit_module": ("metasploit", "value_bool"),
    }

    for key, (signal_type, col) in signal_mappings.items():
        val = signals.get(key)
        if val is None:
            continue

        # Skip false booleans (no signal observed)
        if isinstance(val, bool) and not val:
            continue

        obs = SignalObservation(
            vulnerability_id=vuln_id,
            signal_type=signal_type,
            observed_at=now,
            source="vulndb_ingest",
        )
        if col == "value_num":
            obs.value_num = float(val)
        elif col == "value_bool":
            obs.value_bool = bool(val)

        session.add(obs)


def ingest_signal_records(
    records: List[Dict[str, Any]],
    session: Session,
) -> int:
    """Persist enrichment signal records (EPSS, KEV) to signal_observation.

    Each record must have: cve_id, signal_type, observed_at, and a value field.
    """
    inserted = 0
    for rec in records:
        cve_id = rec.get("cve_id")
        if not cve_id:
            continue

        vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
        if not vuln:
            log.debug("signal_no_vuln", cve_id=cve_id)
            continue

        obs = SignalObservation(
            vulnerability_id=vuln.id,
            signal_type=rec["signal_type"],
            observed_at=rec.get("observed_at", datetime.utcnow()),
            value_num=rec.get("value_num"),
            value_bool=rec.get("value_bool"),
            value_text=rec.get("value_text"),
            source=rec.get("source"),
            evidence_ref=rec.get("evidence_ref"),
        )
        session.add(obs)
        inserted += 1

    session.commit()
    log.info("signals_ingested", count=inserted)
    return inserted


def build_labels(
    session: Session,
    *,
    policy: str = "composite",
) -> int:
    """Build exploitability labels from signal observations.

    Policies:
        - composite: exploited=1 if any of KEV/PoC/Metasploit signals exist
        - kev_only:  exploited=1 if KEV flag is True
        - poc_only:  exploited=1 if PoC/ExploitDB flag is True
    """
    vulns = session.query(Vulnerability).all()
    created = 0

    for vuln in vulns:
        signals = {s.signal_type: s for s in vuln.signals}

        if policy == "kev_only":
            exploited = bool(signals.get("kev") and signals["kev"].value_bool)
            source = "kev"
        elif policy == "poc_only":
            exploited = bool(
                (signals.get("poc_exploitdb") and signals["poc_exploitdb"].value_bool)
                or (signals.get("metasploit") and signals["metasploit"].value_bool)
            )
            source = "poc"
        else:  # composite
            exploited = bool(
                (signals.get("kev") and signals["kev"].value_bool)
                or (signals.get("poc_exploitdb") and signals["poc_exploitdb"].value_bool)
                or (signals.get("metasploit") and signals["metasploit"].value_bool)
            )
            source = "composite"

        # Check if label already exists
        existing = (
            session.query(LabelObservation)
            .filter_by(vulnerability_id=vuln.id, label_type="exploited")
            .first()
        )
        if existing:
            continue

        label = LabelObservation(
            vulnerability_id=vuln.id,
            label_type="exploited",
            label_value=1 if exploited else 0,
            label_asof=datetime.utcnow(),
            label_source=source,
            label_rationale=f"Policy={policy}; signals={list(signals.keys())}",
        )
        session.add(label)
        created += 1

    session.commit()
    log.info("labels_built", count=created, policy=policy)
    return created
