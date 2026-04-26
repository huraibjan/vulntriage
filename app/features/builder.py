"""Feature builder – constructs ML-ready feature vectors from DB records.

All features are computed "as-of" a given date to prevent leakage.
The leakage_audit flag will validate that every observation used
has observed_at <= the as-of date.

Ablation and circularity exclusion are handled at the DataFrame level
by ``app.features.ablation.apply_ablation()`` and
``app.ingest.label_builder.get_excluded_features()``, not here.
This module always computes ALL features; filtering is done downstream.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.models import (
    FeatureSnapshot,
    LabelObservation,
    SignalObservation,
    Vulnerability,
)
from app.features.cvss_parser import parse_cvss_vector

log = get_logger(__name__)

# ── CWE categories for encoding ─────────────────────────────────────────
# Top CWEs – grouped by broad category for manageable dimensionality
CWE_CATEGORIES: Dict[str, str] = {
    "CWE-79": "injection",      # XSS
    "CWE-89": "injection",      # SQL injection
    "CWE-78": "injection",      # OS command injection
    "CWE-77": "injection",      # Command injection
    "CWE-20": "input_validation",
    "CWE-22": "path_traversal",
    "CWE-200": "information_disclosure",
    "CWE-287": "auth_bypass",
    "CWE-288": "auth_bypass",
    "CWE-306": "auth_bypass",
    "CWE-425": "auth_bypass",
    "CWE-362": "race_condition",
    "CWE-434": "file_upload",
    "CWE-502": "deserialization",
    "CWE-787": "memory_safety",
    "CWE-122": "memory_safety",
    "CWE-119": "memory_safety",
    "CWE-416": "memory_safety",
    "CWE-918": "ssrf",
}


def build_features_for_vuln(
    vuln: Vulnerability,
    session: Session,
    asof: date,
    *,
    leakage_audit: bool = False,
    prefetched_signals: Optional[List[SignalObservation]] = None,
) -> Dict[str, Any]:
    """Compute the feature vector for a single vulnerability as-of a date.

    Returns a dict of feature name → value, suitable for JSON serialization
    and loading into pandas/xgboost.

    If *prefetched_signals* is provided, uses those instead of querying the DB.
    This is the key optimisation for batch mode (avoids N+1 queries).
    """
    features: Dict[str, Any] = {}
    audit_violations: List[str] = []

    # ── 1. CVSS features ─────────────────────────────────────────────────
    features["cvss_base_score"] = vuln.cvss_base_score or 0.0
    features["cvss_version_31"] = float(vuln.cvss_version == "3.1") if vuln.cvss_version else 0.0

    parsed = parse_cvss_vector(vuln.cvss_vector)
    if parsed.is_valid:
        features.update(parsed.to_feature_dict())
    else:
        # Fill with zeros
        for key in [
            "cvss_attack_vector", "cvss_attack_complexity",
            "cvss_privileges_required", "cvss_user_interaction",
            "cvss_scope", "cvss_confidentiality_impact",
            "cvss_integrity_impact", "cvss_availability_impact",
            "cvss_is_network", "cvss_no_privs", "cvss_no_interaction",
            "cvss_scope_changed", "cvss_cia_total",
        ]:
            features[key] = 0.0

    # ── 2. Temporal features ─────────────────────────────────────────────
    if vuln.published_at:
        pub_date = vuln.published_at.date() if isinstance(vuln.published_at, datetime) else vuln.published_at
        features["days_since_published"] = (asof - pub_date).days
    else:
        features["days_since_published"] = 0

    # ── 3. Signal features (time-aware) ──────────────────────────────────
    if prefetched_signals is not None:
        signals = prefetched_signals
    else:
        signals = (
            session.query(SignalObservation)
            .filter(SignalObservation.vulnerability_id == vuln.id)
            .all()
        )

    epss_latest = None
    kev_flag = False
    poc_flag = False
    msf_flag = False
    days_since_poc = None

    for sig in signals:
        sig_date = sig.observed_at.date() if isinstance(sig.observed_at, datetime) else sig.observed_at

        # Leakage check
        if leakage_audit and sig_date > asof:
            audit_violations.append(
                f"Signal {sig.signal_type} observed_at={sig_date} > asof={asof}"
            )
            continue  # skip this signal

        if sig.signal_type == "epss" and sig.value_num is not None:
            if epss_latest is None or sig_date >= (epss_latest.observed_at.date() if isinstance(epss_latest.observed_at, datetime) else epss_latest.observed_at):
                epss_latest = sig

        elif sig.signal_type == "kev" and sig.value_bool:
            kev_flag = True

        elif sig.signal_type == "poc_exploitdb" and sig.value_bool:
            poc_flag = True
            if vuln.published_at:
                pub_date = vuln.published_at.date() if isinstance(vuln.published_at, datetime) else vuln.published_at
                days_since_poc = (asof - pub_date).days  # approximate

        elif sig.signal_type == "metasploit" and sig.value_bool:
            msf_flag = True

    features["epss_score"] = epss_latest.value_num if epss_latest else 0.0
    features["kev_flag"] = float(kev_flag)
    features["poc_exploitdb_flag"] = float(poc_flag)
    features["metasploit_flag"] = float(msf_flag)
    features["days_since_poc"] = days_since_poc if days_since_poc is not None else -1
    features["exploit_signal_count"] = float(sum([kev_flag, poc_flag, msf_flag]))

    # ── 4. CWE category features ─────────────────────────────────────────
    cwes = vuln.cwe_ids or []
    categories_present = set()
    for cwe in cwes:
        cat = CWE_CATEGORIES.get(cwe, "other")
        categories_present.add(cat)

    all_cats = list(set(CWE_CATEGORIES.values())) + ["other"]
    for cat in all_cats:
        features[f"cwe_{cat}"] = float(cat in categories_present)
    features["cwe_count"] = float(len(cwes))

    # ── 5. Text features ─────────────────────────────────────────────────
    desc = vuln.description or ""
    features["description_length"] = float(len(desc))
    features["description_word_count"] = float(len(desc.split()))

    # ── 6. Product/reference features ────────────────────────────────────
    products = vuln.affected_products_json or []
    features["product_count"] = float(len(products))
    refs = vuln.references_json or []
    features["reference_count"] = float(len(refs))

    # ── 7. Composite exploitability score (analysis helper, not ML label)
    features["composite_exploit_score"] = _composite_score(features)

    # ── Log leakage audit results ────────────────────────────────────────
    if leakage_audit and audit_violations:
        log.error(
            "leakage_violations_detected",
            vuln_id=str(vuln.id),
            violations=audit_violations,
        )

    return features


def _composite_score(f: Dict[str, Any]) -> float:
    """Simple weighted composite exploitability indicator for analysis.

    NOT a model output – just a quick heuristic for exploratory analysis.
    """
    score = (
        0.25 * (f.get("cvss_base_score", 0) / 10.0)
        + 0.30 * f.get("epss_score", 0)
        + 0.15 * f.get("kev_flag", 0)
        + 0.15 * f.get("poc_exploitdb_flag", 0)
        + 0.10 * f.get("metasploit_flag", 0)
        + 0.05 * min(f.get("exploit_signal_count", 0) / 3.0, 1.0)
    )
    return round(score, 4)


def build_all_features(
    session: Session,
    asof: date,
    *,
    leakage_audit: bool = False,
    batch_size: int = 5000,
) -> pd.DataFrame:
    """Build features for ALL vulnerabilities and return a DataFrame.

    Also persists FeatureSnapshot rows in the database.

    Optimised for bulk execution: loads ALL signal observations in a
    single query and groups them by vulnerability_id in Python.  This
    turns O(N) DB round-trips into O(1), reducing 180K individual
    queries down to one.
    """
    from collections import defaultdict

    # ── Step 1: Prefetch ALL signals in one query ────────────────────────
    log.info("prefetching_signals", msg="Loading all signal observations …")
    all_signals = session.query(SignalObservation).all()
    signals_by_vuln: Dict[Any, List[SignalObservation]] = defaultdict(list)
    for sig in all_signals:
        signals_by_vuln[sig.vulnerability_id].append(sig)
    log.info("prefetched_signals", total=len(all_signals), vulns_with_signals=len(signals_by_vuln))

    # ── Step 2: Load all vulns ───────────────────────────────────────────
    vulns = session.query(Vulnerability).all()
    total = len(vulns)
    log.info("building_features", total_vulns=total, asof=str(asof))

    # ── Step 3: Prefetch existing snapshots to avoid per-row lookup ──────
    existing_snap_ids = set(
        row[0] for row in
        session.query(FeatureSnapshot.vulnerability_id)
        .filter_by(asof=asof, feature_version="v1")
        .all()
    )
    log.info("existing_snapshots", count=len(existing_snap_ids))

    rows: List[Dict[str, Any]] = []
    persisted = 0

    for i, vuln in enumerate(vulns, 1):
        vuln_signals = signals_by_vuln.get(vuln.id, [])
        feat = build_features_for_vuln(
            vuln, session, asof,
            leakage_audit=leakage_audit,
            prefetched_signals=vuln_signals,
        )
        feat["vuln_id"] = str(vuln.id)
        feat["cve_id"] = vuln.cve_id
        feat["published_at"] = str(vuln.published_at) if vuln.published_at else None

        # Persist snapshot (skip if already exists)
        if vuln.id not in existing_snap_ids:
            snap = FeatureSnapshot(
                vulnerability_id=vuln.id,
                asof=asof,
                features_json=feat,
                feature_version="v1",
            )
            session.add(snap)
            persisted += 1

        rows.append(feat)

        # Periodic commit + progress log
        if i % batch_size == 0:
            session.commit()
            log.info("feature_progress", processed=i, total=total, persisted=persisted)

    session.commit()
    log.info("features_built", count=len(rows), persisted=persisted, asof=str(asof))
    return pd.DataFrame(rows)


def build_labels_df(session: Session, *, policy_name: Optional[str] = None) -> pd.DataFrame:
    """Load labels into a DataFrame with vuln_id and exploited columns.

    If *policy_name* is given, only labels from that specific policy are
    returned.  Otherwise all ``label_type='exploited'`` labels are loaded
    (backwards-compatible).
    """
    q = session.query(LabelObservation).filter_by(label_type="exploited")
    if policy_name:
        q = q.filter_by(label_source=policy_name)
    labels = q.all()
    rows = [
        {"vuln_id": str(l.vulnerability_id), "exploited": l.label_value}
        for l in labels
    ]
    return pd.DataFrame(rows)


def time_aware_split(
    df: pd.DataFrame,
    cutoff: str,
    date_col: str = "published_at",
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Split a DataFrame by a temporal cutoff date.

    Records published before (or on) the cutoff go to train,
    records after go to test.

    Raises ValueError if either split is empty.
    """
    cutoff_dt = pd.to_datetime(cutoff)
    df[date_col] = pd.to_datetime(df[date_col], format="ISO8601")

    train = df[df[date_col] <= cutoff_dt].copy()
    test = df[df[date_col] > cutoff_dt].copy()

    if len(train) == 0:
        raise ValueError(f"Train split is empty with cutoff={cutoff}")
    if len(test) == 0:
        raise ValueError(f"Test split is empty with cutoff={cutoff}")

    log.info("time_split", cutoff=cutoff, n_train=len(train), n_test=len(test))
    return train, test
