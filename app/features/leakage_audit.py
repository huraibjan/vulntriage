"""Leakage audit — systematic check for temporal, label, and entity leakage.

Produces a JSON report that can be included in thesis appendix as
evidence of experimental integrity.

Leakage Types
-------------
1. **Temporal leakage**: Feature observation timestamp > as-of date.
2. **Label leakage**: Feature column is directly derived from the
   label signal (e.g., ``kev_flag`` used as feature when KEV is label).
3. **Entity leakage**: Same (asset, CVE) pair appears in both train
   and test sets (relevant for asset-level experiments).
4. **Distributional leakage**: Train/test distributions are suspiciously
   similar (optional, statistical test).

Usage
-----
::

    from app.features.leakage_audit import audit_feature_set
    report = audit_feature_set(features_df, labels_df, asof_date,
                               policy_name="kev_strict")
    # report is a dict; write to JSON for thesis appendix
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import numpy as np
import pandas as pd

from app.core.logging import get_logger

log = get_logger(__name__)


def audit_feature_set(
    features_df: pd.DataFrame,
    labels_df: pd.DataFrame,
    asof_date: date,
    *,
    policy_name: Optional[str] = None,
    label_type: Optional[str] = None,
    train_ids: Optional[Set[str]] = None,
    test_ids: Optional[Set[str]] = None,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a comprehensive leakage audit on a feature/label dataset.

    Parameters
    ----------
    features_df : DataFrame
        Feature matrix (rows = samples, columns = features + meta).
    labels_df : DataFrame
        Label DataFrame with at least ``vuln_id`` and a label column.
    asof_date : date
        The as-of date used for feature construction.
    policy_name : str, optional
        CVE-level label policy name (for label leakage check).
    label_type : str, optional
        Asset-level label type (for actionability label leakage check).
    train_ids : set[str], optional
        Set of sample IDs in the training set (for entity leakage check).
    test_ids : set[str], optional
        Set of sample IDs in the test set.
    output_path : str, optional
        If provided, write JSON report to this path.

    Returns
    -------
    dict
        Audit report with findings per leakage type.
    """
    report: Dict[str, Any] = {
        "audit_timestamp": datetime.utcnow().isoformat(),
        "asof_date": str(asof_date),
        "n_features": len([c for c in features_df.columns if c not in _META_COLS]),
        "n_samples": len(features_df),
        "n_labels": len(labels_df),
        "checks": {},
        "violations": [],
        "overall_pass": True,
    }

    # ── Check 1: Temporal leakage ────────────────────────────────────
    temporal = _check_temporal_leakage(features_df, asof_date)
    report["checks"]["temporal_leakage"] = temporal
    if not temporal["pass"]:
        report["overall_pass"] = False
        report["violations"].extend(temporal.get("violations", []))

    # ── Check 2: Label leakage (CVE-level) ───────────────────────────
    if policy_name:
        label_leak = _check_label_leakage_cve(features_df, policy_name)
        report["checks"]["label_leakage_cve"] = label_leak
        if not label_leak["pass"]:
            report["overall_pass"] = False
            report["violations"].extend(label_leak.get("violations", []))

    # ── Check 3: Label leakage (actionability) ───────────────────────
    if label_type:
        action_leak = _check_label_leakage_actionability(features_df, label_type)
        report["checks"]["label_leakage_actionability"] = action_leak
        if not action_leak["pass"]:
            report["overall_pass"] = False
            report["violations"].extend(action_leak.get("violations", []))

    # ── Check 4: Entity leakage ──────────────────────────────────────
    if train_ids is not None and test_ids is not None:
        entity_leak = _check_entity_leakage(train_ids, test_ids)
        report["checks"]["entity_leakage"] = entity_leak
        if not entity_leak["pass"]:
            report["overall_pass"] = False
            report["violations"].extend(entity_leak.get("violations", []))

    # ── Check 5: Feature correlation with label ──────────────────────
    label_col = _find_label_column(labels_df)
    if label_col:
        corr_check = _check_suspicious_correlations(features_df, labels_df, label_col)
        report["checks"]["suspicious_correlations"] = corr_check

    # ── Summary ──────────────────────────────────────────────────────
    n_violations = len(report["violations"])
    report["summary"] = {
        "total_checks": len(report["checks"]),
        "total_violations": n_violations,
        "verdict": "PASS" if report["overall_pass"] else f"FAIL ({n_violations} violations)",
    }

    log.info("leakage_audit_complete",
             verdict=report["summary"]["verdict"],
             violations=n_violations)

    # ── Write to file ────────────────────────────────────────────────
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        log.info("leakage_audit_saved", path=output_path)

    return report


# ── Meta columns to exclude from feature checks ─────────────────────

_META_COLS = {"vuln_id", "cve_id", "published_at", "asset_id", "asset_name"}


# ── Check implementations ───────────────────────────────────────────

def _check_temporal_leakage(
    features_df: pd.DataFrame,
    asof_date: date,
) -> Dict[str, Any]:
    """Check if published_at timestamps exceed the as-of date.

    This catches cases where features were computed for CVEs that
    hadn't been published yet as of the training cutoff.
    """
    result: Dict[str, Any] = {"pass": True, "violations": []}

    if "published_at" not in features_df.columns:
        result["note"] = "No published_at column; cannot check temporal leakage"
        return result

    pub_dates = pd.to_datetime(features_df["published_at"], errors="coerce")
    asof_dt = pd.Timestamp(asof_date)
    future_mask = pub_dates > asof_dt
    n_future = int(future_mask.sum())

    result["total_samples"] = len(features_df)
    result["future_samples"] = n_future
    result["future_fraction"] = round(n_future / max(len(features_df), 1), 4)

    if n_future > 0:
        result["pass"] = False
        result["violations"].append(
            f"{n_future} samples have published_at > asof_date ({asof_date})"
        )
        # Sample some violators — use cve_id if available, else index
        id_col = "cve_id" if "cve_id" in features_df.columns else None
        if id_col:
            violators = features_df.loc[future_mask, id_col].head(5).tolist()
        else:
            violators = features_df.loc[future_mask].index[:5].tolist()
        result["sample_violators"] = violators

    return result


def _check_label_leakage_cve(
    features_df: pd.DataFrame,
    policy_name: str,
) -> Dict[str, Any]:
    """Check if any features are derived from the label signal (CVE-level)."""
    from app.ingest.label_builder import get_excluded_features

    result: Dict[str, Any] = {"pass": True, "violations": []}

    try:
        excluded = get_excluded_features(policy_name)
    except ValueError as e:
        result["note"] = f"Could not load policy: {e}"
        return result

    feature_cols = set(features_df.columns) - _META_COLS
    leaked = feature_cols & excluded

    result["policy_name"] = policy_name
    result["excluded_features"] = sorted(excluded)
    result["feature_columns"] = sorted(feature_cols)
    result["leaked_features"] = sorted(leaked)

    if leaked:
        result["pass"] = False
        result["violations"].append(
            f"Features {sorted(leaked)} are derived from label signal "
            f"for policy '{policy_name}'"
        )

    return result


def _check_label_leakage_actionability(
    features_df: pd.DataFrame,
    label_type: str,
) -> Dict[str, Any]:
    """Check if actionability features leak into their own labels."""
    from app.ingest.actionability_label_builder import get_excluded_features_for_label

    result: Dict[str, Any] = {"pass": True, "violations": []}

    try:
        excluded = get_excluded_features_for_label(label_type)
    except ValueError as e:
        result["note"] = f"Could not load label policy: {e}"
        return result

    feature_cols = set(features_df.columns) - _META_COLS
    leaked = feature_cols & excluded

    result["label_type"] = label_type
    result["excluded_features"] = sorted(excluded)
    result["leaked_features"] = sorted(leaked)

    if leaked:
        result["pass"] = False
        result["violations"].append(
            f"Features {sorted(leaked)} leak into label type '{label_type}'"
        )

    return result


def _check_entity_leakage(
    train_ids: Set[str],
    test_ids: Set[str],
) -> Dict[str, Any]:
    """Check if any sample IDs appear in both train and test sets."""
    result: Dict[str, Any] = {"pass": True, "violations": []}

    overlap = train_ids & test_ids
    result["train_size"] = len(train_ids)
    result["test_size"] = len(test_ids)
    result["overlap_count"] = len(overlap)
    result["overlap_fraction"] = round(len(overlap) / max(len(test_ids), 1), 4)

    if overlap:
        result["pass"] = False
        result["violations"].append(
            f"{len(overlap)} sample IDs appear in both train and test sets"
        )
        result["sample_overlaps"] = sorted(list(overlap))[:10]

    return result


def _check_suspicious_correlations(
    features_df: pd.DataFrame,
    labels_df: pd.DataFrame,
    label_col: str,
    *,
    threshold: float = 0.95,
) -> Dict[str, Any]:
    """Flag features with suspiciously high correlation to the label.

    A correlation > threshold usually indicates direct leakage.
    """
    result: Dict[str, Any] = {"pass": True, "threshold": threshold}

    # Merge features and labels
    merge_key = "vuln_id" if "vuln_id" in labels_df.columns else "cve_id"
    if merge_key not in features_df.columns or merge_key not in labels_df.columns:
        result["note"] = f"Cannot merge: {merge_key} not in both DataFrames"
        return result

    merged = features_df.merge(
        labels_df[[merge_key, label_col]], on=merge_key, how="inner"
    )

    if len(merged) == 0:
        result["note"] = "No samples after merge"
        return result

    feature_cols = [c for c in features_df.columns if c not in _META_COLS]
    suspicious: List[Dict[str, Any]] = []

    for col in feature_cols:
        if col not in merged.columns:
            continue
        try:
            corr = merged[col].astype(float).corr(merged[label_col].astype(float))
            if not np.isnan(corr) and abs(corr) > threshold:
                suspicious.append({"feature": col, "correlation": round(corr, 4)})
        except (ValueError, TypeError):
            continue

    result["checked_features"] = len(feature_cols)
    result["suspicious_features"] = suspicious

    if suspicious:
        result["pass"] = False
        result["note"] = (
            f"{len(suspicious)} features have |correlation| > {threshold} with label"
        )

    return result


def _find_label_column(labels_df: pd.DataFrame) -> Optional[str]:
    """Identify the label column in a DataFrame."""
    candidates = [
        "exploited", "label",
        "affected_asset_label", "reachable_label",
        "control_gap_label", "action_required_label",
    ]
    for c in candidates:
        if c in labels_df.columns:
            return c
    return None


# ── Convenience: full pipeline audit ────────────────────────────────

def audit_experiment(
    features_df: pd.DataFrame,
    labels_df: pd.DataFrame,
    asof_date: date,
    policy_name: str,
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    *,
    label_type: Optional[str] = None,
    output_dir: str = "reports",
) -> Dict[str, Any]:
    """Run full leakage audit for an experiment and save report.

    Combines temporal, label, entity, and correlation checks.
    """
    # Determine train/test IDs
    id_col = "vuln_id" if "vuln_id" in train_df.columns else "cve_id"
    if "asset_id" in train_df.columns:
        # Asset-level: composite ID
        train_ids = {
            f"{row[id_col]}_{row['asset_id']}"
            for _, row in train_df.iterrows()
        }
        test_ids = {
            f"{row[id_col]}_{row['asset_id']}"
            for _, row in test_df.iterrows()
        }
    else:
        train_ids = set(train_df[id_col].astype(str))
        test_ids = set(test_df[id_col].astype(str))

    output_path = str(Path(output_dir) / f"leakage_audit_{policy_name}.json")

    return audit_feature_set(
        features_df=features_df,
        labels_df=labels_df,
        asof_date=asof_date,
        policy_name=policy_name,
        label_type=label_type,
        train_ids=train_ids,
        test_ids=test_ids,
        output_path=output_path,
    )
