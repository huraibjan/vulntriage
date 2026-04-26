"""Evaluation slices – subpopulation analysis for fairness and robustness.

Slices the test set into meaningful sub-populations so we can report
performance not just "overall" but for the segments that matter most
to defenders.

Slice Definitions
-----------------
1. **cvss_critical** – CVSS ≥ 9.0 (critical severity)
2. **cvss_medium_low** – CVSS < 7.0 (medium/low — where triage is hardest)
3. **has_kev** – CVEs in CISA KEV catalog
4. **no_kev** – CVEs NOT in KEV (vast majority)
5. **first_30_days** – Published within last 30 days of the test window
6. **after_365_days** – Published more than 1 year before the test window
7. **cwe_top25** – CWEs in the MITRE CWE Top-25 2024 list

Usage
-----
::

    from app.ml.evaluation_slices import get_slice, list_slices, apply_slices

    # Get one slice
    mask = get_slice("cvss_critical", df)
    df_critical = df[mask]

    # Get all slices at once
    sliced_dfs = apply_slices(df)
    for name, sub_df in sliced_dfs.items():
        metrics = evaluate_model(model, sub_df)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import pandas as pd

from app.core.logging import get_logger

log = get_logger(__name__)


# ── MITRE CWE Top-25 (2024) ────────────────────────────────────────────

CWE_TOP25_2024 = {
    "CWE-787",   # Out-of-bounds Write
    "CWE-79",    # Cross-site Scripting
    "CWE-89",    # SQL Injection
    "CWE-416",   # Use After Free
    "CWE-78",    # OS Command Injection
    "CWE-20",    # Improper Input Validation
    "CWE-125",   # Out-of-bounds Read
    "CWE-22",    # Path Traversal
    "CWE-352",   # CSRF
    "CWE-434",   # Unrestricted Upload
    "CWE-862",   # Missing Authorization
    "CWE-476",   # NULL Pointer Dereference
    "CWE-287",   # Improper Authentication
    "CWE-190",   # Integer Overflow
    "CWE-502",   # Deserialization
    "CWE-77",    # Command Injection
    "CWE-119",   # Buffer Overflow
    "CWE-798",   # Hard-coded Credentials
    "CWE-918",   # SSRF
    "CWE-306",   # Missing Authentication
    "CWE-362",   # Race Condition
    "CWE-269",   # Improper Privilege Management
    "CWE-94",    # Code Injection
    "CWE-863",   # Incorrect Authorization
    "CWE-276",   # Incorrect Default Permissions
}


# ── Slice definitions ──────────────────────────────────────────────────

@dataclass(frozen=True)
class SliceDefinition:
    """Defines a sub-population evaluation slice."""

    name: str
    description: str
    min_samples: int = 50  # Minimum samples for the slice to be meaningful

    def apply(self, df: pd.DataFrame) -> pd.Series:
        """Return a boolean mask selecting rows in this slice."""
        raise NotImplementedError


class CvssCriticalSlice(SliceDefinition):
    """CVSS base score ≥ 9.0."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "cvss_base_score"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] >= 9.0


class CvssMediumLowSlice(SliceDefinition):
    """CVSS base score < 7.0 — the triage grey zone."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "cvss_base_score"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] < 7.0


class HasKevSlice(SliceDefinition):
    """CVEs with kev_flag = 1."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "kev_flag"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] == 1.0


class NoKevSlice(SliceDefinition):
    """CVEs without KEV flag (vast majority)."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "kev_flag"
        if col not in df.columns:
            return pd.Series(True, index=df.index)
        return df[col] != 1.0


class First30DaysSlice(SliceDefinition):
    """CVEs published within 30 days of the test window end."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "days_since_published"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] <= 30


class After365DaysSlice(SliceDefinition):
    """CVEs published more than 1 year before the as-of date."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "days_since_published"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] > 365


class CweTop25Slice(SliceDefinition):
    """CVEs with at least one CWE in the MITRE Top-25 2024 list."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        # CWE features are encoded as cwe_injection, cwe_memory_safety, etc.
        # We need to check the original cwe_ids if available, or use the
        # encoded features as a proxy

        # Check for raw cwe_ids column first
        if "cwe_ids" in df.columns:
            def _has_top25(cwes):
                if not cwes:
                    return False
                if isinstance(cwes, str):
                    import json
                    try:
                        cwes = json.loads(cwes)
                    except (json.JSONDecodeError, TypeError):
                        return False
                return bool(set(cwes) & CWE_TOP25_2024)
            return df["cwe_ids"].apply(_has_top25)

        # Fall back to encoded CWE category features
        # Memory safety, injection, auth_bypass are subsets of top-25
        top25_proxy_cols = [
            "cwe_injection",
            "cwe_memory_safety",
            "cwe_auth_bypass",
            "cwe_path_traversal",
            "cwe_deserialization",
            "cwe_ssrf",
            "cwe_file_upload",
            "cwe_race_condition",
        ]
        present = [c for c in top25_proxy_cols if c in df.columns]
        if not present:
            return pd.Series(False, index=df.index)
        return df[present].sum(axis=1) > 0


# ── Registry ───────────────────────────────────────────────────────────

SLICES: Dict[str, SliceDefinition] = {
    "cvss_critical": CvssCriticalSlice(
        name="cvss_critical",
        description="CVSS ≥ 9.0 (critical severity)",
    ),
    "cvss_medium_low": CvssMediumLowSlice(
        name="cvss_medium_low",
        description="CVSS < 7.0 (medium/low — triage grey zone)",
    ),
    "has_kev": HasKevSlice(
        name="has_kev",
        description="CVEs in CISA KEV catalog",
        min_samples=20,  # KEV is small
    ),
    "no_kev": NoKevSlice(
        name="no_kev",
        description="CVEs NOT in KEV catalog",
    ),
    "first_30_days": First30DaysSlice(
        name="first_30_days",
        description="Published within last 30 days (freshest CVEs)",
    ),
    "after_365_days": After365DaysSlice(
        name="after_365_days",
        description="Published >1 year ago (long-tail CVEs)",
    ),
    "cwe_top25": CweTop25Slice(
        name="cwe_top25",
        description="CWEs in MITRE CWE Top-25 2024",
    ),
}


# ── Asset-level slices (for actionability evaluation) ───────────────

class InternetFacingSlice(SliceDefinition):
    """Assets flagged as internet-facing."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "internet_facing_flag"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] == 1.0


class CrownJewelSlice(SliceDefinition):
    """Assets with criticality score ≥ 0.75 (high/critical)."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "asset_criticality_score"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] >= 0.75


class ReachableConfirmedSlice(SliceDefinition):
    """Assets with confirmed network reachability."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "network_reachable_flag"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] == 1.0


class HighControlCoverageSlice(SliceDefinition):
    """Assets with control_coverage_score ≥ 0.5."""

    def apply(self, df: pd.DataFrame) -> pd.Series:
        col = "control_coverage_score"
        if col not in df.columns:
            return pd.Series(False, index=df.index)
        return df[col] >= 0.5


# Register asset-level slices
ASSET_SLICES: Dict[str, SliceDefinition] = {
    "internet_facing": InternetFacingSlice(
        name="internet_facing",
        description="Internet-facing assets (highest exposure)",
        min_samples=10,
    ),
    "crown_jewel": CrownJewelSlice(
        name="crown_jewel",
        description="High/critical criticality assets",
        min_samples=10,
    ),
    "reachable_confirmed": ReachableConfirmedSlice(
        name="reachable_confirmed",
        description="Assets with confirmed network reachability",
        min_samples=10,
    ),
    "high_control_coverage": HighControlCoverageSlice(
        name="high_control_coverage",
        description="Assets with control coverage ≥ 0.5",
        min_samples=10,
    ),
}

# Add asset slices to the main registry
SLICES.update(ASSET_SLICES)


# ── Public API ─────────────────────────────────────────────────────────

def get_slice(name: str, df: pd.DataFrame) -> pd.Series:
    """Get a boolean mask for a named slice.

    Parameters
    ----------
    name : str
        Slice name (must be in SLICES).
    df : DataFrame
        Feature DataFrame to slice.

    Returns
    -------
    Series[bool]
        Boolean mask.
    """
    if name not in SLICES:
        raise ValueError(
            f"Unknown slice '{name}'. Available: {sorted(SLICES.keys())}"
        )
    return SLICES[name].apply(df)


def apply_slices(
    df: pd.DataFrame,
    *,
    slice_names: Optional[List[str]] = None,
    min_samples: bool = True,
) -> Dict[str, pd.DataFrame]:
    """Apply all (or selected) slices and return sub-DataFrames.

    Parameters
    ----------
    df : DataFrame
        Full test DataFrame.
    slice_names : list[str], optional
        Specific slices to apply. If None, applies all.
    min_samples : bool
        If True, skip slices with fewer than their min_samples threshold.

    Returns
    -------
    dict[str, DataFrame]
        Mapping of slice_name → filtered DataFrame.
        Always includes "overall" as the full DataFrame.
    """
    result: Dict[str, pd.DataFrame] = {"overall": df}
    names = slice_names or list(SLICES.keys())

    for name in names:
        if name not in SLICES:
            log.warning("unknown_slice", name=name)
            continue

        slice_def = SLICES[name]
        mask = slice_def.apply(df)
        sub_df = df[mask]

        if min_samples and len(sub_df) < slice_def.min_samples:
            log.warning(
                "slice_too_small",
                name=name,
                count=len(sub_df),
                min_required=slice_def.min_samples,
            )
            continue

        result[name] = sub_df
        log.info("slice_applied", name=name, count=len(sub_df))

    return result


def evaluate_slices(
    df: pd.DataFrame,
    y_true_col: str,
    y_pred_col: str,
    y_prob_col: Optional[str] = None,
    *,
    slice_names: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Compute metrics for each slice and return a summary table.

    Parameters
    ----------
    df : DataFrame
        Must contain the true label, predicted label, and optionally
        predicted probability columns.
    y_true_col : str
        Column name for true labels.
    y_pred_col : str
        Column name for predicted labels.
    y_prob_col : str, optional
        Column name for predicted probabilities (for AUC/PR-AUC).
    slice_names : list[str], optional
        Specific slices to evaluate.

    Returns
    -------
    DataFrame
        One row per slice with metrics columns.
    """
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    sliced = apply_slices(df, slice_names=slice_names)
    rows: List[Dict[str, Any]] = []

    for name, sub_df in sliced.items():
        y_true = sub_df[y_true_col].values
        y_pred = sub_df[y_pred_col].values

        metrics: Dict[str, Any] = {
            "slice": name,
            "n": len(sub_df),
            "n_positive": int(y_true.sum()),
            "positive_rate": float(y_true.mean()),
        }

        # Classification metrics
        if len(np.unique(y_true)) > 1:
            metrics["accuracy"] = round(accuracy_score(y_true, y_pred), 4)
            metrics["precision"] = round(precision_score(y_true, y_pred, zero_division=0), 4)
            metrics["recall"] = round(recall_score(y_true, y_pred, zero_division=0), 4)
            metrics["f1"] = round(f1_score(y_true, y_pred, zero_division=0), 4)

            if y_prob_col and y_prob_col in sub_df.columns:
                y_prob = sub_df[y_prob_col].values
                try:
                    metrics["roc_auc"] = round(roc_auc_score(y_true, y_prob), 4)
                except ValueError:
                    metrics["roc_auc"] = None
                try:
                    metrics["pr_auc"] = round(average_precision_score(y_true, y_prob), 4)
                except ValueError:
                    metrics["pr_auc"] = None
        else:
            # Only one class in this slice
            metrics["accuracy"] = round(accuracy_score(y_true, y_pred), 4)
            metrics["precision"] = None
            metrics["recall"] = None
            metrics["f1"] = None
            metrics["roc_auc"] = None
            metrics["pr_auc"] = None

        rows.append(metrics)

    result = pd.DataFrame(rows)
    log.info("slice_evaluation_complete", num_slices=len(rows))
    return result


def list_slices() -> List[Dict[str, str]]:
    """Return human-readable list of all available evaluation slices."""
    return [
        {
            "name": s.name,
            "description": s.description,
            "min_samples": s.min_samples,
        }
        for s in SLICES.values()
    ]
