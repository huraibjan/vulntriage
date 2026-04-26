"""Stage 1: Tabular XGBoost model for exploitability prediction.

Handles class imbalance, feature importance, and probability output.
Supports time-aware splitting and comprehensive evaluation metrics.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
)

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)

# Features used by the tabular model (must align with builder.py output)
TABULAR_FEATURES: List[str] = [
    "composite_exploit_score",
    "cvss_attack_complexity",
    "cvss_attack_vector",
    "cvss_availability_impact",
    "cvss_base_score",
    "cvss_cia_total",
    "cvss_confidentiality_impact",
    "cvss_integrity_impact",
    "cvss_is_network",
    "cvss_no_interaction",
    "cvss_no_privs",
    "cvss_privileges_required",
    "cvss_scope",
    "cvss_scope_changed",
    "cvss_user_interaction",
    "cvss_version_31",
    "cwe_auth_bypass",
    "cwe_count",
    "cwe_deserialization",
    "cwe_file_upload",
    "cwe_information_disclosure",
    "cwe_injection",
    "cwe_input_validation",
    "cwe_memory_safety",
    "cwe_other",
    "cwe_path_traversal",
    "cwe_race_condition",
    "cwe_ssrf",
    "days_since_poc",
    "days_since_published",
    "description_length",
    "description_word_count",
    "epss_score",
    "exploit_signal_count",
    "metasploit_flag",
    "poc_exploitdb_flag",
    "product_count",
    "reference_count",
]


def prepare_data(
    features_df: pd.DataFrame,
    labels_df: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Join features and labels, return X and y."""
    merged = features_df.merge(labels_df, on="vuln_id", how="inner")

    # Ensure all expected features exist
    for col in TABULAR_FEATURES:
        if col not in merged.columns:
            merged[col] = 0.0

    X = merged[TABULAR_FEATURES].fillna(0).astype(float)
    y = merged["exploited"].astype(int)

    return X, y


def train_xgboost(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> xgb.XGBClassifier:
    """Train an XGBoost classifier with class imbalance handling.

    Returns the fitted model.
    """
    settings = get_settings()

    # Compute scale_pos_weight for imbalance
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    scale_pos_weight = n_neg / max(n_pos, 1)

    default_params = {
        "n_estimators": 200,
        "max_depth": 6,
        "learning_rate": 0.1,
        "scale_pos_weight": scale_pos_weight,
        "objective": "binary:logistic",
        "eval_metric": "aucpr",
        "random_state": settings.random_seed,
        "use_label_encoder": False,
        "tree_method": "hist",
    }
    if params:
        default_params.update(params)

    model = xgb.XGBClassifier(**default_params)
    model.fit(
        X_train,
        y_train,
        verbose=False,
    )

    log.info(
        "xgb_trained",
        n_train=len(X_train),
        n_pos=n_pos,
        n_neg=n_neg,
        scale_pos_weight=round(scale_pos_weight, 2),
    )
    return model


def evaluate_model(
    model: xgb.XGBClassifier,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    *,
    feature_names: Optional[List[str]] = None,
    top_k_values: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Compute comprehensive evaluation metrics.

    Args:
        feature_names: Actual column names used for training. If None,
            falls back to X_test.columns (preferred) or TABULAR_FEATURES.

    Returns a dict with all metrics for reporting.
    """
    if top_k_values is None:
        top_k_values = get_settings().top_k_list

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)

    # Core metrics
    metrics: Dict[str, Any] = {
        "pr_auc": float(average_precision_score(y_test, y_prob)),
        "brier_score": float(brier_score_loss(y_test, y_prob)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
    }

    # ROC-AUC (may fail with single class)
    try:
        metrics["roc_auc"] = float(roc_auc_score(y_test, y_prob))
    except ValueError:
        metrics["roc_auc"] = 0.0

    # Top-K Precision and Recall
    top_k_precision: Dict[str, float] = {}
    top_k_recall: Dict[str, float] = {}

    ranked_indices = np.argsort(-y_prob)  # descending
    total_positives = int(y_test.sum())

    for k in top_k_values:
        k_actual = min(k, len(y_test))
        top_k_idx = ranked_indices[:k_actual]
        top_k_labels = y_test.iloc[top_k_idx]
        hits = int(top_k_labels.sum())
        top_k_precision[f"precision@{k}"] = hits / k_actual if k_actual > 0 else 0.0
        top_k_recall[f"recall@{k}"] = hits / total_positives if total_positives > 0 else 0.0

    metrics["top_k_precision"] = top_k_precision
    metrics["top_k_recall"] = top_k_recall

    # PR curve data (for plotting)
    precision_curve, recall_curve, thresholds = precision_recall_curve(y_test, y_prob)
    metrics["pr_curve"] = {
        "precision": precision_curve.tolist(),
        "recall": recall_curve.tolist(),
    }

    # Feature importance — use actual column names, not hardcoded list
    importance = model.feature_importances_
    names = feature_names or list(X_test.columns)
    if len(names) != len(importance):
        log.warning(
            "feature_name_mismatch",
            n_names=len(names),
            n_importance=len(importance),
        )
        names = [f"f{i}" for i in range(len(importance))]
    feat_imp = sorted(
        zip(names, importance.tolist()),
        key=lambda x: x[1],
        reverse=True,
    )
    metrics["feature_importance"] = [
        {"feature": name, "importance": round(imp, 4)}
        for name, imp in feat_imp[:15]
    ]

    log.info("xgb_evaluated", pr_auc=metrics["pr_auc"], brier=metrics["brier_score"])
    return metrics


def predict(
    model: xgb.XGBClassifier,
    features: Dict[str, Any],
) -> float:
    """Predict exploitability probability for a single vulnerability."""
    row = {col: features.get(col, 0.0) for col in TABULAR_FEATURES}
    X = pd.DataFrame([row])[TABULAR_FEATURES].fillna(0).astype(float)
    prob = model.predict_proba(X)[:, 1][0]
    return float(prob)


def save_model(model: xgb.XGBClassifier, path: Optional[Path] = None) -> Path:
    """Save the trained model to disk."""
    if path is None:
        path = get_settings().models_dir / "xgb_kev_strict_full.joblib"
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    log.info("model_saved", path=str(path))
    return path


def load_model(path: Optional[Path] = None) -> xgb.XGBClassifier:
    """Load a trained model from disk."""
    if path is None:
        path = get_settings().models_dir / "xgb_kev_strict_full.joblib"
    model = joblib.load(path)
    log.info("model_loaded", path=str(path))
    return model


# ── Baseline implementations ─────────────────────────────────────────────

def cvss_baseline(
    X_test: pd.DataFrame,
    y_test: pd.Series,
    *,
    top_k_values: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """CVSS-only baseline: rank by CVSS base score."""
    if top_k_values is None:
        top_k_values = get_settings().top_k_list

    y_score = X_test["cvss_base_score"].values / 10.0  # normalise to [0,1]
    return _baseline_metrics("cvss_only", y_score, y_test, top_k_values)


def epss_baseline(
    X_test: pd.DataFrame,
    y_test: pd.Series,
    *,
    top_k_values: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """EPSS-only baseline: rank by EPSS score."""
    if top_k_values is None:
        top_k_values = get_settings().top_k_list

    y_score = X_test["epss_score"].values
    return _baseline_metrics("epss_only", y_score, y_test, top_k_values)


def kev_baseline(
    X_test: pd.DataFrame,
    y_test: pd.Series,
    *,
    top_k_values: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """KEV-first baseline: KEV items ranked first, then by CVSS."""
    if top_k_values is None:
        top_k_values = get_settings().top_k_list

    # Score: kev_flag * 1.0 + cvss_base / 100 (KEV dominates)
    y_score = X_test["kev_flag"].values + X_test["cvss_base_score"].values / 100.0
    return _baseline_metrics("kev_first", y_score, y_test, top_k_values)


def _baseline_metrics(
    name: str,
    y_score: np.ndarray,
    y_test: pd.Series,
    top_k_values: List[int],
) -> Dict[str, Any]:
    """Compute standard metrics for a baseline ranker."""
    metrics: Dict[str, Any] = {"name": name}

    try:
        metrics["pr_auc"] = float(average_precision_score(y_test, y_score))
    except ValueError:
        metrics["pr_auc"] = 0.0

    metrics["brier_score"] = float(brier_score_loss(y_test, np.clip(y_score, 0, 1)))

    ranked = np.argsort(-y_score)
    total_pos = int(y_test.sum())

    top_k_prec: Dict[str, float] = {}
    top_k_rec: Dict[str, float] = {}
    for k in top_k_values:
        k_actual = min(k, len(y_test))
        hits = int(y_test.iloc[ranked[:k_actual]].sum())
        top_k_prec[f"precision@{k}"] = hits / k_actual if k_actual > 0 else 0.0
        top_k_rec[f"recall@{k}"] = hits / total_pos if total_pos > 0 else 0.0

    metrics["top_k_precision"] = top_k_prec
    metrics["top_k_recall"] = top_k_rec

    return metrics
