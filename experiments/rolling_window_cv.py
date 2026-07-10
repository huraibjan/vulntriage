#!/usr/bin/env python3
"""Experiment 2: Rolling Window Cross-Validation.

IEEE Reviewer Revision — Section 4.4

Tests temporal model stability by training on historical data and evaluating
on successive future windows.  This guards against temporal leakage and
demonstrates that the model generalises across time.

Window scheme (train-on-past, test-on-next-year):
  Window 1:  train < 2022-06-01,  test 2022-06-01 – 2023-06-01
  Window 2:  train < 2023-06-01,  test 2023-06-01 – 2024-06-01
  Window 3:  train < 2024-06-01,  test 2024-06-01 – 2025-06-01

For each window:
  - Re-train XGBoost tabular model from scratch
  - Evaluate on the corresponding test window
  - Report PR-AUC, ROC-AUC, Brier score, Precision@50, Recall@50

Usage (from project root):
    python experiments/rolling_window_cv.py

Results are saved to results/rolling_window_cv.json.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.settings import get_settings
from app.db.session import get_session
from app.features.builder import build_all_features, build_labels_df
from app.ingest.label_builder import get_excluded_features
from app.ml.tabular.train import (
    TABULAR_FEATURES,
    train_xgboost,
    evaluate_model,
)

settings = get_settings()
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

ASOF_DATE = date(2026, 3, 3)
POLICY_NAME = "kev_strict"

# Rolling window definitions: (train_cutoff, test_start, test_end)
WINDOWS = [
    ("2022-06-01", "2022-06-01", "2023-06-01"),
    ("2023-06-01", "2023-06-01", "2024-06-01"),
    ("2024-06-01", "2024-06-01", "2025-06-01"),
]


# ── Metric helpers ────────────────────────────────────────────────────────

def compute_metrics(y_true: np.ndarray, y_score: np.ndarray) -> dict:
    metrics = {}
    try:
        metrics["pr_auc"] = round(float(average_precision_score(y_true, y_score)), 4)
    except ValueError:
        metrics["pr_auc"] = 0.0

    try:
        metrics["roc_auc"] = round(float(roc_auc_score(y_true, y_score)), 4)
    except ValueError:
        metrics["roc_auc"] = 0.0

    metrics["brier_score"] = round(float(brier_score_loss(y_true, y_score)), 4)

    # Precision@50 and Recall@50
    ranked = np.argsort(-y_score)
    total_pos = int(y_true.sum())
    for k in [50, 100]:
        k_actual = min(k, len(y_true))
        hits = int(y_true[ranked[:k_actual]].sum())
        metrics[f"precision@{k}"] = round(hits / k_actual, 4) if k_actual else 0.0
        metrics[f"recall@{k}"] = round(hits / total_pos, 4) if total_pos else 0.0

    return metrics


def split_window(
    df: pd.DataFrame,
    train_cutoff: str,
    test_start: str,
    test_end: str,
    date_col: str = "published_at",
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split DataFrame into train (< cutoff) and test (start ≤ x < end)."""
    dates = pd.to_datetime(df[date_col], errors="coerce", format="ISO8601")
    tc = pd.Timestamp(train_cutoff)
    ts = pd.Timestamp(test_start)
    te = pd.Timestamp(test_end)

    train_mask = dates < tc
    test_mask = (dates >= ts) & (dates < te)

    return df[train_mask].copy(), df[test_mask].copy()


# ── Main experiment ───────────────────────────────────────────────────────

def run() -> dict:
    t0 = time.time()
    print("=" * 70)
    print("  Experiment 2: Rolling Window Cross-Validation")
    print("=" * 70)

    # ── 1. Load full dataset once ─────────────────────────────────────────
    print(f"\n[1/3] Loading features from database (asof={ASOF_DATE}) …")
    with get_session() as session:
        features_df = build_all_features(session, ASOF_DATE)
        labels_df = build_labels_df(session, policy_name=POLICY_NAME)

    merged = features_df.merge(labels_df, on="vuln_id", how="inner")
    print(f"  Total records: {len(merged):,}")
    print(f"  Positives:     {int(merged['exploited'].sum()):,}")

    # Exclude circular features for this policy
    excluded = get_excluded_features(POLICY_NAME)
    safe_features = [f for f in TABULAR_FEATURES if f not in excluded]
    print(f"  Safe features: {len(safe_features)} (excluded {len(excluded)} circular)")

    # ── 2. Also compute single static split as anchor baseline ────────────
    print("\n[2/3] Static baseline (train < 2024-06, test ≥ 2024-06) …")

    static_cutoff = "2024-06-01"
    dates = pd.to_datetime(merged["published_at"], errors="coerce", format="ISO8601")
    tc = pd.Timestamp(static_cutoff)
    static_train = merged[dates < tc]
    static_test = merged[dates >= tc]

    if len(static_train) > 0 and len(static_test) > 0:
        X_str = static_train[safe_features].fillna(0).astype(float)
        y_str = static_train["exploited"].astype(int)
        X_ste = static_test[safe_features].fillna(0).astype(float)
        y_ste = static_test["exploited"].astype(int)

        m_static = train_xgboost(X_str, y_str)
        p_static = m_static.predict_proba(X_ste)[:, 1]
        static_metrics = compute_metrics(y_ste.values, p_static)
        print(f"  Static baseline PR-AUC = {static_metrics['pr_auc']:.4f}")
    else:
        static_metrics = {"note": "insufficient data"}
        print("  Static baseline: insufficient data")

    # ── 3. Rolling window evaluation ──────────────────────────────────────
    print("\n[3/3] Rolling window experiments …")
    window_results = []

    for idx, (train_cutoff, test_start, test_end) in enumerate(WINDOWS, 1):
        wt0 = time.time()
        print(f"\n  Window {idx}: train < {train_cutoff}  |  test [{test_start}, {test_end})")

        train_df, test_df = split_window(merged, train_cutoff, test_start, test_end)
        n_train_pos = int(train_df["exploited"].sum()) if len(train_df) else 0
        n_test_pos = int(test_df["exploited"].sum()) if len(test_df) else 0

        print(f"    Train: {len(train_df):,} ({n_train_pos} positives)")
        print(f"    Test:  {len(test_df):,} ({n_test_pos} positives)")

        if len(train_df) < 10 or n_train_pos < 2:
            print("    SKIP: too little training data")
            window_results.append({
                "window": idx,
                "train_cutoff": train_cutoff,
                "test_start": test_start,
                "test_end": test_end,
                "n_train": len(train_df),
                "n_test": len(test_df),
                "n_train_pos": n_train_pos,
                "n_test_pos": n_test_pos,
                "metrics": None,
                "skip_reason": "insufficient training data",
            })
            continue

        if len(test_df) < 5 or n_test_pos < 1:
            print("    SKIP: too little test data")
            window_results.append({
                "window": idx,
                "train_cutoff": train_cutoff,
                "test_start": test_start,
                "test_end": test_end,
                "n_train": len(train_df),
                "n_test": len(test_df),
                "n_train_pos": n_train_pos,
                "n_test_pos": n_test_pos,
                "metrics": None,
                "skip_reason": "insufficient test data",
            })
            continue

        X_train = train_df[safe_features].fillna(0).astype(float)
        y_train = train_df["exploited"].astype(int)
        X_test = test_df[safe_features].fillna(0).astype(float)
        y_test = test_df["exploited"].astype(int)

        model = train_xgboost(X_train, y_train)
        y_prob = model.predict_proba(X_test)[:, 1]
        metrics = compute_metrics(y_test.values, y_prob)

        elapsed_w = time.time() - wt0
        print(f"    PR-AUC={metrics['pr_auc']:.4f}  ROC-AUC={metrics['roc_auc']:.4f}  "
              f"Brier={metrics['brier_score']:.4f}  ({elapsed_w:.1f}s)")

        window_results.append({
            "window": idx,
            "train_cutoff": train_cutoff,
            "test_start": test_start,
            "test_end": test_end,
            "n_train": len(train_df),
            "n_test": len(test_df),
            "n_train_pos": n_train_pos,
            "n_test_pos": n_test_pos,
            "metrics": metrics,
            "training_seconds": round(elapsed_w, 1),
        })

    # Summary table
    print("\n" + "-" * 70)
    print(f"  {'Window':<10} {'Cutoff':<13} {'Train N':>8} {'Test N':>7} {'PR-AUC':>8}")
    print("-" * 70)
    for r in window_results:
        m = r["metrics"] or {}
        auc = f"{m.get('pr_auc', '-'):.4f}" if m else "skipped"
        print(f"  W{r['window']:<9} {r['train_cutoff']:<13} {r['n_train']:>8,} "
              f"{r['n_test']:>7,} {auc:>8}")

    elapsed = time.time() - t0
    result = {
        "experiment": "rolling_window_cv",
        "policy": POLICY_NAME,
        "asof_date": str(ASOF_DATE),
        "n_features": len(safe_features),
        "excluded_circular_features": sorted(excluded),
        "static_baseline": static_metrics,
        "windows": window_results,
        "elapsed_seconds": round(elapsed, 1),
    }

    out = RESULTS_DIR / "rolling_window_cv.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"\n  Results saved → {out}")

    return result


if __name__ == "__main__":
    run()
