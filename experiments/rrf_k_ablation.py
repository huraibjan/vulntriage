#!/usr/bin/env python3
"""Experiment 1: RRF k hyperparameter ablation.

IEEE Reviewer Revision — Section 4.3

Tests Reciprocal Rank Fusion (RRF) at k ∈ {10, 20, 30, 60, 100, 200} by
combining three independent ranking signals:
  - p_tabular : XGBoost tabular model probability
  - p_text    : Sentence-embedding logistic-head probability
  - p_epss    : EPSS score (external enrichment)

For each k, RRF fuses the three ranked lists into a combined exploitability
ranking.  PR-AUC on the held-out test set is the primary metric.

Baseline comparisons:
  - EPSS-only ranking
  - CVSS-only ranking
  - Stacking ensemble (meta-learner over the same three sources)

Usage (from project root):
    python experiments/rrf_k_ablation.py

Results are saved to results/rrf_k_ablation.json.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import date
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.settings import get_settings
from app.db.session import get_session
from app.features.builder import build_all_features, build_labels_df, time_aware_split
from app.features.ablation import get_ablation_config
from app.ingest.label_builder import get_excluded_features
from app.ml.tabular.train import TABULAR_FEATURES, prepare_data

settings = get_settings()
MODELS_DIR = Path("models")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY_NAME = "kev_strict"

K_VALUES = [10, 20, 30, 60, 100, 200]


# ── RRF core ─────────────────────────────────────────────────────────────

def reciprocal_rank_fusion(
    score_arrays: list[np.ndarray],
    k: int = 60,
) -> np.ndarray:
    """Compute RRF scores from multiple probability arrays.

    Each array is ranked (highest probability = rank 1).  The combined
    RRF score for item i is:
        score_rrf(i) = Σ 1 / (k + rank_j(i))

    Args:
        score_arrays: List of 1-D probability arrays, all same length.
        k: Smoothing constant (default 60, as in Cormack et al. 2009).

    Returns:
        1-D array of combined RRF scores (higher = more exploitable).
    """
    n = len(score_arrays[0])
    rrf_scores = np.zeros(n)

    for scores in score_arrays:
        # argsort descending → positions[i] is 0-based rank of item i
        order = np.argsort(-scores)
        ranks = np.empty(n, dtype=float)
        ranks[order] = np.arange(1, n + 1)  # 1-based
        rrf_scores += 1.0 / (k + ranks)

    return rrf_scores


# ── Helpers ───────────────────────────────────────────────────────────────

def pr_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    try:
        return float(average_precision_score(y_true, y_score))
    except ValueError:
        return 0.0


def load_tabular_model() -> object:
    path = MODELS_DIR / "xgb_kev_strict_full.joblib"
    if not path.exists():
        # Try any available kev_strict model
        candidates = list(MODELS_DIR.glob("xgb_kev_strict*.joblib"))
        if not candidates:
            raise FileNotFoundError(f"No XGB model found in {MODELS_DIR}")
        path = candidates[0]
    return joblib.load(path)


def load_text_model() -> object | None:
    for name in ["text_logreg_v2.joblib", "text_logreg.joblib"]:
        path = MODELS_DIR / name
        if path.exists():
            return joblib.load(path)
    return None


def load_text_embeddings(path: MODELS_DIR) -> object | None:
    for name in ["text_embedding_pipeline_v2.joblib", "text_embedding_pipeline.joblib"]:
        p = MODELS_DIR / name
        if p.exists():
            return joblib.load(p)
    return None


def get_text_probs(
    descriptions: pd.Series,
    text_model,
    emb_pipeline,
) -> np.ndarray:
    """Return text-model probabilities for a list of CVE descriptions."""
    if text_model is None or emb_pipeline is None:
        return np.zeros(len(descriptions))

    try:
        embeddings = emb_pipeline.transform(descriptions.tolist())
        return text_model.predict_proba(embeddings)[:, 1]
    except Exception as e:
        print(f"  [WARN] Text model prediction failed: {e}")
        return np.zeros(len(descriptions))


# ── Main experiment ───────────────────────────────────────────────────────

def run() -> dict:
    t0 = time.time()
    print("=" * 70)
    print("  Experiment 1: RRF k Hyperparameter Ablation")
    print("=" * 70)

    # ── 1. Load data ─────────────────────────────────────────────────────
    print(f"\n[1/4] Loading features from database (asof={ASOF_DATE}) …")
    with get_session() as session:
        features_df = build_all_features(session, ASOF_DATE)
        labels_df = build_labels_df(session, policy_name=POLICY_NAME)

    # Time-aware split
    merged = features_df.merge(labels_df, on="vuln_id", how="inner")
    train_df, test_df = time_aware_split(merged, CUTOFF_DATE)
    print(f"  Train: {len(train_df):,}  |  Test: {len(test_df):,}")

    # Prepare tabular X/y (exclude circular features for kev_strict)
    excluded = get_excluded_features(POLICY_NAME)
    safe_features = [f for f in TABULAR_FEATURES if f not in excluded]

    X_train = train_df[safe_features].fillna(0).astype(float)
    y_train = train_df["exploited"].astype(int)
    X_test = test_df[safe_features].fillna(0).astype(float)
    y_test = test_df["exploited"].astype(int)

    n_pos = int(y_test.sum())
    n_total = len(y_test)
    print(f"  Test positives: {n_pos}/{n_total} ({100*n_pos/n_total:.1f}%)")

    # ── 2. Load models & get probabilities ───────────────────────────────
    print("\n[2/4] Loading saved models …")
    tabular_model = load_tabular_model()
    text_model = load_text_model()
    emb_pipeline = load_text_embeddings(MODELS_DIR)

    print(f"  Tabular model: {tabular_model.__class__.__name__}")
    print(f"  Text model:    {'loaded' if text_model else 'NOT FOUND – using zeros'}")

    p_tabular = tabular_model.predict_proba(X_test)[:, 1]

    # EPSS scores (in safe_features if not excluded, otherwise from raw)
    if "epss_score" in test_df.columns:
        p_epss = test_df["epss_score"].fillna(0).values.astype(float)
    else:
        p_epss = np.zeros(len(y_test))

    descriptions = test_df.get("description", pd.Series([""] * len(test_df)))
    p_text = get_text_probs(descriptions, text_model, emb_pipeline)

    print(f"  p_tabular range: [{p_tabular.min():.3f}, {p_tabular.max():.3f}]")
    print(f"  p_epss    range: [{p_epss.min():.3f}, {p_epss.max():.3f}]")
    print(f"  p_text    range: [{p_text.min():.3f}, {p_text.max():.3f}]")

    # ── 3. Baselines ─────────────────────────────────────────────────────
    print("\n[3/4] Computing baseline metrics …")

    baselines = {
        "tabular_only": pr_auc(y_test.values, p_tabular),
        "epss_only": pr_auc(y_test.values, p_epss),
        "cvss_only": pr_auc(
            y_test.values,
            test_df["cvss_base_score"].fillna(0).values / 10.0,
        ),
    }

    if text_model is not None:
        baselines["text_only"] = pr_auc(y_test.values, p_text)

    # Try loading stacking ensemble
    stacking_pr_auc = None
    for name in ["stacking_4way.joblib", "stacking_3way.joblib", "stacking_ensemble.joblib"]:
        path = MODELS_DIR / name
        if path.exists():
            try:
                from app.ml.stacking.ensemble import StackingEnsemble
                ens = StackingEnsemble()
                ens.load(path)
                p_stacking = ens.predict({
                    "tabular": p_tabular,
                    "text": p_text,
                    "epss": p_epss,
                })
                stacking_pr_auc = pr_auc(y_test.values, p_stacking)
                baselines["stacking_ensemble"] = stacking_pr_auc
                print(f"  Stacking ensemble loaded from {name}")
            except Exception as e:
                print(f"  [WARN] Stacking ensemble failed: {e}")
            break

    print("  Baseline PR-AUC:")
    for name, val in baselines.items():
        print(f"    {name:<25} {val:.4f}")

    # ── 4. RRF k ablation ────────────────────────────────────────────────
    print("\n[4/4] Running RRF k ablation …")
    score_arrays = [p_tabular, p_text, p_epss]

    rrf_results = []
    for k in K_VALUES:
        rrf_scores = reciprocal_rank_fusion(score_arrays, k=k)
        auc = pr_auc(y_test.values, rrf_scores)
        rrf_results.append({"k": k, "pr_auc": round(auc, 4)})
        marker = " ← default" if k == 60 else ""
        print(f"  k={k:>4}  PR-AUC={auc:.4f}{marker}")

    # Best k
    best = max(rrf_results, key=lambda x: x["pr_auc"])
    print(f"\n  Best k: {best['k']} (PR-AUC={best['pr_auc']:.4f})")

    elapsed = time.time() - t0
    result = {
        "experiment": "rrf_k_ablation",
        "cutoff_date": CUTOFF_DATE,
        "policy": POLICY_NAME,
        "n_test": n_total,
        "n_positives_test": n_pos,
        "sources": ["tabular", "text", "epss"],
        "k_values_tested": K_VALUES,
        "rrf_results": rrf_results,
        "baselines": {k: round(v, 4) for k, v in baselines.items()},
        "best_k": best["k"],
        "best_k_pr_auc": best["pr_auc"],
        "elapsed_seconds": round(elapsed, 1),
    }

    out = RESULTS_DIR / "rrf_k_ablation.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"\n  Results saved → {out}")

    return result


if __name__ == "__main__":
    run()
