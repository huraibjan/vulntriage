#!/usr/bin/env python3
"""Experiment 3: SHAP Feature Group Ablation.

IEEE Reviewer Revision — Section 4.5

Quantifies the contribution of each feature group to exploitability prediction
using two complementary methods:

Method A — Leave-One-Group-Out (LOGO):
  For each feature group, zero-out all features in that group on the held-out
  test set (model weights unchanged) and measure the PR-AUC drop vs. the
  baseline.  This estimates the predictive contribution of each group.

Method B — Built-in XGBoost importance aggregated by group:
  Sum each group's feature gain importances from the trained model.  This
  shows which features the model actually relies on during inference.

Feature groups (aligned with app/features/ablation.py FEATURE_GROUPS):
  ┌──────────────────────┬──────────────────────────────────────────────┐
  │ Group                │ Features                                     │
  ├──────────────────────┼──────────────────────────────────────────────┤
  │ cvss_core            │ cvss_base_score, cvss_version_31             │
  │ cvss_vector          │ attack_vector, complexity, CIA impacts, …    │
  │ temporal             │ days_since_published, days_since_poc         │
  │ enrichment_safe      │ epss_score                                   │
  │ exploit_signals      │ kev_flag, poc_flag, metasploit_flag, …      │
  │ cwe                  │ cwe_injection, cwe_auth_bypass, …            │
  │ text                 │ description_length, description_word_count   │
  │ network              │ product_count, reference_count               │
  │ composite            │ composite_exploit_score                      │
  └──────────────────────┴──────────────────────────────────────────────┘

Usage (from project root):
    python experiments/shap_feature_ablation.py

Results are saved to results/shap_feature_ablation.json.
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
from app.features.ablation import FEATURE_GROUPS
from app.features.builder import build_all_features, build_labels_df, time_aware_split
from app.ingest.label_builder import get_excluded_features
from app.ml.tabular.train import TABULAR_FEATURES

settings = get_settings()
MODELS_DIR = Path("models")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY_NAME = "kev_strict"

# Feature groups relevant to the TABULAR_FEATURES list used in train.py
# (subset of FEATURE_GROUPS from ablation.py, mapped to columns that exist
#  in TABULAR_FEATURES so ablation operates on the actual trained features)
TABULAR_FEATURE_GROUPS: dict[str, list[str]] = {
    "cvss_core": [
        "cvss_base_score",
        "cvss_version_31",
    ],
    "cvss_vector": [
        "cvss_attack_vector",
        "cvss_attack_complexity",
        "cvss_privileges_required",
        "cvss_user_interaction",
        "cvss_scope",
        "cvss_confidentiality_impact",
        "cvss_integrity_impact",
        "cvss_availability_impact",
        "cvss_is_network",
        "cvss_no_privs",
        "cvss_no_interaction",
        "cvss_scope_changed",
        "cvss_cia_total",
    ],
    "temporal": [
        "days_since_published",
        "days_since_poc",
    ],
    "enrichment_safe": [
        "epss_score",
    ],
    "exploit_signals": [
        "kev_flag",
        "poc_exploitdb_flag",
        "metasploit_flag",
        "exploit_signal_count",
    ],
    "cwe": [
        "cwe_injection",
        "cwe_input_validation",
        "cwe_path_traversal",
        "cwe_information_disclosure",
        "cwe_auth_bypass",
        "cwe_race_condition",
        "cwe_file_upload",
        "cwe_deserialization",
        "cwe_memory_safety",
        "cwe_ssrf",
        "cwe_other",
        "cwe_count",
    ],
    "text": [
        "description_length",
        "description_word_count",
    ],
    "network": [
        "product_count",
        "reference_count",
    ],
    "composite": [
        "composite_exploit_score",
    ],
}


# ── Helpers ───────────────────────────────────────────────────────────────

def pr_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    try:
        return float(average_precision_score(y_true, y_score))
    except ValueError:
        return 0.0


def load_tabular_model():
    path = MODELS_DIR / "xgb_kev_strict_full.joblib"
    if not path.exists():
        candidates = sorted(MODELS_DIR.glob("xgb_kev_strict*.joblib"))
        if not candidates:
            raise FileNotFoundError(f"No XGB kev_strict model in {MODELS_DIR}/")
        path = candidates[-1]
    model = joblib.load(path)
    print(f"  Loaded: {path.name}")
    return model


def importance_by_group(model, feature_names: list[str]) -> dict[str, float]:
    """Aggregate XGBoost gain importance by feature group."""
    importances = dict(zip(feature_names, model.feature_importances_.tolist()))
    group_imp: dict[str, float] = {}

    for group_name, group_feats in TABULAR_FEATURE_GROUPS.items():
        total = sum(importances.get(f, 0.0) for f in group_feats if f in importances)
        group_imp[group_name] = round(total, 6)

    # Normalise to sum to 1
    total_imp = sum(group_imp.values()) or 1.0
    return {k: round(v / total_imp, 4) for k, v in group_imp.items()}


# ── Main experiment ───────────────────────────────────────────────────────

def run() -> dict:
    t0 = time.time()
    print("=" * 70)
    print("  Experiment 3: Feature Group Ablation (SHAP-style LOGO)")
    print("=" * 70)

    # ── 1. Load data ─────────────────────────────────────────────────────
    print(f"\n[1/4] Loading features (asof={ASOF_DATE}) …")
    with get_session() as session:
        features_df = build_all_features(session, ASOF_DATE)
        labels_df = build_labels_df(session, policy_name=POLICY_NAME)

    merged = features_df.merge(labels_df, on="vuln_id", how="inner")
    train_df, test_df = time_aware_split(merged, CUTOFF_DATE)
    print(f"  Train: {len(train_df):,}  |  Test: {len(test_df):,}")

    # Build feature matrix with all TABULAR_FEATURES (model was trained on these)
    # kev_strict excludes kev_flag from training; we respect that here
    excluded = get_excluded_features(POLICY_NAME)
    model_features = [f for f in TABULAR_FEATURES if f not in excluded]

    X_test = test_df[model_features].fillna(0).astype(float)
    y_test = test_df["exploited"].astype(int).values

    n_pos = int(y_test.sum())
    print(f"  Test positives: {n_pos}/{len(y_test)} ({100*n_pos/len(y_test):.1f}%)")

    # ── 2. Load model & baseline ─────────────────────────────────────────
    print("\n[2/4] Loading tabular model …")
    model = load_tabular_model()

    p_baseline = model.predict_proba(X_test)[:, 1]
    baseline_auc = pr_auc(y_test, p_baseline)
    print(f"  Baseline PR-AUC (full model): {baseline_auc:.4f}")

    # ── 3. Method A — Leave-One-Group-Out ────────────────────────────────
    print("\n[3/4] Method A: Leave-One-Group-Out (LOGO) ablation …")
    print(f"  {'Group':<20} {'PR-AUC':>8} {'Δ PR-AUC':>10} {'Features zeroed':>16}")
    print("  " + "-" * 60)

    logo_results = []
    for group_name, group_feats in TABULAR_FEATURE_GROUPS.items():
        # Only zero features that are actually in the model's feature set
        feats_to_zero = [f for f in group_feats if f in model_features]
        if not feats_to_zero:
            continue

        X_ablated = X_test.copy()
        X_ablated[feats_to_zero] = 0.0

        p_ablated = model.predict_proba(X_ablated)[:, 1]
        ablated_auc = pr_auc(y_test, p_ablated)
        delta = ablated_auc - baseline_auc

        print(f"  {group_name:<20} {ablated_auc:>8.4f} {delta:>+10.4f} "
              f"{len(feats_to_zero):>16}")

        logo_results.append({
            "group": group_name,
            "pr_auc": round(ablated_auc, 4),
            "delta_pr_auc": round(delta, 4),
            "n_features_zeroed": len(feats_to_zero),
            "features_zeroed": feats_to_zero,
        })

    # Sort by absolute impact (most impactful first)
    logo_results.sort(key=lambda x: x["delta_pr_auc"])

    # ── 4. Method B — built-in gain importance by group ──────────────────
    print("\n[4/4] Method B: XGBoost gain importance by group …")
    group_importance = importance_by_group(model, model_features)

    print(f"  {'Group':<20} {'Gain share':>12}")
    print("  " + "-" * 34)
    for grp, share in sorted(group_importance.items(), key=lambda x: -x[1]):
        bar = "█" * int(share * 40)
        print(f"  {grp:<20} {share:>10.4f}  {bar}")

    elapsed = time.time() - t0
    result = {
        "experiment": "shap_feature_group_ablation",
        "method": "leave_one_group_out + xgb_gain_importance",
        "policy": POLICY_NAME,
        "cutoff_date": CUTOFF_DATE,
        "asof_date": str(ASOF_DATE),
        "n_test": len(y_test),
        "n_positives_test": n_pos,
        "baseline_pr_auc": round(baseline_auc, 4),
        "model_features_count": len(model_features),
        "excluded_circular_features": sorted(excluded),
        "logo_ablation": logo_results,
        "gain_importance_by_group": group_importance,
        "elapsed_seconds": round(elapsed, 1),
    }

    out = RESULTS_DIR / "shap_feature_ablation.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"\n  Results saved → {out}")

    return result


if __name__ == "__main__":
    run()
