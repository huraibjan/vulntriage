#!/usr/bin/env python3
"""Experiment 3: Feature-Group Ablation (SHAP complement).

IEEE Reviewer Revision — addresses Reviewer 2 comment #6.

The paper reports SHAP top-5 features only.  This experiment quantifies the
contribution of each *feature group* to the tabular model's PR-AUC with three
complementary methods:

  Method A — Leave-One-Group-Out RETRAIN (gold standard):
    Retrain the same tuned XGBoost configuration with the group's columns
    removed; the PR-AUC drop vs. the all-features baseline is that group's
    marginal contribution.

  Method B — Inference-time zeroing (deployment perspective):
    Zero the group's columns on the test set under the UNCHANGED paper model
    (xgb_tuned_tabular_v2); measures reliance of the deployed model.

  Method C — XGBoost gain importance aggregated by group:
    What the deployed model's trees actually split on.

CONSISTENCY: uses the exact v2 data split (train < 2024-06-01, 15% val
carved out with seed 42) and the saved xgb_tuned_tabular_v2 model, whose
test PR-AUC (0.25069) is the paper's published tabular anchor.

Usage (from project root):
    python experiments/shap_feature_ablation.py

Results are saved to results/feature_group_ablation.json.
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
import xgboost as xgb
from sklearn.metrics import average_precision_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.models import FeatureSnapshot
from app.db.session import get_session
from app.features.ablation import get_feature_columns
from app.features.builder import build_labels_df, time_aware_split

MODELS_DIR = Path("models")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY = "kev_strict"
ABLATION = "no_circular"
SEED = 42
VAL_FRACTION = 0.15
PAPER_TABULAR_ANCHOR = 0.25069

# Tuned v2 hyper-parameters (scale_pos_weight recomputed per fit).
XGB_PARAMS = {
    "n_estimators": 414,
    "max_depth": 7,
    "learning_rate": 0.08742933234856033,
    "subsample": 0.987460777589654,
    "colsample_bytree": 0.6966521828215488,
    "min_child_weight": 3,
    "gamma": 0.2877938000832214,
    "reg_alpha": 1.6377473104949667,
    "reg_lambda": 2.617494451636084,
    "objective": "binary:logistic",
    "eval_metric": "aucpr",
    "tree_method": "hist",
    "random_state": SEED,
    "n_jobs": 4,
}


def group_of(col: str) -> str:
    """Map a no-circular feature column to its semantic group."""
    if col in ("cvss_base_score", "cvss_version_31"):
        return "cvss_core"
    if col.startswith("cvss_"):
        return "cvss_vector"
    if col.startswith("cwe_"):
        return "cwe"
    if col.startswith("description_"):
        return "text"
    if col == "epss_score":
        return "enrichment_epss"
    if col.startswith("days_since"):
        return "temporal"
    if col in ("product_count", "reference_count"):
        return "reference_network"
    return "asset_context"  # sbom/vex/reachability/controls/decision features


def pr_auc(y, p) -> float:
    try:
        return float(average_precision_score(y, p))
    except ValueError:
        return 0.0


def fit_xgb(X, y):
    n_pos = int(y.sum())
    params = dict(XGB_PARAMS)
    params["scale_pos_weight"] = (len(y) - n_pos) / max(n_pos, 1)
    model = xgb.XGBClassifier(**params)
    model.fit(X, y)
    return model


def run() -> dict:
    t0 = time.time()
    print("=" * 72)
    print("  Experiment 3: Feature-Group Ablation (R2 #6)")
    print("=" * 72)

    # ── 1. Reconstruct the exact v2 split ────────────────────────────────
    print(f"\n[1/5] Loading features (asof={ASOF_DATE}) …")
    with get_session() as session:
        snaps = session.query(FeatureSnapshot).filter_by(
            asof=ASOF_DATE, feature_version="v1"
        ).all()
        rows = []
        for s in snaps:
            feat = dict(s.features_json)
            feat["vuln_id"] = str(s.vulnerability_id)
            rows.append(feat)
        features_df = pd.DataFrame(rows)
        labels_df = build_labels_df(session, policy_name=POLICY)

    merged = features_df.merge(labels_df, on="vuln_id", how="inner")
    train_full, test_df = time_aware_split(merged, CUTOFF_DATE)
    y_full = train_full["exploited"].astype(int)
    train_df, _val_df = train_test_split(
        train_full, test_size=VAL_FRACTION, stratify=y_full, random_state=SEED
    )
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)

    feat_cols = get_feature_columns(ABLATION, policy_name=POLICY)
    available = [c for c in feat_cols if c in merged.columns]
    groups: dict[str, list[str]] = {}
    for c in available:
        groups.setdefault(group_of(c), []).append(c)

    X_train = train_df[available].fillna(0).astype(float)
    y_train = train_df["exploited"].astype(int)
    X_test = test_df[available].fillna(0).astype(float)
    y_test = test_df["exploited"].astype(int).values
    n_pos = int(y_test.sum())
    print(f"  Train: {len(train_df):,} | Test: {len(test_df):,} ({n_pos} pos)")
    print(f"  Features: {len(available)} in {len(groups)} groups:")
    for g, cols in sorted(groups.items()):
        print(f"    {g:<18} {len(cols):>2} features")

    # ── 2. Anchor check with the saved paper model ───────────────────────
    print("\n[2/5] Anchor check (saved xgb_tuned_tabular_v2) …")
    paper_model = joblib.load(MODELS_DIR / "xgb_tuned_tabular_v2.joblib")
    p_paper = paper_model.predict_proba(X_test)[:, 1]
    paper_auc = pr_auc(y_test, p_paper)
    ok = abs(paper_auc - PAPER_TABULAR_ANCHOR) < 1e-3
    print(f"  Saved-model test PR-AUC = {paper_auc:.5f} "
          f"(paper {PAPER_TABULAR_ANCHOR:.5f})  {'OK' if ok else 'MISMATCH!'}")

    # ── 3. Method A: retrain without each group ──────────────────────────
    print("\n[3/5] Method A: Leave-One-Group-Out RETRAIN …")
    retrain_baseline_model = fit_xgb(X_train, y_train)
    retrain_baseline = pr_auc(y_test, retrain_baseline_model.predict_proba(X_test)[:, 1])
    print(f"  Retrain baseline (all {len(available)} features): PR-AUC={retrain_baseline:.5f}")
    print(f"  {'Group':<18} {'PR-AUC w/o':>11} {'Δ vs base':>10} {'rel drop':>9}")
    print("  " + "-" * 52)

    method_a = []
    for g, cols in sorted(groups.items()):
        keep = [c for c in available if c not in cols]
        model_g = fit_xgb(X_train[keep], y_train)
        auc_g = pr_auc(y_test, model_g.predict_proba(X_test[keep])[:, 1])
        delta = auc_g - retrain_baseline
        rel = delta / retrain_baseline if retrain_baseline else 0.0
        print(f"  {g:<18} {auc_g:>11.5f} {delta:>+10.5f} {rel:>+8.1%}")
        method_a.append({
            "group": g, "n_features": len(cols),
            "pr_auc_without_group": round(auc_g, 5),
            "delta_pr_auc": round(delta, 5),
            "relative_drop": round(rel, 4),
        })
    method_a.sort(key=lambda r: r["delta_pr_auc"])

    # ── 4. Method B: inference-time zeroing on the paper model ───────────
    print("\n[4/5] Method B: inference-time zeroing (paper model unchanged) …")
    print(f"  {'Group':<18} {'PR-AUC zeroed':>13} {'Δ vs anchor':>12}")
    print("  " + "-" * 47)
    method_b = []
    for g, cols in sorted(groups.items()):
        X_z = X_test.copy()
        X_z[cols] = 0.0
        auc_z = pr_auc(y_test, paper_model.predict_proba(X_z)[:, 1])
        delta = auc_z - paper_auc
        print(f"  {g:<18} {auc_z:>13.5f} {delta:>+12.5f}")
        method_b.append({
            "group": g, "pr_auc_zeroed": round(auc_z, 5),
            "delta_pr_auc": round(delta, 5),
        })
    method_b.sort(key=lambda r: r["delta_pr_auc"])

    # ── 5. Method C: gain importance aggregated by group ─────────────────
    print("\n[5/5] Method C: gain importance by group (paper model) …")
    booster_names = paper_model.get_booster().feature_names or available
    imp = dict(zip(booster_names, paper_model.feature_importances_.tolist()))
    method_c = {}
    for g, cols in groups.items():
        method_c[g] = sum(imp.get(c, 0.0) for c in cols)
    tot = sum(method_c.values()) or 1.0
    method_c = {g: round(v / tot, 4) for g, v in
                sorted(method_c.items(), key=lambda kv: -kv[1])}
    for g, share in method_c.items():
        print(f"  {g:<18} {share:>7.1%}")

    elapsed = round(time.time() - t0, 1)
    result = {
        "experiment": "feature_group_ablation",
        "reviewer_item": "R2-#6",
        "cutoff_date": CUTOFF_DATE,
        "policy": POLICY,
        "ablation": ABLATION,
        "n_test": len(y_test),
        "n_positives_test": n_pos,
        "paper_anchor_pr_auc": round(paper_auc, 5),
        "retrain_baseline_pr_auc": round(retrain_baseline, 5),
        "groups": {g: cols for g, cols in sorted(groups.items())},
        "method_a_logo_retrain": method_a,
        "method_b_inference_zeroing": method_b,
        "method_c_gain_importance_share": method_c,
        "elapsed_seconds": elapsed,
    }
    (RESULTS_DIR / "feature_group_ablation.json").write_text(json.dumps(result, indent=2))
    print(f"\n  Saved -> results/feature_group_ablation.json  ({elapsed}s)")
    return result


if __name__ == "__main__":
    run()
