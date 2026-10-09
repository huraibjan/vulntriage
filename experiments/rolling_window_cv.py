#!/usr/bin/env python3
"""Experiment 2: Rolling-Window Cross-Validation.

IEEE Reviewer Revision — addresses Reviewer 2 comment #4 (and Reviewer 1's
robustness concern).

The paper reports a single fixed temporal split (train < 2024-06-01).  This
experiment tests temporal stability by sliding that boundary across four
successive years and always training-on-past / testing-on-the-next-year:

  W1:  train < 2021-06-01,  test [2021-06-01, 2022-06-01)
  W2:  train < 2022-06-01,  test [2022-06-01, 2023-06-01)
  W3:  train < 2023-06-01,  test [2023-06-01, 2024-06-01)
  W4:  train < 2024-06-01,  test [2024-06-01, 2025-06-01)   (= paper's split)

RETROACTIVE-ENRICHMENT CAVEAT
-----------------------------
Enrichment features in the snapshot store are frozen at the 2026-03 as-of
date: in particular every EPSS score is the *2026* value (the DB holds no
EPSS history), so older test windows receive scores that already encode
years of post-publication exploitation hindsight.  A single-config rolling
window would therefore *overstate* performance on early windows.  To both
demonstrate temporal stability honestly and quantify this leakage channel,
every window is evaluated under TWO feature configurations:

  A. frozen-enrichment  — the paper's no-circular set (46 features, incl.
     2026-frozen epss_score).  Inflation on early windows quantifies the
     "retroactive enrichment" leakage layer of the circularity audit.
  B. publication-time-safe — only features knowable when the CVE is
     published (CVSS base/vector, CWE one-hots, description stats).  This
     is the true leak-free temporal-stability measurement.

To isolate the effect of the temporal shift, every window re-trains the SAME
XGBoost configuration (the tuned v2 hyper-parameters), recomputing only
``scale_pos_weight`` for that window's class balance.  We report PR-AUC,
ROC-AUC, Brier, and Precision/Recall@{50,100} per window plus mean +/- std
across windows for both configurations.

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
import xgboost as xgb
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.models import FeatureSnapshot
from app.db.session import get_session
from app.features.ablation import get_feature_columns
from app.features.builder import build_labels_df

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

ASOF_DATE = date(2026, 3, 3)
POLICY = "kev_strict"
ABLATION = "no_circular"
SEED = 42

# Tuned v2 hyper-parameters (from models/xgb_tuned_tabular_v2.joblib), held
# fixed across all windows; scale_pos_weight is recomputed per window.
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

# (train_cutoff, test_start, test_end)
WINDOWS = [
    ("2021-06-01", "2021-06-01", "2022-06-01"),
    ("2022-06-01", "2022-06-01", "2023-06-01"),
    ("2023-06-01", "2023-06-01", "2024-06-01"),
    ("2024-06-01", "2024-06-01", "2025-06-01"),
]

# Features knowable at CVE publication time (no post-publication enrichment,
# no accumulating counters, no as-of-relative temporal features).
PUB_TIME_SAFE_PREFIXES = ("cvss_", "cwe_", "description_")


def pub_time_safe_columns(columns: list[str]) -> list[str]:
    return [c for c in columns if c.startswith(PUB_TIME_SAFE_PREFIXES)]


def compute_metrics(y_true: np.ndarray, y_score: np.ndarray) -> dict:
    metrics = {
        "pr_auc": round(float(average_precision_score(y_true, y_score)), 5),
        "roc_auc": round(float(roc_auc_score(y_true, y_score)), 5),
        "brier": round(float(brier_score_loss(y_true, y_score)), 5),
    }
    ranked = np.argsort(-y_score)
    total_pos = int(y_true.sum())
    for k in (50, 100):
        ka = min(k, len(y_true))
        hits = int(y_true[ranked[:ka]].sum())
        metrics[f"precision@{k}"] = round(hits / ka, 4) if ka else 0.0
        metrics[f"recall@{k}"] = round(hits / total_pos, 4) if total_pos else 0.0
    return metrics


def train_window_model(X_train, y_train):
    n_pos = int(y_train.sum())
    n_neg = len(y_train) - n_pos
    params = dict(XGB_PARAMS)
    params["scale_pos_weight"] = n_neg / max(n_pos, 1)
    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train)
    return model


def run() -> dict:
    t0 = time.time()
    print("=" * 72)
    print("  Experiment 2: Rolling-Window Cross-Validation (R2 #4)")
    print("=" * 72)

    # ── Load the full feature matrix + labels once ───────────────────────
    print(f"\n[1/2] Loading features (asof={ASOF_DATE}, policy={POLICY}) …")
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
    feat_cols = get_feature_columns(ABLATION, policy_name=POLICY)
    frozen_cols = [c for c in feat_cols if c in merged.columns]
    safe_cols = pub_time_safe_columns(frozen_cols)
    dates = pd.to_datetime(merged["published_at"], errors="coerce", format="ISO8601")
    print(f"  Records: {len(merged):,} | positives: {int(merged['exploited'].sum())}")
    print(f"  Config A (frozen-enrichment): {len(frozen_cols)} features")
    print(f"  Config B (pub-time-safe):     {len(safe_cols)} features")

    configs = {
        "frozen_enrichment": frozen_cols,
        "pub_time_safe": safe_cols,
    }

    # ── Rolling windows ──────────────────────────────────────────────────
    print("\n[2/2] Rolling windows (train-on-past / test-next-year) …")
    window_results = []
    for idx, (cut, ts, te) in enumerate(WINDOWS, 1):
        wt0 = time.time()
        train_mask = dates < pd.Timestamp(cut)
        test_mask = (dates >= pd.Timestamp(ts)) & (dates < pd.Timestamp(te))
        tr, teed = merged[train_mask], merged[test_mask]
        n_tr_pos = int(tr["exploited"].sum())
        n_te_pos = int(teed["exploited"].sum())

        print(f"\n  W{idx}: train < {cut}   test [{ts}, {te})")
        print(f"     train {len(tr):,} ({n_tr_pos} pos)  |  test {len(teed):,} ({n_te_pos} pos)")

        entry = {
            "window": idx, "train_cutoff": cut, "test_start": ts, "test_end": te,
            "n_train": len(tr), "n_test": len(teed),
            "n_train_pos": n_tr_pos, "n_test_pos": n_te_pos,
        }

        if n_tr_pos < 5 or n_te_pos < 5:
            print("     SKIP: too few positives")
            entry.update({"metrics": None, "skip_reason": "too few positives"})
            window_results.append(entry)
            continue

        y_tr = tr["exploited"].astype(int)
        y_te = teed["exploited"].astype(int).values

        for config_name, cols in configs.items():
            X_tr = tr[cols].fillna(0).astype(float)
            X_te = teed[cols].fillna(0).astype(float)
            model = train_window_model(X_tr, y_tr)
            y_prob = model.predict_proba(X_te)[:, 1]
            metrics = compute_metrics(y_te, y_prob)
            entry[config_name] = metrics
            print(f"     [{config_name:<18}] PR-AUC={metrics['pr_auc']:.5f}  "
                  f"ROC-AUC={metrics['roc_auc']:.5f}  P@50={metrics['precision@50']:.3f}")

        entry["training_seconds"] = round(time.time() - wt0, 1)
        window_results.append(entry)

    # ── Aggregate per config ─────────────────────────────────────────────
    aggregates = {}
    for config_name in configs:
        valid = [w[config_name] for w in window_results if w.get(config_name)]
        agg = {}
        for key in ["pr_auc", "roc_auc", "brier", "precision@50", "recall@50",
                    "precision@100", "recall@100"]:
            vals = [m[key] for m in valid]
            agg[key] = {"mean": round(float(np.mean(vals)), 5),
                        "std": round(float(np.std(vals)), 5),
                        "min": round(float(np.min(vals)), 5),
                        "max": round(float(np.max(vals)), 5)}
        aggregates[config_name] = agg

    print("\n" + "-" * 78)
    print(f"  {'Window':<8}{'Cutoff':<13}{'Test':>8} "
          f"{'PR-AUC (frozen)':>16} {'PR-AUC (pub-safe)':>18}")
    print("-" * 78)
    for w in window_results:
        fz, ps = w.get("frozen_enrichment"), w.get("pub_time_safe")
        if fz and ps:
            print(f"  W{w['window']:<7}{w['train_cutoff']:<13}{w['n_test']:>8,} "
                  f"{fz['pr_auc']:>16.5f} {ps['pr_auc']:>18.5f}")
    print("-" * 78)
    for config_name, agg in aggregates.items():
        print(f"  {config_name}: PR-AUC {agg['pr_auc']['mean']:.5f} +/- {agg['pr_auc']['std']:.5f} "
              f"(min {agg['pr_auc']['min']:.5f}, max {agg['pr_auc']['max']:.5f})")

    elapsed = round(time.time() - t0, 1)
    result = {
        "experiment": "rolling_window_cv",
        "reviewer_item": "R2-#4",
        "policy": POLICY,
        "ablation": ABLATION,
        "asof_date": str(ASOF_DATE),
        "configs": {
            "frozen_enrichment": {
                "n_features": len(frozen_cols),
                "note": "Paper's no-circular set; epss_score frozen at 2026-03 "
                        "values (no EPSS history in DB) — retroactive-enrichment "
                        "leakage inflates early windows.",
            },
            "pub_time_safe": {
                "n_features": len(safe_cols),
                "features": safe_cols,
                "note": "Only features knowable at CVE publication; leak-free "
                        "temporal-stability measurement.",
            },
        },
        "xgb_params": {k: v for k, v in XGB_PARAMS.items()
                       if k in ("n_estimators", "max_depth", "learning_rate")},
        "windows": window_results,
        "aggregates": aggregates,
        "elapsed_seconds": elapsed,
    }
    (RESULTS_DIR / "rolling_window_cv.json").write_text(json.dumps(result, indent=2))
    print(f"\n  Saved -> results/rolling_window_cv.json  ({elapsed}s)")
    return result


if __name__ == "__main__":
    run()
