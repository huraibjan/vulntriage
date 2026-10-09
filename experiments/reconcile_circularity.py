#!/usr/bin/env python3
"""Reconcile the circularity / clean-tabular / SHAP numbers to ONE pipeline.

The paper reported "clean tabular" PR-AUC as three different values because they
came from three different runs: Table III circularity (older run_experiments
pipeline, 0.2389), Table II main results (saved v2 model, 0.2507), and the
feature-group ablation (fresh tuned retrain, 0.2679). This script recomputes the
circularity audit AND the SHAP top-5 with the single tuned v2 configuration on
the exact v2 split, so Table III and the feature-ablation share one baseline and
the inflation factor is computed consistently.

Definitions match the code's ablation configs (`full` = circular, all available
features incl. exploit signals; `no_circular` = clean tabular). The saved model
that composes the RRF anchor (0.25069) is left untouched; the ablation baseline
is a fresh tuned retrain, and the paper notes this one-line distinction.

Usage:  python experiments/reconcile_circularity.py   (needs Postgres up)
Writes: results/circularity_reconciled.json, results/shap_v2.json
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
from app.ml.text.embeddings import TextEmbeddingPipeline

MODELS_DIR = Path("models")
RESULTS_DIR = Path("results")
ASOF = date(2026, 3, 3)
CUTOFF = "2024-06-01"
POLICY = "kev_strict"
SEED = 42
VAL_FRACTION = 0.15
PCA_COMPONENTS = 64
SAVED_TABULAR_ANCHOR = 0.25069

XGB_PARAMS = {
    "n_estimators": 414, "max_depth": 7, "learning_rate": 0.08742933234856033,
    "subsample": 0.987460777589654, "colsample_bytree": 0.6966521828215488,
    "min_child_weight": 3, "gamma": 0.2877938000832214,
    "reg_alpha": 1.6377473104949667, "reg_lambda": 2.617494451636084,
    "objective": "binary:logistic", "eval_metric": "aucpr", "tree_method": "hist",
    "random_state": SEED, "n_jobs": 4,
}


def pr_auc(y, p):
    try:
        return float(average_precision_score(y, p))
    except ValueError:
        return 0.0


def fit(X, y):
    n_pos = int(y.sum())
    p = dict(XGB_PARAMS)
    p["scale_pos_weight"] = (len(y) - n_pos) / max(n_pos, 1)
    m = xgb.XGBClassifier(**p)
    m.fit(X, y)
    return m


def run():
    t0 = time.time()
    print("=" * 72)
    print("  Reconcile circularity + SHAP to the tuned v2 pipeline")
    print("=" * 72)

    with get_session() as s:
        snaps = s.query(FeatureSnapshot).filter_by(asof=ASOF, feature_version="v1").all()
        rows = [dict(x.features_json, vuln_id=str(x.vulnerability_id)) for x in snaps]
        fdf = pd.DataFrame(rows)
        labels = build_labels_df(s, policy_name=POLICY)
        # descriptions for the E6 (text) config
        from app.db.models import Vulnerability
        import uuid as uuidmod
        need = fdf["vuln_id"].tolist()
        desc = {}
        for i in range(0, len(need), 10000):
            batch = [uuidmod.UUID(v) for v in need[i:i + 10000]]
            for vid, d in s.query(Vulnerability.id, Vulnerability.description).filter(
                    Vulnerability.id.in_(batch)).all():
                desc[str(vid)] = d or ""

    merged = fdf.merge(labels, on="vuln_id", how="inner")
    train_full, test_df = time_aware_split(merged, CUTOFF)
    y_full = train_full["exploited"].astype(int)
    train_df, _ = train_test_split(train_full, test_size=VAL_FRACTION,
                                   stratify=y_full, random_state=SEED)
    train_df = train_df.reset_index(drop=True)
    test_df = test_df.reset_index(drop=True)
    ytr = train_df["exploited"].astype(int)
    yte = test_df["exploited"].astype(int).values
    print(f"  Train {len(train_df):,} | Test {len(test_df):,} ({int(yte.sum())} pos)")

    full_cols = [c for c in get_feature_columns("full", policy_name=POLICY) if c in merged.columns]
    clean_cols = [c for c in get_feature_columns("no_circular", policy_name=POLICY) if c in merged.columns]
    leaky = [c for c in full_cols if c not in clean_cols]
    cvss_epss = [c for c in clean_cols if c.startswith("cvss") or c == "epss_score"]
    print(f"  full(circular)={len(full_cols)}  clean={len(clean_cols)}  "
          f"leaky={leaky}  cvss+epss={len(cvss_epss)}")

    def Xtr(cols): return train_df[cols].fillna(0).astype(float)
    def Xte(cols): return test_df[cols].fillna(0).astype(float)

    # ── Anchor check (saved model, unchanged) ───────────────────────────
    saved = joblib.load(MODELS_DIR / "xgb_tuned_tabular_v2.joblib")
    saved_auc = pr_auc(yte, saved.predict_proba(Xte(clean_cols))[:, 1])
    print(f"\n  Saved-model tabular PR-AUC = {saved_auc:.5f} "
          f"(anchor {SAVED_TABULAR_ANCHOR}; {'OK' if abs(saved_auc-SAVED_TABULAR_ANCHOR)<1e-3 else 'MISMATCH'})")

    # ── Circularity configs, all tuned retrain, same split ──────────────
    print("\n  Tuned retrain of each configuration:")
    configs = {}
    configs["circular_full"] = pr_auc(yte, fit(Xtr(full_cols), ytr).predict_proba(Xte(full_cols))[:, 1])
    configs["clean_tabular"] = pr_auc(yte, fit(Xtr(clean_cols), ytr).predict_proba(Xte(clean_cols))[:, 1])
    configs["cvss_epss_only"] = pr_auc(yte, fit(Xtr(cvss_epss), ytr).predict_proba(Xte(cvss_epss))[:, 1])
    configs["epss_only"] = pr_auc(yte, test_df["epss_score"].fillna(0).values)
    configs["cvss_only"] = pr_auc(yte, test_df.get("cvss_base_score", pd.Series(0, index=test_df.index)).fillna(0).values / 10.0)

    # E6 = clean + SBERT text embeddings
    pipe = TextEmbeddingPipeline(model_name="all-MiniLM-L6-v2", n_components=PCA_COMPONENTS)
    pipe.load(MODELS_DIR / "text_embedding_pipeline_v2.joblib")
    def texts(df): return [desc.get(v, "") if len(desc.get(v, "")) > 10 else "No description available." for v in df["vuln_id"]]
    tr_emb = pipe.transform_raw(pipe.encode_raw(texts(train_df), cache_key="v2_train"))
    te_emb = pipe.transform_raw(pipe.encode_raw(texts(test_df), cache_key="v2_test"))
    embcols = [f"emb_{i}" for i in range(te_emb.shape[1])]
    Xtr6 = pd.concat([Xtr(clean_cols).reset_index(drop=True), pd.DataFrame(tr_emb, columns=embcols)], axis=1)
    Xte6 = pd.concat([Xte(clean_cols).reset_index(drop=True), pd.DataFrame(te_emb, columns=embcols)], axis=1)
    configs["clean_plus_text"] = pr_auc(yte, fit(Xtr6, ytr).predict_proba(Xte6)[:, 1])

    inflation = configs["circular_full"] / configs["clean_tabular"]
    for k, v in configs.items():
        print(f"    {k:<18} {v:.5f}")
    print(f"    INFLATION (circular/clean) = {inflation:.3f}x")

    # ── SHAP top-5 on the saved tabular model (TreeSHAP via XGBoost) ─────
    print("\n  SHAP top-5 (TreeSHAP on saved xgb_tuned_tabular_v2):")
    booster = saved.get_booster()
    names = booster.feature_names or clean_cols
    dtest = xgb.DMatrix(Xte(clean_cols).values, feature_names=list(names))
    contribs = booster.predict(dtest, pred_contribs=True)  # (n, n_feat+1)
    mean_abs = np.abs(contribs[:, :-1]).mean(axis=0)
    order = np.argsort(-mean_abs)
    total = float(mean_abs.sum()) or 1.0
    shap_top = []
    for j in order[:8]:
        shap_top.append({"feature": str(names[j]),
                         "mean_abs_shap": round(float(mean_abs[j]), 4),
                         "share": round(float(mean_abs[j]) / total, 4)})
    for r in shap_top[:5]:
        print(f"    {r['feature']:<28} {r['mean_abs_shap']:.4f}  ({r['share']:.1%})")
    top5_share = sum(r["share"] for r in shap_top[:5])
    print(f"    top-5 cumulative share: {top5_share:.1%}")

    out = {
        "experiment": "reconcile_circularity",
        "n_test": len(yte), "n_positives_test": int(yte.sum()),
        "saved_tabular_anchor": round(saved_auc, 5),
        "configs_tuned_retrain": {k: round(v, 5) for k, v in configs.items()},
        "inflation_factor": round(inflation, 3),
        "note": "All circularity configs use the tuned v2 params on the v2 split "
                "(fresh retrain). clean_tabular is the single ablation baseline "
                "shared with the feature-group ablation; the saved model in "
                "Table II (0.25069) differs marginally due to retraining.",
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    (RESULTS_DIR / "circularity_reconciled.json").write_text(json.dumps(out, indent=2))
    (RESULTS_DIR / "shap_v2.json").write_text(json.dumps(
        {"model": "xgb_tuned_tabular_v2", "method": "TreeSHAP (pred_contribs)",
         "top_features": shap_top, "top5_share": round(top5_share, 4)}, indent=2))
    print(f"\n  Saved -> results/circularity_reconciled.json, results/shap_v2.json "
          f"({out['elapsed_seconds']}s)")


if __name__ == "__main__":
    run()
