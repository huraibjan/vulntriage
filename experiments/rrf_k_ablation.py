#!/usr/bin/env python3
"""Experiment 1: RRF k ablation + SOTA fusion-method comparison.

IEEE Reviewer Revision — addresses Reviewer 2 comments #1 and #3.

  R2-#3  RRF k hyperparameter ablation:
         Sweep k in {5,10,20,30,40,60,80,100,150,200,300} and report PR-AUC,
         confirming the sensitivity of the fusion around the k=60 default.

  R2-#1  SOTA ensemble-fusion baseline comparison:
         Compare RRF against other multi-model fusion algorithms on the SAME
         three base rankers (fair comparison, identical inputs):
           - Equal-weight average (CombSUM, min-max normalised)
           - CombMNZ (CombSUM x #non-zero sources)
           - Borda count (rank aggregation)
           - Optimised weighted blend (weights learned on a val split, SLSQP)
           - Stacking ensemble (logistic-regression meta-learner on val)
           - Reciprocal Rank Fusion (ours, k=60)

CONSISTENCY GUARANTEE
---------------------
This script loads the *exact* saved v2 models
(xgb_tuned_tabular_v2, xgb_tuned_tabemb_v2, text_embedding_pipeline_v2) that
produced the paper's headline numbers, and reconstructs the identical
deterministic train/val/test split used by run_ensemble_v2.py.  It therefore
reproduces the published base metrics to 5 dp:

    tabular 0.25069 | tab+emb 0.30864 | epss 0.27105 | RRF@60 0.36714

The three RRF sources are {xgb_tabular, xgb_tabemb, epss} — identical to
run_ensemble_v2.py::main.

Usage (from project root):
    python experiments/rrf_k_ablation.py

Results are saved to results/rrf_k_ablation.json and
results/ensemble_fusion_baselines.json.
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
from scipy.optimize import minimize
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.models import FeatureSnapshot, Vulnerability
from app.db.session import get_session
from app.features.ablation import get_feature_columns
from app.features.builder import build_labels_df, time_aware_split
from app.ml.text.embeddings import TextEmbeddingPipeline

# ── Configuration (mirrors run_ensemble_v2.py exactly) ─────────────────────
ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY = "kev_strict"
ABLATION = "no_circular"
PCA_COMPONENTS = 64
SEED = 42
VAL_FRACTION = 0.15

MODELS_DIR = Path("models")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

K_VALUES = [5, 10, 20, 30, 40, 60, 80, 100, 150, 200, 300]

# Published anchors from results/ensemble_v2_comparison.csv (for a self-check)
PAPER_ANCHORS = {
    "tabular": 0.25069,
    "tabemb": 0.30864,
    "epss": 0.27105,
    "rrf_k60": 0.36714,
}


# ── Metrics ────────────────────────────────────────────────────────────────

def pr_auc(y, p) -> float:
    try:
        return float(average_precision_score(y, p))
    except ValueError:
        return 0.0


def roc(y, p) -> float:
    try:
        return float(roc_auc_score(y, p))
    except ValueError:
        return 0.0


def precision_at_k(y, p, k):
    order = np.argsort(-p)
    k = min(k, len(y))
    return float(y[order[:k]].sum()) / k if k else 0.0


def full_metrics(y, p) -> dict:
    return {
        "pr_auc": round(pr_auc(y, p), 5),
        "roc_auc": round(roc(y, p), 5),
        "precision@25": round(precision_at_k(y, p, 25), 4),
        "precision@50": round(precision_at_k(y, p, 50), 4),
        "precision@100": round(precision_at_k(y, p, 100), 4),
    }


# ── Fusion methods (all operate on the SAME source probability arrays) ─────

def _minmax(p: np.ndarray) -> np.ndarray:
    lo, hi = p.min(), p.max()
    return (p - lo) / (hi - lo) if hi > lo else np.zeros_like(p)


def rrf_fuse(sources: dict[str, np.ndarray], k: int = 60) -> np.ndarray:
    """Reciprocal Rank Fusion (identical formula to run_ensemble_v2.py)."""
    n = len(next(iter(sources.values())))
    scores = np.zeros(n)
    for p in sources.values():
        ranks = np.argsort(np.argsort(-p))  # rank 0 = highest prob
        scores += 1.0 / (k + ranks)
    return scores


def combsum(sources: dict[str, np.ndarray]) -> np.ndarray:
    """Equal-weight average of min-max-normalised scores (CombSUM)."""
    return np.mean([_minmax(p) for p in sources.values()], axis=0)


def combmnz(sources: dict[str, np.ndarray]) -> np.ndarray:
    """CombMNZ = CombSUM x number of sources with non-zero normalised score."""
    norm = [_minmax(p) for p in sources.values()]
    csum = np.sum(norm, axis=0)
    nonzero = np.sum([(p > 0).astype(float) for p in norm], axis=0)
    return csum * nonzero


def borda(sources: dict[str, np.ndarray]) -> np.ndarray:
    """Borda count rank aggregation (higher rank => more points)."""
    n = len(next(iter(sources.values())))
    scores = np.zeros(n)
    for p in sources.values():
        order = np.argsort(-p)
        pts = np.empty(n)
        pts[order] = np.arange(n, 0, -1)  # top item gets n points
        scores += pts
    return scores


def optimised_blend(sources_val, y_val, sources_test):
    """Weighted average with weights (simplex) learned on the val set."""
    names = list(sources_val.keys())
    V = np.column_stack([_minmax(sources_val[n]) for n in names])
    T = np.column_stack([_minmax(sources_test[n]) for n in names])

    def neg_pr(w):
        w = np.clip(w, 0, None)
        s = w.sum()
        if s == 0:
            return 0.0
        return -pr_auc(y_val, V @ (w / s))

    x0 = np.ones(len(names)) / len(names)
    cons = {"type": "eq", "fun": lambda w: w.sum() - 1}
    bounds = [(0, 1)] * len(names)
    res = minimize(neg_pr, x0, method="SLSQP", bounds=bounds, constraints=cons)
    w = np.clip(res.x, 0, None)
    w = w / w.sum() if w.sum() else x0
    return T @ w, dict(zip(names, [round(float(x), 4) for x in w]))


def stacking(sources_val, y_val, sources_test):
    """Logistic-regression meta-learner over the base rankers (Wolpert)."""
    names = list(sources_val.keys())
    V = np.column_stack([sources_val[n] for n in names])
    T = np.column_stack([sources_test[n] for n in names])
    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(V, y_val)
    return clf.predict_proba(T)[:, 1]


# ── Data / model reconstruction (deterministic, mirrors v2) ────────────────

def reconstruct_split_and_probs():
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
        train_df, val_df = train_test_split(
            train_full, test_size=VAL_FRACTION, stratify=y_full, random_state=SEED
        )
        val_df = val_df.reset_index(drop=True)
        test_df = test_df.reset_index(drop=True)

        # Descriptions for val + test
        need_ids = val_df["vuln_id"].tolist() + test_df["vuln_id"].tolist()
        desc_map = {}
        for i in range(0, len(need_ids), 10000):
            batch = need_ids[i:i + 10000]
            for vid, desc in session.query(
                Vulnerability.id, Vulnerability.description
            ).filter(Vulnerability.id.in_(batch)).all():
                desc_map[str(vid)] = desc or ""

    def texts_for(df):
        return [desc_map.get(v, "") if len(desc_map.get(v, "")) > 10
                else "No description available." for v in df["vuln_id"]]

    val_texts, test_texts = texts_for(val_df), texts_for(test_df)

    # Feature columns (no-circular ablation) and X matrices
    feat_cols = get_feature_columns(ABLATION, policy_name=POLICY)
    available = [c for c in feat_cols if c in test_df.columns]
    Xv = val_df[available].fillna(0).astype(float)
    Xte = test_df[available].fillna(0).astype(float)

    y_val = val_df["exploited"].astype(int).values
    y_test = test_df["exploited"].astype(int).values
    epss_val = val_df["epss_score"].fillna(0).values
    epss_test = test_df["epss_score"].fillna(0).values
    cvss_test = test_df["cvss_base_score"].fillna(0).values / 10.0

    # Load saved v2 models
    tab = joblib.load(MODELS_DIR / "xgb_tuned_tabular_v2.joblib")
    tabemb = joblib.load(MODELS_DIR / "xgb_tuned_tabemb_v2.joblib")
    pipe = TextEmbeddingPipeline(model_name="all-MiniLM-L6-v2", n_components=PCA_COMPONENTS)
    pipe.load(MODELS_DIR / "text_embedding_pipeline_v2.joblib")

    # Tabular probabilities
    p_tab_val = tab.predict_proba(Xv)[:, 1]
    p_tab_test = tab.predict_proba(Xte)[:, 1]

    # Tabular+embedding probabilities (cached raw embeddings: v2_val / v2_test)
    val_emb = pipe.transform_raw(pipe.encode_raw(val_texts, cache_key="v2_val"))
    test_emb = pipe.transform_raw(pipe.encode_raw(test_texts, cache_key="v2_test"))
    emb_cols = [f"emb_{i}" for i in range(test_emb.shape[1])]
    Xv_emb = pd.concat([Xv.reset_index(drop=True),
                        pd.DataFrame(val_emb, columns=emb_cols)], axis=1)
    Xte_emb = pd.concat([Xte.reset_index(drop=True),
                         pd.DataFrame(test_emb, columns=emb_cols)], axis=1)
    p_tabemb_val = tabemb.predict_proba(Xv_emb)[:, 1]
    p_tabemb_test = tabemb.predict_proba(Xte_emb)[:, 1]

    sources_val = {"xgb_tabular": p_tab_val, "xgb_tabemb": p_tabemb_val, "epss": epss_val}
    sources_test = {"xgb_tabular": p_tab_test, "xgb_tabemb": p_tabemb_test, "epss": epss_test}
    extra = {"cvss_test": cvss_test, "test_df": test_df}
    return sources_val, y_val, sources_test, y_test, extra


# ── Main ────────────────────────────────────────────────────────────────────

def run() -> dict:
    t0 = time.time()
    print("=" * 72)
    print("  Experiment 1: RRF k ablation + fusion-method comparison (R2 #1, #3)")
    print("=" * 72)

    print("\n[1/4] Reconstructing v2 split and base-model probabilities …")
    sources_val, y_val, sources_test, y_test, extra = reconstruct_split_and_probs()
    n_pos = int(y_test.sum())
    print(f"  Test: {len(y_test):,} rows, {n_pos} positives ({100*n_pos/len(y_test):.2f}%)")

    # ── Self-check against published anchors ─────────────────────────────
    print("\n[2/4] Consistency self-check vs paper anchors …")
    checks = {
        "tabular": pr_auc(y_test, sources_test["xgb_tabular"]),
        "tabemb": pr_auc(y_test, sources_test["xgb_tabemb"]),
        "epss": pr_auc(y_test, sources_test["epss"]),
        "rrf_k60": pr_auc(y_test, rrf_fuse(sources_test, k=60)),
    }
    all_ok = True
    for name, val in checks.items():
        anchor = PAPER_ANCHORS[name]
        ok = abs(val - anchor) < 1e-3
        all_ok &= ok
        print(f"    {name:<10} {val:.5f}  (paper {anchor:.5f})  {'OK' if ok else 'MISMATCH!'}")
    if not all_ok:
        print("  [WARN] Base metrics do not match the paper — investigate before use.")

    # ── R2-#1 : fusion-method comparison (fair, same 3 sources) ──────────
    print("\n[3/4] Fusion-method comparison on identical base rankers (R2 #1) …")
    fusion_preds = {
        "EPSS (single-model baseline)": sources_test["epss"],
        "CVSS (single-model baseline)": extra["cvss_test"],
        "Best single model (tab+emb)": sources_test["xgb_tabemb"],
        "CombSUM (equal-weight avg)": combsum(sources_test),
        "CombMNZ": combmnz(sources_test),
        "Borda count": borda(sources_test),
        "Stacking (LogReg meta-learner)": stacking(sources_val, y_val, sources_test),
        "RRF (ours, k=60)": rrf_fuse(sources_test, k=60),
    }
    blend_test, blend_w = optimised_blend(sources_val, y_val, sources_test)
    fusion_preds["Optimised weighted blend"] = blend_test

    fusion_results = {}
    for name, p in fusion_preds.items():
        fusion_results[name] = full_metrics(y_test, p)
    # Order table by PR-AUC
    ordered = sorted(fusion_results.items(), key=lambda kv: -kv[1]["pr_auc"])
    print(f"  {'Method':<34} {'PR-AUC':>8} {'ROC-AUC':>8} {'P@50':>7}")
    print("  " + "-" * 60)
    for name, m in ordered:
        star = "  *" if name.startswith("RRF") else ""
        print(f"  {name:<34} {m['pr_auc']:>8.5f} {m['roc_auc']:>8.5f} "
              f"{m['precision@50']:>7.3f}{star}")
    print(f"  (optimised blend weights: {blend_w})")

    # ── R2-#3 : RRF k sweep ──────────────────────────────────────────────
    print("\n[4/4] RRF k hyperparameter ablation (R2 #3) …")
    rrf_results = []
    for k in K_VALUES:
        auc = pr_auc(y_test, rrf_fuse(sources_test, k=k))
        rrf_results.append({"k": k, "pr_auc": round(auc, 5)})
        marker = "  <- default (paper)" if k == 60 else ""
        print(f"    k={k:>4}   PR-AUC={auc:.5f}{marker}")
    best = max(rrf_results, key=lambda r: r["pr_auc"])
    default = next(r for r in rrf_results if r["k"] == 60)
    spread = max(r["pr_auc"] for r in rrf_results) - min(r["pr_auc"] for r in rrf_results)
    print(f"\n  Best k={best['k']} (PR-AUC={best['pr_auc']:.5f}); "
          f"default k=60 PR-AUC={default['pr_auc']:.5f}; "
          f"spread across all k = {spread:.5f}")

    elapsed = round(time.time() - t0, 1)

    # ── Persist ──────────────────────────────────────────────────────────
    rrf_json = {
        "experiment": "rrf_k_ablation",
        "reviewer_item": "R2-#3",
        "cutoff_date": CUTOFF_DATE,
        "policy": POLICY,
        "ablation": ABLATION,
        "sources": list(sources_test.keys()),
        "n_test": len(y_test),
        "n_positives_test": n_pos,
        "paper_anchor_check": {k: round(v, 5) for k, v in checks.items()},
        "k_values_tested": K_VALUES,
        "rrf_results": rrf_results,
        "default_k": 60,
        "default_k_pr_auc": default["pr_auc"],
        "best_k": best["k"],
        "best_k_pr_auc": best["pr_auc"],
        "pr_auc_spread_across_k": round(spread, 5),
        "elapsed_seconds": elapsed,
    }
    (RESULTS_DIR / "rrf_k_ablation.json").write_text(json.dumps(rrf_json, indent=2))
    print(f"\n  Saved -> results/rrf_k_ablation.json")

    fusion_json = {
        "experiment": "ensemble_fusion_baselines",
        "reviewer_item": "R2-#1",
        "cutoff_date": CUTOFF_DATE,
        "policy": POLICY,
        "ablation": ABLATION,
        "note": "All multi-model methods fuse the same three base rankers: "
                "xgb_tabular, xgb_tabemb, epss.",
        "n_test": len(y_test),
        "n_positives_test": n_pos,
        "optimised_blend_weights": blend_w,
        "results": {name: m for name, m in ordered},
        "elapsed_seconds": elapsed,
    }
    (RESULTS_DIR / "ensemble_fusion_baselines.json").write_text(json.dumps(fusion_json, indent=2))
    print(f"  Saved -> results/ensemble_fusion_baselines.json")

    return {"rrf": rrf_json, "fusion": fusion_json}


if __name__ == "__main__":
    run()
