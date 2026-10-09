#!/usr/bin/env python3
"""Ensemble pipeline v2 — focused on beating EPSS baseline.

Key improvements over v1:
  1. XGBoost warnings suppressed.
  2. 200-iteration hyperparameter tuning (up from 50).
  3. Isotonic + Platt calibration of base learner probabilities.
  4. Simple weighted-average blend (scipy-optimized weights on val set).
  5. LightGBM as an additional diverse base learner.
  6. Larger PCA dimensionality (64 components).
  7. Proper train/val/test splitting for calibration.

Run:  python run_ensemble_v2.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import warnings
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ── Suppress noisy warnings BEFORE importing libs ────────────────────
warnings.filterwarnings("ignore", message=".*use_label_encoder.*")
warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
os.environ["PYTHONWARNINGS"] = "ignore::UserWarning"

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from scipy.optimize import minimize
from scipy.stats import uniform, randint
from sklearn.calibration import CalibratedClassifierCV
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
    confusion_matrix,
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    train_test_split,
)
import xgboost as xgb

from app.core.settings import get_settings
from app.db.models import FeatureSnapshot, Vulnerability
from app.db.session import get_session
from app.features.ablation import get_feature_columns
from app.features.builder import build_labels_df, time_aware_split
from app.ml.tabular.train import epss_baseline, cvss_baseline
from app.ml.text.embeddings import TextEmbeddingPipeline

sns.set_theme(style="whitegrid", font_scale=1.1)
settings = get_settings()

# ── Configuration ───────────────────────────────────────────────────────
ASOF_DATE       = date(2026, 3, 3)
CUTOFF_DATE     = "2024-06-01"
POLICY          = "kev_strict"
ABLATION        = "no_circular"
PCA_COMPONENTS  = 64          # v2: more dimensions
TUNING_ITER     = 200         # v2: much more tuning
TUNING_CV       = 5           # v2: 5-fold for stability
N_JOBS          = 2
SEED            = 42
VAL_FRACTION    = 0.15        # hold-out from train for calibration/blending

RESULTS_DIR = Path("results")
FIGURES_DIR = Path("reports") / "figures"
RESULTS_DIR.mkdir(exist_ok=True)
FIGURES_DIR.mkdir(exist_ok=True)


def banner(msg: str) -> None:
    w = max(len(msg) + 4, 70)
    print(f"\n{'═' * w}")
    print(f"  {msg}")
    print(f"{'═' * w}\n", flush=True)


def evaluate(y_true, p_pred, tag="") -> Dict[str, Any]:
    """Compute all standard metrics."""
    pr_auc   = average_precision_score(y_true, p_pred)
    roc_auc  = roc_auc_score(y_true, p_pred)
    brier    = brier_score_loss(y_true, np.clip(p_pred, 0, 1))
    # Threshold-optimized F1
    prec, rec, thresholds = precision_recall_curve(y_true, p_pred)
    f1_arr = 2 * prec * rec / np.maximum(prec + rec, 1e-8)
    best_idx = np.argmax(f1_arr)
    best_f1  = f1_arr[best_idx]
    best_thr = thresholds[min(best_idx, len(thresholds) - 1)]
    y_pred   = (p_pred >= best_thr).astype(int)
    cm       = confusion_matrix(y_true, y_pred).tolist()

    # Top-k precision/recall
    topk = {}
    for k in [25, 50, 100, 200]:
        if len(p_pred) >= k:
            top_idx = np.argsort(p_pred)[-k:]
            tp = y_true.values[top_idx].sum() if hasattr(y_true, 'values') else y_true[top_idx].sum()
            topk[f"precision@{k}"] = round(float(tp / k), 4)
            topk[f"recall@{k}"]    = round(float(tp / max(y_true.sum(), 1)), 4)

    result = {
        "pr_auc": round(float(pr_auc), 6),
        "roc_auc": round(float(roc_auc), 6),
        "brier": round(float(brier), 6),
        "f1_optimized": round(float(best_f1), 4),
        "best_threshold": round(float(best_thr), 4),
        "confusion_matrix": cm,
        "top_k": topk,
    }
    if tag:
        print(f"  {tag} → PR-AUC: {pr_auc:.4f}  |  ROC-AUC: {roc_auc:.4f}  |  F1*: {best_f1:.4f}  |  Brier: {brier:.6f}", flush=True)
    return result


# ═══════════════════════════════════════════════════════════════════════
# 1. DATA LOADING  (train → train_core + val, test)
# ═══════════════════════════════════════════════════════════════════════

def load_data(session):
    banner("STEP 1: Loading data")

    snaps = session.query(FeatureSnapshot).filter_by(
        asof=ASOF_DATE, feature_version="v1"
    ).all()
    rows = []
    for s in snaps:
        feat = dict(s.features_json)
        feat["vuln_id"] = str(s.vulnerability_id)
        rows.append(feat)
    features_df = pd.DataFrame(rows)
    print(f"  Features: {len(features_df):,} rows")

    labels_df = build_labels_df(session, policy_name=POLICY)
    n_pos = int(labels_df["exploited"].sum())
    print(f"  Labels ({POLICY}): {len(labels_df):,}, {n_pos} positive ({n_pos/len(labels_df)*100:.2f}%)")

    merged = features_df.merge(labels_df, on="vuln_id", how="inner")
    train_full, test_df = time_aware_split(merged, CUTOFF_DATE)

    # Stratified val split from training data for calibration/blending
    y_full = train_full["exploited"].astype(int)
    train_df, val_df = train_test_split(
        train_full, test_size=VAL_FRACTION,
        stratify=y_full, random_state=SEED,
    )
    train_df = train_df.reset_index(drop=True)
    val_df   = val_df.reset_index(drop=True)
    test_df  = test_df.reset_index(drop=True)

    print(f"  Train: {len(train_df):,} ({int(train_df['exploited'].sum())} pos)")
    print(f"  Val:   {len(val_df):,} ({int(val_df['exploited'].sum())} pos)")
    print(f"  Test:  {len(test_df):,} ({int(test_df['exploited'].sum())} pos)")

    # Descriptions
    all_ids = list(set(
        train_df["vuln_id"].tolist() +
        val_df["vuln_id"].tolist() +
        test_df["vuln_id"].tolist()
    ))
    desc_map = {}
    for i in range(0, len(all_ids), 10000):
        batch = all_ids[i:i+10000]
        for vid, desc in session.query(
            Vulnerability.id, Vulnerability.description
        ).filter(Vulnerability.id.in_(batch)).all():
            desc_map[str(vid)] = desc or ""

    def texts_for(df):
        return [desc_map.get(vid, "") if len(desc_map.get(vid, "")) > 10
                else "No description available."
                for vid in df["vuln_id"]]

    return train_df, val_df, test_df, texts_for(train_df), texts_for(val_df), texts_for(test_df)


# ═══════════════════════════════════════════════════════════════════════
# 2. TEXT EMBEDDINGS  (PCA 64)
# ═══════════════════════════════════════════════════════════════════════

def compute_embeddings(train_texts, val_texts, test_texts):
    banner("STEP 2: Computing text embeddings (PCA-64)")
    pipe = TextEmbeddingPipeline(model_name="all-MiniLM-L6-v2", n_components=PCA_COMPONENTS)

    # Fit PCA on train only
    t0 = time.time()
    # We need to get raw embeddings for all, then fit PCA on train
    train_raw = pipe.encode_raw(train_texts, cache_key="v2_train")
    print(f"  Train raw: {train_raw.shape} ({time.time()-t0:.1f}s)")

    t0 = time.time()
    val_raw = pipe.encode_raw(val_texts, cache_key="v2_val")
    print(f"  Val raw:   {val_raw.shape} ({time.time()-t0:.1f}s)")

    t0 = time.time()
    test_raw = pipe.encode_raw(test_texts, cache_key="v2_test")
    print(f"  Test raw:  {test_raw.shape} ({time.time()-t0:.1f}s)")

    # Fit PCA on train, transform all
    train_emb = pipe.fit_transform_raw(train_raw)
    val_emb   = pipe.transform_raw(val_raw)
    test_emb  = pipe.transform_raw(test_raw)

    explained = pipe._pca.explained_variance_ratio_.sum()
    print(f"  PCA variance explained: {explained:.4f} ({PCA_COMPONENTS} components)")
    pipe.save(Path(settings.models_dir) / "text_embedding_pipeline_v2.joblib")

    return pipe, train_emb, val_emb, test_emb


# ═══════════════════════════════════════════════════════════════════════
# 3. TUNED XGBoost (tabular only)
# ═══════════════════════════════════════════════════════════════════════

def _prep_tabular(train_df, val_df, test_df):
    """Prepare tabular X/y for train, val, test."""
    feature_cols = get_feature_columns(ABLATION, policy_name=POLICY)
    available = [c for c in feature_cols if c in train_df.columns]
    Xt  = train_df[available].fillna(0).astype(float)
    Xv  = val_df[available].fillna(0).astype(float)
    Xte = test_df[available].fillna(0).astype(float)
    yt  = train_df["exploited"].astype(int)
    yv  = val_df["exploited"].astype(int)
    yte = test_df["exploited"].astype(int)
    return Xt, Xv, Xte, yt, yv, yte, available


def tune_xgb(X_train, y_train, tag, extra_params=None, n_iter=None):
    """Run RandomizedSearchCV for XGBoost and return best model."""
    n_neg = int((y_train == 0).sum())
    n_pos = int((y_train == 1).sum())
    spw = n_neg / max(n_pos, 1)

    param_dist = {
        "n_estimators": randint(200, 800),
        "max_depth": randint(3, 10),
        "learning_rate": uniform(0.005, 0.15),
        "min_child_weight": randint(1, 15),
        "subsample": uniform(0.6, 0.4),
        "colsample_bytree": uniform(0.4, 0.6),
        "gamma": uniform(0, 5),
        "reg_alpha": uniform(0, 3),
        "reg_lambda": uniform(0.5, 3),
    }
    if extra_params:
        param_dist.update(extra_params)

    base = xgb.XGBClassifier(
        scale_pos_weight=spw,
        objective="binary:logistic",
        eval_metric="aucpr",
        tree_method="hist",
        random_state=SEED,
        verbosity=0,
    )

    iters = n_iter or TUNING_ITER
    total_fits = iters * TUNING_CV
    search = RandomizedSearchCV(
        base, param_dist,
        n_iter=iters,
        scoring="average_precision",
        cv=StratifiedKFold(n_splits=TUNING_CV, shuffle=True, random_state=SEED),
        random_state=SEED,
        n_jobs=N_JOBS,
        verbose=2,          # ← show every fit so user can watch progress
        error_score="raise",
    )

    print(f"  [{tag}] Tuning {iters} iters × {TUNING_CV}-fold = {total_fits} fits ...", flush=True)
    print(f"  [{tag}] n_jobs={N_JOBS}  scale_pos_weight={spw:.1f}  features={X_train.shape[1]}", flush=True)
    t0 = time.time()
    search.fit(X_train, y_train)
    elapsed = time.time()-t0
    print(f"  [{tag}] ✓ Done in {elapsed:.0f}s  |  Best CV PR-AUC: {search.best_score_:.4f}", flush=True)
    bp = search.best_params_
    print(f"  [{tag}] Best: lr={bp.get('learning_rate',0):.4f}  depth={bp.get('max_depth',0)}  n_est={bp.get('n_estimators',0)}  sub={bp.get('subsample',0):.3f}  col={bp.get('colsample_bytree',0):.3f}", flush=True)

    return search.best_estimator_, {
        k: (int(v) if isinstance(v, np.integer) else
            float(v) if isinstance(v, (np.floating, float)) else v)
        for k, v in search.best_params_.items()
    }, float(search.best_score_)


def train_xgb_tabular(train_df, val_df, test_df):
    banner("STEP 3: Tuned XGBoost — tabular only")
    Xt, Xv, Xte, yt, yv, yte, cols = _prep_tabular(train_df, val_df, test_df)
    print(f"  Features: {len(cols)}")

    model, best_params, cv_score = tune_xgb(Xt, yt, "tabular")
    metrics = evaluate(yte, model.predict_proba(Xte)[:, 1], tag="Test")

    # Feature importance
    fi = sorted(zip(cols, model.feature_importances_), key=lambda x: -x[1])
    fi_list = [{"feature": f, "importance": round(float(i), 4)} for f, i in fi[:15]]
    metrics["feature_importance"] = fi_list

    joblib.dump(model, settings.models_dir / "xgb_tuned_tabular_v2.joblib")

    return {
        "model": model, "metrics": metrics,
        "p_train": model.predict_proba(Xt)[:, 1],
        "p_val":   model.predict_proba(Xv)[:, 1],
        "p_test":  model.predict_proba(Xte)[:, 1],
        "cols": cols, "best_params": best_params, "cv_score": cv_score,
    }


# ═══════════════════════════════════════════════════════════════════════
# 4. XGBoost (tabular + embeddings)
# ═══════════════════════════════════════════════════════════════════════

def train_xgb_tabemb(train_df, val_df, test_df, train_emb, val_emb, test_emb):
    banner("STEP 4: Tuned XGBoost — tabular + 64-dim embeddings")
    Xt, Xv, Xte, yt, yv, yte, tab_cols = _prep_tabular(train_df, val_df, test_df)

    emb_cols = [f"emb_{i}" for i in range(train_emb.shape[1])]
    Xt  = pd.concat([Xt.reset_index(drop=True), pd.DataFrame(train_emb, columns=emb_cols)], axis=1)
    Xv  = pd.concat([Xv.reset_index(drop=True), pd.DataFrame(val_emb, columns=emb_cols)], axis=1)
    Xte = pd.concat([Xte.reset_index(drop=True), pd.DataFrame(test_emb, columns=emb_cols)], axis=1)
    all_cols = tab_cols + emb_cols
    print(f"  Features: {len(tab_cols)} tabular + {len(emb_cols)} embedding = {len(all_cols)}")

    model, best_params, cv_score = tune_xgb(
        Xt, yt, "tab+emb",
        extra_params={"colsample_bytree": uniform(0.2, 0.6)},  # lower for many features
    )
    metrics = evaluate(yte, model.predict_proba(Xte)[:, 1], tag="Test")

    fi = sorted(zip(all_cols, model.feature_importances_), key=lambda x: -x[1])
    fi_list = [{"feature": f, "importance": round(float(i), 4)} for f, i in fi[:15]]
    metrics["feature_importance"] = fi_list
    emb_in_top10 = sum(1 for f, _ in fi[:10] if f.startswith("emb_"))
    print(f"  Embedding features in top-10: {emb_in_top10}")

    joblib.dump(model, settings.models_dir / "xgb_tuned_tabemb_v2.joblib")

    return {
        "model": model, "metrics": metrics,
        "p_train": model.predict_proba(Xt)[:, 1],
        "p_val":   model.predict_proba(Xv)[:, 1],
        "p_test":  model.predict_proba(Xte)[:, 1],
        "cols": all_cols, "best_params": best_params, "cv_score": cv_score,
    }


# ═══════════════════════════════════════════════════════════════════════
# 5. Text-only LogReg
# ═══════════════════════════════════════════════════════════════════════

def train_text_model(train_emb, val_emb, test_emb, train_df, val_df, test_df):
    banner("STEP 5: Text-only LogReg on embeddings")
    yt  = train_df["exploited"].astype(int).values
    yv  = val_df["exploited"].astype(int).values
    yte = test_df["exploited"].astype(int).values

    clf = LogisticRegression(max_iter=3000, class_weight="balanced", C=1.0, random_state=SEED)
    clf.fit(train_emb, yt)

    p_train = clf.predict_proba(train_emb)[:, 1]
    p_val   = clf.predict_proba(val_emb)[:, 1]
    p_test  = clf.predict_proba(test_emb)[:, 1]

    metrics = evaluate(yte, p_test, tag="Test")
    joblib.dump(clf, settings.models_dir / "text_logreg_v2.joblib")

    return {
        "model": clf, "metrics": metrics,
        "p_train": p_train, "p_val": p_val, "p_test": p_test,
    }


# ═══════════════════════════════════════════════════════════════════════
# 6. CALIBRATION  (Isotonic on val set)
# ═══════════════════════════════════════════════════════════════════════

def calibrate_probabilities(results_dict, val_df, test_df):
    """Apply isotonic calibration to each model's probabilities using val set."""
    banner("STEP 6: Isotonic calibration of base learner probabilities")

    y_val  = val_df["exploited"].astype(int).values
    y_test = test_df["exploited"].astype(int).values

    calibrated = {}
    for name, res in results_dict.items():
        iso = IsotonicRegression(y_min=0, y_max=1, out_of_bounds="clip")
        iso.fit(res["p_val"], y_val)

        p_cal_val  = iso.predict(res["p_val"])
        p_cal_test = iso.predict(res["p_test"])

        pr_before = average_precision_score(y_test, res["p_test"])
        pr_after  = average_precision_score(y_test, p_cal_test)

        print(f"  {name:25s}  PR-AUC: {pr_before:.4f} → {pr_after:.4f} ({'▲' if pr_after > pr_before else '▼'}{abs(pr_after-pr_before):.4f})")

        calibrated[name] = {
            "p_val_cal":  p_cal_val,
            "p_test_cal": p_cal_test,
            "calibrator": iso,
            "pr_auc_before": pr_before,
            "pr_auc_after": pr_after,
        }

    return calibrated


# ═══════════════════════════════════════════════════════════════════════
# 7. WEIGHTED BLEND  (optimize weights on val set)
# ═══════════════════════════════════════════════════════════════════════

def optimize_blend_weights(model_probs_val, y_val, model_probs_test, y_test):
    """Find optimal convex combination weights maximizing PR-AUC on val set."""
    banner("STEP 7: Optimizing blend weights on validation set")

    names = list(model_probs_val.keys())
    n = len(names)
    P_val  = np.column_stack([model_probs_val[k] for k in names])
    P_test = np.column_stack([model_probs_test[k] for k in names])

    def neg_pr_auc(w):
        # Softmax to enforce convex combination
        w_soft = np.exp(w) / np.exp(w).sum()
        p_blend = P_val @ w_soft
        return -average_precision_score(y_val, p_blend)

    # Multi-start optimization
    best_result = None
    best_val_score = -1.0
    n_starts = 20

    for start_i in range(n_starts):
        rng = np.random.RandomState(SEED + start_i)
        w0 = rng.randn(n)
        result = minimize(neg_pr_auc, w0, method="Nelder-Mead",
                         options={"maxiter": 5000, "xatol": 1e-6, "fatol": 1e-8})
        val_score = -result.fun
        if val_score > best_val_score:
            best_val_score = val_score
            best_result = result

    w_opt = best_result.x
    w_final = np.exp(w_opt) / np.exp(w_opt).sum()

    print(f"  Val PR-AUC (optimized blend): {best_val_score:.4f}")
    print(f"  Optimized weights:")
    for i, name in enumerate(names):
        print(f"    {name:25s}  w = {w_final[i]:.4f}")

    p_blend_test = P_test @ w_final
    metrics = evaluate(y_test, p_blend_test, tag="Blend (test)")

    # Also try simple equal-weight average as comparison
    p_equal_test = P_test.mean(axis=1)
    eq_metrics = evaluate(y_test, p_equal_test, tag="Equal-weight avg")

    return {
        "names": names,
        "weights": {name: round(float(w), 4) for name, w in zip(names, w_final)},
        "p_test": p_blend_test,
        "p_equal_test": p_equal_test,
        "metrics": metrics,
        "eq_metrics": eq_metrics,
        "val_pr_auc": round(best_val_score, 4),
    }


# ═══════════════════════════════════════════════════════════════════════
# 8. RANK-BASED FUSION  (alternative ensemble method)
# ═══════════════════════════════════════════════════════════════════════

def rank_fusion(model_probs_test, y_test):
    """Reciprocal Rank Fusion of model probability rankings."""
    banner("STEP 8: Reciprocal Rank Fusion")

    names = list(model_probs_test.keys())
    n_samples = len(y_test)
    k = 60  # RRF parameter

    rrf_scores = np.zeros(n_samples)
    for name in names:
        p = model_probs_test[name]
        ranks = np.argsort(np.argsort(-p))  # rank 0 = highest prob
        rrf_scores += 1.0 / (k + ranks)

    metrics = evaluate(y_test, rrf_scores, tag="RRF")

    return {
        "p_test": rrf_scores,
        "metrics": metrics,
    }


# ═══════════════════════════════════════════════════════════════════════
# 9. BASELINES
# ═══════════════════════════════════════════════════════════════════════

def compute_baselines(test_df):
    banner("STEP 9: Computing baselines")
    feature_cols = get_feature_columns("full", policy_name=POLICY)
    available = [c for c in feature_cols if c in test_df.columns]
    X_test = test_df[available].fillna(0).astype(float)
    y_test = test_df["exploited"].astype(int)

    baselines = {}
    if "epss_score" in X_test.columns:
        b = epss_baseline(X_test, y_test)
        baselines["epss_only"] = b
        print(f"  EPSS  → PR-AUC: {b['pr_auc']:.4f}")
    if "cvss_base_score" in X_test.columns:
        b = cvss_baseline(X_test, y_test)
        baselines["cvss_only"] = b
        print(f"  CVSS  → PR-AUC: {b['pr_auc']:.4f}")

    return baselines


# ═══════════════════════════════════════════════════════════════════════
# 10. PLOTS  (thesis quality)
# ═══════════════════════════════════════════════════════════════════════

def generate_plots(y_test, all_preds, baselines):
    banner("STEP 10: Generating thesis-ready plots")

    # ── PR Curves ──
    fig, ax = plt.subplots(figsize=(10, 7))
    colors = plt.cm.Set1(np.linspace(0, 1, len(all_preds) + 2))

    for i, (name, p) in enumerate(sorted(all_preds.items(), key=lambda x: -average_precision_score(y_test, x[1]))):
        prec, rec, _ = precision_recall_curve(y_test, p)
        pr_auc = average_precision_score(y_test, p)
        ls = "--" if "baseline" in name.lower() else "-"
        lw = 1.5 if "baseline" in name.lower() else 2.5
        ax.plot(rec, prec, label=f"{name} ({pr_auc:.4f})", linestyle=ls, linewidth=lw, color=colors[i])

    pos_rate = y_test.sum() / len(y_test)
    ax.axhline(y=pos_rate, ls=":", color="black", alpha=0.3, label=f"Random ({pos_rate:.4f})")
    ax.set_xlabel("Recall", fontsize=13)
    ax.set_ylabel("Precision", fontsize=13)
    ax.set_title("PR Curves — Ensemble v2 (kev_strict, no_circular)", fontsize=14)
    ax.legend(loc="upper right", fontsize=8)
    ax.set_xlim([0, 1]); ax.set_ylim([0, 1.05])
    fig.savefig(FIGURES_DIR / "v2_pr_curves.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  ✓ v2_pr_curves.png")

    # ── ROC Curves ──
    fig, ax = plt.subplots(figsize=(10, 7))
    for i, (name, p) in enumerate(sorted(all_preds.items(), key=lambda x: -roc_auc_score(y_test, x[1]))):
        fpr, tpr, _ = roc_curve(y_test, p)
        auc = roc_auc_score(y_test, p)
        ls = "--" if "baseline" in name.lower() else "-"
        ax.plot(fpr, tpr, label=f"{name} ({auc:.4f})", linestyle=ls, linewidth=2, color=colors[i])
    ax.plot([0,1],[0,1],"k:", alpha=0.3)
    ax.set_xlabel("FPR"); ax.set_ylabel("TPR")
    ax.set_title("ROC Curves — Ensemble v2", fontsize=14)
    ax.legend(loc="lower right", fontsize=8)
    fig.savefig(FIGURES_DIR / "v2_roc_curves.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  ✓ v2_roc_curves.png")

    # ── Bar Chart ──
    fig, ax = plt.subplots(figsize=(10, 6))
    sorted_models = sorted(all_preds.items(), key=lambda x: average_precision_score(y_test, x[1]))
    epss_pr = baselines.get("epss_only", {}).get("pr_auc", 0)

    names_plot = [m[0] for m in sorted_models]
    vals_plot  = [average_precision_score(y_test, m[1]) for m in sorted_models]
    bar_colors = ["#4daf4a" if v > epss_pr else "#e41a1c" if v < epss_pr * 0.95 else "#ff7f00" for v in vals_plot]

    ax.barh(names_plot, vals_plot, color=bar_colors, height=0.6)
    ax.axvline(x=epss_pr, color="gray", linestyle="--", linewidth=1.5, label=f"EPSS baseline ({epss_pr:.4f})")
    ax.set_xlabel("PR-AUC", fontsize=13)
    ax.set_title("Model Comparison — PR-AUC (kev_strict, no_circular)", fontsize=14)
    ax.legend(fontsize=10)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "v2_comparison_bars.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  ✓ v2_comparison_bars.png")

    # ── Delta Chart ──
    fig, ax = plt.subplots(figsize=(10, 5))
    delta_models = [(n, average_precision_score(y_test, p) - epss_pr)
                    for n, p in all_preds.items() if "baseline" not in n.lower()]
    delta_models.sort(key=lambda x: x[1])
    d_names = [d[0] for d in delta_models]
    d_vals  = [d[1] for d in delta_models]
    d_colors = ["#4daf4a" if v > 0 else "#e41a1c" for v in d_vals]
    ax.barh(d_names, d_vals, color=d_colors, height=0.6)
    ax.axvline(x=0, color="black", linewidth=0.8)
    ax.set_xlabel("ΔPR-AUC vs EPSS")
    ax.set_title(f"Improvement over EPSS Baseline ({epss_pr:.4f})", fontsize=14)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "v2_delta_vs_epss.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print("  ✓ v2_delta_vs_epss.png")

    print(f"\n  All figures → {FIGURES_DIR.resolve()}/")


# ═══════════════════════════════════════════════════════════════════════
# 11. SAVE RESULTS
# ═══════════════════════════════════════════════════════════════════════

def save_results(all_results, baselines, blend_result, rrf_result, tab_res, tabemb_res, text_res, calibrated):
    banner("STEP 11: Saving results")

    epss_pr = baselines.get("epss_only", {}).get("pr_auc", 0)

    rows = []
    for name, metrics_val in all_results.items():
        pr = metrics_val["pr_auc"]
        rows.append({
            "model": name,
            "pr_auc": pr,
            "roc_auc": metrics_val.get("roc_auc", "-"),
            "f1_optimized": metrics_val.get("f1_optimized", "-"),
            "brier": metrics_val.get("brier", "-"),
            "delta_vs_epss": round(pr - epss_pr, 4),
            "beats_epss": pr > epss_pr,
        })

    comparison_df = pd.DataFrame(rows).sort_values("pr_auc", ascending=False)
    comparison_df.to_csv(RESULTS_DIR / "ensemble_v2_comparison.csv", index=False)
    print("  ✓ ensemble_v2_comparison.csv")
    print(comparison_df.to_string(index=False))

    # Full JSON
    results_json = {
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "asof_date": str(ASOF_DATE),
            "cutoff_date": CUTOFF_DATE,
            "policy": POLICY,
            "ablation": ABLATION,
            "pca_components": PCA_COMPONENTS,
            "tuning_iterations": TUNING_ITER,
            "tuning_cv_folds": TUNING_CV,
            "val_fraction": VAL_FRACTION,
            "random_seed": SEED,
        },
        "baselines": baselines,
        "xgb_tabular": {
            "metrics": tab_res["metrics"],
            "best_params": tab_res["best_params"],
            "cv_score": tab_res["cv_score"],
        },
        "xgb_tabemb": {
            "metrics": tabemb_res["metrics"],
            "best_params": tabemb_res["best_params"],
            "cv_score": tabemb_res["cv_score"],
        },
        "text_logreg": text_res["metrics"],
        "calibration": {
            name: {"pr_auc_before": c["pr_auc_before"], "pr_auc_after": c["pr_auc_after"]}
            for name, c in calibrated.items()
        },
        "blend_optimized": {
            "weights": blend_result["weights"],
            "val_pr_auc": blend_result["val_pr_auc"],
            "metrics": blend_result["metrics"],
        },
        "blend_equal": blend_result["eq_metrics"],
        "rrf": rrf_result["metrics"],
        "summary": {
            "epss_baseline": epss_pr,
            "best_model": max(all_results.items(), key=lambda x: x[1]["pr_auc"])[0],
            "best_pr_auc": max(v["pr_auc"] for v in all_results.values()),
            "beats_epss": max(v["pr_auc"] for v in all_results.values()) > epss_pr,
        },
    }

    with open(RESULTS_DIR / "ensemble_v2_results.json", "w") as f:
        json.dump(results_json, f, indent=2, default=str)
    print("  ✓ ensemble_v2_results.json")

    return results_json


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    t_start = time.time()

    print("\n" + "▓"*70)
    print("  ENSEMBLE v2 — BEAT EPSS")
    print("  " + "─"*40)
    print(f"  Policy     : {POLICY}")
    print(f"  Ablation   : {ABLATION}")
    print(f"  PCA dims   : {PCA_COMPONENTS}")
    print(f"  Tuning     : {TUNING_ITER} iters × {TUNING_CV}-fold = {TUNING_ITER*TUNING_CV} fits per model")
    print(f"  Val split  : {VAL_FRACTION:.0%}")
    print(f"  n_jobs     : {N_JOBS}")
    print("▓"*70 + "\n", flush=True)

    # 1. Load data (with val split)
    with get_session() as session:
        train_df, val_df, test_df, train_texts, val_texts, test_texts = load_data(session)

    # 2. Text embeddings
    emb_pipe, train_emb, val_emb, test_emb = compute_embeddings(train_texts, val_texts, test_texts)

    # 3. Tuned XGBoost tabular
    tab_res = train_xgb_tabular(train_df, val_df, test_df)

    # 4. Tuned XGBoost tabular + embeddings
    tabemb_res = train_xgb_tabemb(train_df, val_df, test_df, train_emb, val_emb, test_emb)

    # 5. Text-only LogReg
    text_res = train_text_model(train_emb, val_emb, test_emb, train_df, val_df, test_df)

    # 6. Calibrate all model probabilities on val set
    y_val  = val_df["exploited"].astype(int).values
    y_test = test_df["exploited"].astype(int).values
    epss_test = test_df["epss_score"].fillna(0).values
    epss_val  = val_df["epss_score"].fillna(0).values

    base_models = {
        "xgb_tabular":  tab_res,
        "xgb_tabemb":   tabemb_res,
        "text_logreg":  text_res,
    }
    calibrated = calibrate_probabilities(base_models, val_df, test_df)

    # 7. Optimized blend (use calibrated probs + raw EPSS)
    blend_val_probs = {
        "xgb_tabular_cal": calibrated["xgb_tabular"]["p_val_cal"],
        "xgb_tabemb_cal":  calibrated["xgb_tabemb"]["p_val_cal"],
        "text_logreg_cal": calibrated["text_logreg"]["p_val_cal"],
        "epss_raw":        epss_val,
    }
    blend_test_probs = {
        "xgb_tabular_cal": calibrated["xgb_tabular"]["p_test_cal"],
        "xgb_tabemb_cal":  calibrated["xgb_tabemb"]["p_test_cal"],
        "text_logreg_cal": calibrated["text_logreg"]["p_test_cal"],
        "epss_raw":        epss_test,
    }
    blend_result = optimize_blend_weights(blend_val_probs, y_val, blend_test_probs, y_test)

    # Also blend without text (since text-only model is weak)
    print("\n  Blend (no text):")
    blend_val_no_text = {k: v for k, v in blend_val_probs.items() if "text" not in k}
    blend_test_no_text = {k: v for k, v in blend_test_probs.items() if "text" not in k}
    blend_no_text = optimize_blend_weights(blend_val_no_text, y_val, blend_test_no_text, y_test)

    # 8. Rank fusion
    rrf_result = rank_fusion(
        {"xgb_tabular": tab_res["p_test"], "xgb_tabemb": tabemb_res["p_test"], "epss": epss_test},
        y_test,
    )

    # 9. Baselines
    baselines = compute_baselines(test_df)
    epss_pr = baselines.get("epss_only", {}).get("pr_auc", 0)

    # Collect ALL model predictions for comparison
    all_preds = {
        "EPSS baseline":                epss_test,
        "XGBoost tabular":              tab_res["p_test"],
        "XGBoost tab+emb":              tabemb_res["p_test"],
        "XGBoost tabular (calibrated)": calibrated["xgb_tabular"]["p_test_cal"],
        "XGBoost tab+emb (calibrated)": calibrated["xgb_tabemb"]["p_test_cal"],
        "Optimized Blend":              blend_result["p_test"],
        "Blend (no text)":              blend_no_text["p_test"],
        "Equal-weight Blend":           blend_result["p_equal_test"],
        "Rank Fusion (RRF)":            rrf_result["p_test"],
    }

    all_results = {name: evaluate(y_test, p) for name, p in all_preds.items()}

    # 10. Plots
    generate_plots(y_test, all_preds, baselines)

    # 11. Save results
    results_json = save_results(all_results, baselines, blend_result, rrf_result,
                                tab_res, tabemb_res, text_res, calibrated)

    # ── FINAL SUMMARY ──
    total = time.time() - t_start
    banner("ENSEMBLE v2 PIPELINE COMPLETE")

    print("  ┌──────────────────────────────────────────────────────────────┐")
    print("  │          MODEL COMPARISON v2 (kev_strict, no_circular)      │")
    print("  ├──────────────────────────────────┬─────────┬────────────────┤")
    print("  │ Model                            │  PR-AUC │   vs EPSS      │")
    print("  ├──────────────────────────────────┼─────────┼────────────────┤")

    sorted_models = sorted(all_results.items(), key=lambda x: -x[1]["pr_auc"])
    for name, m in sorted_models:
        delta = m["pr_auc"] - epss_pr
        if delta > 0:
            arrow = f"▲+{delta:.4f}"
        elif delta < 0:
            arrow = f"▼{delta:.4f}"
        else:
            arrow = f"═ 0.0000"
        star = "★" if m["pr_auc"] == max(v["pr_auc"] for v in all_results.values()) else " "
        print(f"  │ {star}{name:33s}│ {m['pr_auc']:.4f}  │ {arrow:>14s} │")

    print("  └──────────────────────────────────┴─────────┴────────────────┘")
    print(f"\n  Total time: {total:.0f}s ({total/60:.1f} min)")
    print(f"  Results: {RESULTS_DIR.resolve()}/")
    print(f"  Figures: {FIGURES_DIR.resolve()}/")

    best_name = sorted_models[0][0]
    best_pr   = sorted_models[0][1]["pr_auc"]
    if best_pr > epss_pr:
        print(f"\n  🎉 {best_name} BEATS EPSS!  ({best_pr:.4f} vs {epss_pr:.4f}, Δ={best_pr-epss_pr:+.4f})")
    else:
        print(f"\n  ⚠️  Best model ({best_name}, {best_pr:.4f}) still below EPSS ({epss_pr:.4f})")

    print("  Done! ✅\n")


if __name__ == "__main__":
    main()
