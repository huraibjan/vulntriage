#!/usr/bin/env python3
"""Experiment 6: Point-in-Time EPSS — the fully honest headline evaluation.

MOTIVATION (conference-defense critical)
----------------------------------------
The snapshot store holds only 2026-03 EPSS values, so the paper's main
evaluation scores test CVEs (published 2024-06 .. 2026-03) with EPSS values
that postdate them — the retroactive-enrichment channel quantified by the
rolling-window experiment.  This experiment removes that channel entirely
using FIRST's public historical EPSS archive:

  * TRAIN/VAL CVEs get EPSS exactly as of the 2024-06-01 cutoff snapshot —
    precisely what a model trained at the cutoff would have seen.
  * TEST CVEs get EPSS from the first monthly snapshot ON/AFTER their
    publication date (0-31 day lag) — what an analyst triaging a new CVE
    would actually have had.  CVEs not yet scored in that snapshot get 0.

The tuned v2 XGBoost configurations are retrained with the point-in-time
EPSS feature, and the full RRF ensemble is re-evaluated.  Every number can
then be defended as free of enrichment hindsight.

Snapshots: data/epss_history/epss_scores-YYYY-MM-DD.csv.gz (22 monthly
files, 2024-06-01 .. 2026-03-01; 2024-12-02 substitutes an unavailable
2024-12-01).  Each file carries the EPSS model version in its header
(v2023.03.01 = EPSS v3 through 2025; later files EPSS v4), i.e. scores are
exactly what FIRST published on that date.

Usage (from project root):
    python experiments/point_in_time_epss.py

Results are saved to results/point_in_time_epss.json.
"""

from __future__ import annotations

import glob
import gzip
import json
import sys
import time
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.models import FeatureSnapshot, Vulnerability
from app.db.session import get_session
from app.features.ablation import get_feature_columns
from app.features.builder import build_labels_df, time_aware_split
from app.ml.text.embeddings import TextEmbeddingPipeline

ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY = "kev_strict"
ABLATION = "no_circular"
SEED = 42
VAL_FRACTION = 0.15
PCA_COMPONENTS = 64

EPSS_DIR = Path("data/epss_history")
MODELS_DIR = Path("models")
RESULTS_DIR = Path("results")

XGB_PARAMS = {
    "n_estimators": 414, "max_depth": 7,
    "learning_rate": 0.08742933234856033,
    "subsample": 0.987460777589654,
    "colsample_bytree": 0.6966521828215488,
    "min_child_weight": 3, "gamma": 0.2877938000832214,
    "reg_alpha": 1.6377473104949667, "reg_lambda": 2.617494451636084,
    "objective": "binary:logistic", "eval_metric": "aucpr",
    "tree_method": "hist", "random_state": SEED, "n_jobs": 4,
}


def pr_auc(y, p):
    try:
        return float(average_precision_score(y, p))
    except ValueError:
        return 0.0


def p_at_k(y, p, k):
    order = np.argsort(-p)
    k = min(k, len(y))
    return float(y[order[:k]].sum()) / k


def rrf_fuse(arrays, k=60):
    n = len(arrays[0])
    s = np.zeros(n)
    for p in arrays:
        ranks = np.argsort(np.argsort(-p))
        s += 1.0 / (k + ranks)
    return s


def fit_xgb(X, y):
    n_pos = int(y.sum())
    params = dict(XGB_PARAMS)
    params["scale_pos_weight"] = (len(y) - n_pos) / max(n_pos, 1)
    m = xgb.XGBClassifier(**params)
    m.fit(X, y)
    return m


# ── EPSS snapshot loading ──────────────────────────────────────────────────

def load_snapshots() -> dict[str, dict[str, float]]:
    """Return {snapshot_date_str: {cve_id: epss}} sorted by date."""
    snaps = {}
    for path in sorted(glob.glob(str(EPSS_DIR / "epss_scores-*.csv.gz"))):
        d = Path(path).stem.replace("epss_scores-", "").replace(".csv", "")
        with gzip.open(path, "rt") as f:
            header = f.readline()          # model version comment
            df = pd.read_csv(f)
        snaps[d] = dict(zip(df["cve"], df["epss"].astype(float)))
        print(f"    {d}: {len(df):,} CVEs   ({header.strip()[:60]})")
    return snaps


def pit_epss_for_test(pub_dates: pd.Series, cve_ids: pd.Series,
                      snaps: dict) -> np.ndarray:
    """First monthly snapshot on/after each CVE's publication date."""
    snap_dates = sorted(snaps.keys())
    snap_ts = [pd.Timestamp(d) for d in snap_dates]
    out = np.zeros(len(cve_ids))
    for i, (pub, cve) in enumerate(zip(pub_dates, cve_ids)):
        if pd.isna(pub) or not cve:
            continue
        idx = next((j for j, ts in enumerate(snap_ts) if ts >= pub), None)
        if idx is None:
            continue                      # published after last snapshot
        out[i] = snaps[snap_dates[idx]].get(cve, 0.0)
    return out


def run() -> dict:
    t0 = time.time()
    print("=" * 72)
    print("  Experiment 6: Point-in-Time EPSS (honest headline evaluation)")
    print("=" * 72)

    print("\n[1/5] Loading EPSS history snapshots …")
    snaps = load_snapshots()
    cutoff_snap = snaps[sorted(snaps.keys())[0]]     # 2024-06-01

    print("\n[2/5] Reconstructing v2 split …")
    with get_session() as session:
        db_snaps = session.query(FeatureSnapshot).filter_by(
            asof=ASOF_DATE, feature_version="v1").all()
        rows = []
        for s in db_snaps:
            feat = dict(s.features_json)
            feat["vuln_id"] = str(s.vulnerability_id)
            rows.append(feat)
        fdf = pd.DataFrame(rows)
        labels = build_labels_df(session, policy_name=POLICY)
        merged = fdf.merge(labels, on="vuln_id", how="inner")

        train_full, test_df = time_aware_split(merged, CUTOFF_DATE)
        y_full = train_full["exploited"].astype(int)
        train_df, val_df = train_test_split(
            train_full, test_size=VAL_FRACTION, stratify=y_full,
            random_state=SEED)
        train_df = train_df.reset_index(drop=True)
        val_df = val_df.reset_index(drop=True)
        test_df = test_df.reset_index(drop=True)

        # cve_id + description maps
        need = (train_df["vuln_id"].tolist() + val_df["vuln_id"].tolist()
                + test_df["vuln_id"].tolist())
        import uuid as uuid_mod
        cve_map, desc_map = {}, {}
        for i in range(0, len(need), 10000):
            batch = [uuid_mod.UUID(v) for v in need[i:i + 10000]]
            for vid, cve, desc in session.query(
                    Vulnerability.id, Vulnerability.cve_id,
                    Vulnerability.description).filter(
                    Vulnerability.id.in_(batch)).all():
                cve_map[str(vid)] = cve or ""
                desc_map[str(vid)] = desc or ""

    for df in (train_df, val_df, test_df):
        df["cve_id"] = df["vuln_id"].map(cve_map)

    y_train = train_df["exploited"].astype(int)
    y_val = val_df["exploited"].astype(int).values
    y_test = test_df["exploited"].astype(int).values
    print(f"  Train {len(train_df):,} | Val {len(val_df):,} | "
          f"Test {len(test_df):,} ({int(y_test.sum())} pos)")

    # ── 3. Point-in-time EPSS assignment ────────────────────────────────
    print("\n[3/5] Assigning point-in-time EPSS …")
    # Train/val: as of cutoff snapshot
    ep_train = train_df["cve_id"].map(cutoff_snap).fillna(0.0).values
    ep_val = val_df["cve_id"].map(cutoff_snap).fillna(0.0).values
    # Test: first snapshot after publication
    pub = pd.to_datetime(test_df["published_at"], errors="coerce",
                         format="ISO8601")
    ep_test_pit = pit_epss_for_test(pub, test_df["cve_id"], snaps)
    ep_test_frozen = test_df["epss_score"].fillna(0).values

    cov = float((ep_test_pit > 0).mean())
    corr = float(np.corrcoef(ep_test_pit, ep_test_frozen)[0, 1])
    print(f"  Test PIT-EPSS coverage: {cov:.1%} nonzero | "
          f"corr(PIT, frozen-2026) = {corr:.3f}")
    print(f"  EPSS-only PR-AUC: frozen={pr_auc(y_test, ep_test_frozen):.5f}  "
          f"point-in-time={pr_auc(y_test, ep_test_pit):.5f}")

    # ── 4. Retrain models with PIT EPSS ─────────────────────────────────
    print("\n[4/5] Retraining models with point-in-time EPSS …")
    feat_cols = get_feature_columns(ABLATION, policy_name=POLICY)
    avail = [c for c in feat_cols if c in merged.columns]

    def X_of(df, ep):
        X = df[avail].fillna(0).astype(float).copy()
        X["epss_score"] = ep
        return X

    Xtr, Xv, Xte = (X_of(train_df, ep_train), X_of(val_df, ep_val),
                    X_of(test_df, ep_test_pit))

    tab = fit_xgb(Xtr, y_train)
    p_tab = tab.predict_proba(Xte)[:, 1]
    print(f"  PIT tabular      PR-AUC = {pr_auc(y_test, p_tab):.5f} "
          f"(frozen anchor 0.25069)")

    # tab+emb with cached embeddings
    def texts_for(df):
        return [desc_map.get(v, "") if len(desc_map.get(v, "")) > 10
                else "No description available." for v in df["vuln_id"]]

    pipe = TextEmbeddingPipeline(model_name="all-MiniLM-L6-v2",
                                 n_components=PCA_COMPONENTS)
    pipe.load(MODELS_DIR / "text_embedding_pipeline_v2.joblib")
    tr_emb = pipe.transform_raw(pipe.encode_raw(texts_for(train_df),
                                                cache_key="v2_train"))
    v_emb = pipe.transform_raw(pipe.encode_raw(texts_for(val_df),
                                               cache_key="v2_val"))
    te_emb = pipe.transform_raw(pipe.encode_raw(texts_for(test_df),
                                                cache_key="v2_test"))
    emb_cols = [f"emb_{i}" for i in range(te_emb.shape[1])]

    def with_emb(X, emb):
        return pd.concat([X.reset_index(drop=True),
                          pd.DataFrame(emb, columns=emb_cols)], axis=1)

    tabemb = fit_xgb(with_emb(Xtr, tr_emb), y_train)
    p_tabemb = tabemb.predict_proba(with_emb(Xte, te_emb))[:, 1]
    print(f"  PIT tab+emb      PR-AUC = {pr_auc(y_test, p_tabemb):.5f} "
          f"(frozen anchor 0.30864)")

    # ── 5. RRF under honest conditions ──────────────────────────────────
    print("\n[5/5] RRF ensemble under point-in-time conditions …")
    p_rrf_pit = rrf_fuse([p_tab, p_tabemb, ep_test_pit], k=60)

    results_rows = {
        "EPSS point-in-time (baseline)": ep_test_pit,
        "CVSS": test_df["cvss_base_score"].fillna(0).values / 10.0,
        "XGB tabular (PIT)": p_tab,
        "XGB tab+emb (PIT)": p_tabemb,
        "RRF ensemble (PIT)": p_rrf_pit,
    }
    table = {}
    for name, p in results_rows.items():
        table[name] = {
            "pr_auc": round(pr_auc(y_test, p), 5),
            "roc_auc": round(float(roc_auc_score(y_test, p)), 5),
            "precision@50": round(p_at_k(y_test, p, 50), 4),
            "precision@100": round(p_at_k(y_test, p, 100), 4),
        }
    print(f"  {'Model':<30} {'PR-AUC':>8} {'ROC':>8} {'P@100':>7}")
    print("  " + "-" * 58)
    for name, m in sorted(table.items(), key=lambda kv: -kv[1]["pr_auc"]):
        print(f"  {name:<30} {m['pr_auc']:>8.5f} {m['roc_auc']:>8.5f} "
              f"{m['precision@100']:>7.3f}")

    epss_pit_auc = table["EPSS point-in-time (baseline)"]["pr_auc"]
    rrf_pit_auc = table["RRF ensemble (PIT)"]["pr_auc"]
    gain = (rrf_pit_auc - epss_pit_auc) / epss_pit_auc if epss_pit_auc else 0
    print(f"\n  RRF vs point-in-time EPSS: {gain:+.1%}")
    print(f"  (frozen-2026 comparison was 0.36714 vs 0.27105 = +35.4%)")

    out = {
        "experiment": "point_in_time_epss",
        "purpose": "Remove retroactive-enrichment channel from the headline "
                   "evaluation using FIRST historical EPSS archive.",
        "epss_snapshots": sorted(snaps.keys()),
        "train_epss": "as-of cutoff snapshot 2024-06-01",
        "test_epss": "first monthly snapshot on/after publication (0-31d lag)",
        "test_pit_coverage_nonzero": round(cov, 4),
        "corr_pit_vs_frozen": round(corr, 4),
        "n_test": len(y_test),
        "n_positives_test": int(y_test.sum()),
        "results": table,
        "rrf_gain_over_pit_epss": round(gain, 4),
        "frozen_reference": {"rrf": 0.36714, "epss": 0.27105,
                             "tabular": 0.25069, "tabemb": 0.30864},
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    (RESULTS_DIR / "point_in_time_epss.json").write_text(
        json.dumps(out, indent=2))
    print(f"\n  Saved -> results/point_in_time_epss.json")
    return out


if __name__ == "__main__":
    run()
