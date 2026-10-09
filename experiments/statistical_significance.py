#!/usr/bin/env python3
"""Phase 2: Paired bootstrap CIs + paired permutation significance tests.

IEEE revision-2. Quantifies whether the paper's headline PR-AUC differences are
statistically distinguishable, so claims can be phrased from evidence.

METHODOLOGY (documented for the paper's methods section)
--------------------------------------------------------
Resampling unit
    The CVE (one test instance = one vulnerability with a KEV-strict label and a
    score from each method). Every method is scored on the *same* resampled CVE
    indices (paired), so a resample cannot advantage one method over another.

Metric
    PR-AUC = average precision = sum over positives of precision-at-rank / n_pos
    (the sklearn ``average_precision_score`` definition). We verify our fast
    numpy implementation against sklearn to <1e-6 on the real data before use.
    We report Precision@100 as a point estimate only: top-k on a single global
    ranked list is not well-behaved under an ordinary row bootstrap (the top-k
    set and its size change unstably with duplicates), so we do NOT attach a
    bootstrap CI to it.

Bootstrap (confidence intervals)
    B = 10,000 paired resamples of the 70,831 test CVEs with replacement
    (seed 42). Duplicates are kept and weight an instance identically for every
    method (paired), so method *differences* remain valid. We report PERCENTILE
    95% intervals. We deliberately do not use BCa: reliable acceleration needs a
    leave-one-out jackknife over 70k points, and a mis-specified acceleration is
    worse than a transparent percentile interval; the percentile interval is a
    standard, defensible choice and we state it explicitly.

Permutation (significance)
    B = 10,000 paired randomizations (seed 42). Under H0 the two scoring methods
    are exchangeable, so for each CVE we independently swap the two methods'
    scores with probability 0.5 and recompute the PR-AUC difference, building the
    null. Two-sided p = (1 + #{|null| >= |observed|}) / (B + 1).

Multiple comparisons
    Primary (pre-registered) comparison: RRF vs point-in-time EPSS. The four
    headline comparisons form a family corrected with Holm-Bonferroni. A
    difference is called "statistically distinguishable" only if its Holm-
    adjusted p < 0.05 AND its 95% difference CI excludes 0. We never infer
    significance from two individual CIs merely overlapping / not overlapping.

Usage:  python experiments/statistical_significance.py            (needs DB up)
Outputs: results/statistical_significance.json
         results/statistical_significance.csv
         reports/statistical_significance_summary.md
"""

from __future__ import annotations

import json
import sys
import time
from datetime import date
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rrf_k_ablation import (  # noqa: E402
    combsum,
    reconstruct_split_and_probs,
    rrf_fuse,
)

RESULTS = Path("results")
REPORTS = Path("reports")
SEED = 42
N_BOOT = 10_000
N_PERM = 10_000


# ── fast average precision (verified against sklearn) ──────────────────────

def fast_ap(y: np.ndarray, s: np.ndarray) -> float:
    """Average precision, tie-correct (matches sklearn average_precision_score).

    AP = sum_n (R_n - R_{n-1}) * P_n over distinct score thresholds, aggregating
    tied scores into one threshold group (as sklearn's precision_recall_curve
    does) so heavily-tied score vectors (e.g. point-in-time EPSS with many
    zeros) are scored identically to sklearn.
    """
    n_pos = y.sum()
    if n_pos == 0:
        return 0.0
    order = np.argsort(-s, kind="mergesort")
    y_s = y[order]
    s_s = s[order]
    tp = np.cumsum(y_s)
    fp = np.cumsum(1.0 - y_s)
    # last index of each tied-score group
    last = np.r_[np.nonzero(np.diff(s_s))[0], len(s_s) - 1]
    precision = tp[last] / (tp[last] + fp[last])
    recall = tp[last] / n_pos
    recall_prev = np.r_[0.0, recall[:-1]]
    return float(np.sum((recall - recall_prev) * precision))


def p_at_k(y, s, k=100):
    order = np.argsort(-s)
    k = min(k, len(y))
    return float(y[order[:k]].sum()) / k


# ── point-in-time reconstruction (mirrors point_in_time_epss.py) ───────────

def reconstruct_pit(test_df, y_test):
    """Retrain tabular + tab+emb with point-in-time EPSS; return per-CVE scores."""
    import joblib
    import xgboost as xgb
    from point_in_time_epss import (
        XGB_PARAMS, PCA_COMPONENTS, load_snapshots, pit_epss_for_test,
    )
    from app.db.models import Vulnerability
    from app.db.session import get_session
    from app.features.ablation import get_feature_columns
    from app.ml.text.embeddings import TextEmbeddingPipeline

    snaps = load_snapshots()
    cutoff_snap = snaps[sorted(snaps.keys())[0]]

    # cve_id + description for test rows (+ train for retrain fitting)
    from rrf_k_ablation import (  # reuse the exact split reconstruction
        reconstruct_split_and_probs,
    )
    # We need the train split too; re-run reconstruct once more is wasteful, so
    # rebuild train/val/test frames here from the DB the same way.
    from app.features.builder import build_labels_df, time_aware_split
    from app.db.models import FeatureSnapshot
    from sklearn.model_selection import train_test_split
    with get_session() as s:
        snaps_db = s.query(FeatureSnapshot).filter_by(
            asof=date(2026, 3, 3), feature_version="v1").all()
        rows = [dict(x.features_json, vuln_id=str(x.vulnerability_id)) for x in snaps_db]
        fdf = pd.DataFrame(rows)
        labels = build_labels_df(s, policy_name="kev_strict")
        merged = fdf.merge(labels, on="vuln_id", how="inner")
        tr_full, te = time_aware_split(merged, "2024-06-01")
        y_full = tr_full["exploited"].astype(int)
        tr, _ = train_test_split(tr_full, test_size=0.15, stratify=y_full, random_state=SEED)
        tr = tr.reset_index(drop=True); te = te.reset_index(drop=True)
        need = tr["vuln_id"].tolist() + te["vuln_id"].tolist()
        import uuid as u
        cve_map, desc_map = {}, {}
        for i in range(0, len(need), 10000):
            batch = [u.UUID(v) for v in need[i:i + 10000]]
            for vid, cve, d in s.query(Vulnerability.id, Vulnerability.cve_id,
                                       Vulnerability.description).filter(
                    Vulnerability.id.in_(batch)).all():
                cve_map[str(vid)] = cve or ""; desc_map[str(vid)] = d or ""
    for df in (tr, te):
        df["cve_id"] = df["vuln_id"].map(cve_map)

    feat = [c for c in get_feature_columns("no_circular", policy_name="kev_strict")
            if c in merged.columns]
    ytr = tr["exploited"].astype(int)
    ep_tr = tr["cve_id"].map(cutoff_snap).fillna(0.0).values
    pub = pd.to_datetime(te["published_at"], errors="coerce", format="ISO8601")
    ep_te_pit = pit_epss_for_test(pub, te["cve_id"], snaps)

    def X_of(df, ep):
        X = df[feat].fillna(0).astype(float).copy(); X["epss_score"] = ep; return X

    def fit(X, y):
        p = dict(XGB_PARAMS); p["scale_pos_weight"] = (len(y) - y.sum()) / max(y.sum(), 1)
        m = xgb.XGBClassifier(**p); m.fit(X, y); return m

    tab = fit(X_of(tr, ep_tr), ytr)
    p_tab = tab.predict_proba(X_of(te, ep_te_pit))[:, 1]

    pipe = TextEmbeddingPipeline(model_name="all-MiniLM-L6-v2", n_components=PCA_COMPONENTS)
    pipe.load(Path("models") / "text_embedding_pipeline_v2.joblib")
    def texts(df): return [desc_map.get(v, "") if len(desc_map.get(v, "")) > 10
                           else "No description available." for v in df["vuln_id"]]
    tr_emb = pipe.transform_raw(pipe.encode_raw(texts(tr), cache_key="v2_train"))
    te_emb = pipe.transform_raw(pipe.encode_raw(texts(te), cache_key="v2_test"))
    ec = [f"emb_{i}" for i in range(te_emb.shape[1])]
    def we(X, e): return pd.concat([X.reset_index(drop=True), pd.DataFrame(e, columns=ec)], axis=1)
    tabemb = fit(we(X_of(tr, ep_tr), tr_emb), ytr)
    p_tabemb = tabemb.predict_proba(we(X_of(te, ep_te_pit), te_emb))[:, 1]

    rrf_pit = rrf_fuse({"t": p_tab, "e": p_tabemb, "p": ep_te_pit}, k=60)
    return {"RRF_pit": rrf_pit, "EPSS_pit": ep_te_pit}


# ── tabular with / without EPSS (the -87% dependence claim) ─────────────────

def reconstruct_tab_epss(test_df, y_test):
    import xgboost as xgb
    from point_in_time_epss import XGB_PARAMS
    from app.features.ablation import get_feature_columns
    from app.features.builder import build_labels_df, time_aware_split
    from app.db.models import FeatureSnapshot
    from app.db.session import get_session
    from sklearn.model_selection import train_test_split
    with get_session() as s:
        snaps_db = s.query(FeatureSnapshot).filter_by(
            asof=date(2026, 3, 3), feature_version="v1").all()
        rows = [dict(x.features_json, vuln_id=str(x.vulnerability_id)) for x in snaps_db]
        merged = pd.DataFrame(rows).merge(
            build_labels_df(s, policy_name="kev_strict"), on="vuln_id", how="inner")
    tr_full, te = time_aware_split(merged, "2024-06-01")
    y_full = tr_full["exploited"].astype(int)
    tr, _ = train_test_split(tr_full, test_size=0.15, stratify=y_full, random_state=SEED)
    tr = tr.reset_index(drop=True); te = te.reset_index(drop=True)
    ytr = tr["exploited"].astype(int)
    feat = [c for c in get_feature_columns("no_circular", policy_name="kev_strict")
            if c in merged.columns]
    no_epss = [c for c in feat if c != "epss_score"]

    def fit_pred(cols):
        p = dict(XGB_PARAMS); p["scale_pos_weight"] = (len(ytr) - ytr.sum()) / max(ytr.sum(), 1)
        m = xgb.XGBClassifier(**p); m.fit(tr[cols].fillna(0).astype(float), ytr)
        return m.predict_proba(te[cols].fillna(0).astype(float))[:, 1]

    return {"tab_with_epss": fit_pred(feat), "tab_without_epss": fit_pred(no_epss)}


# ── paired bootstrap + permutation ─────────────────────────────────────────

def paired_bootstrap(y, scores: dict, comparisons, n_boot=N_BOOT, seed=SEED):
    rng = np.random.default_rng(seed)
    n = len(y)
    method_ap = {m: fast_ap(y, s) for m, s in scores.items()}
    boot_method = {m: np.empty(n_boot) for m in scores}
    boot_diff = {c: np.empty(n_boot) for c in comparisons}
    for b in range(n_boot):
        idx = rng.integers(0, n, n)
        yb = y[idx]
        aps = {m: fast_ap(yb, s[idx]) for m, s in scores.items()}
        for m in scores:
            boot_method[m][b] = aps[m]
        for (a, bb) in comparisons:
            boot_diff[(a, bb)][b] = aps[a] - aps[bb]

    def ci(arr):
        return [float(np.percentile(arr, 2.5)), float(np.percentile(arr, 97.5))]

    method_ci = {m: ci(boot_method[m]) for m in scores}
    diff_ci = {}
    for (a, bb) in comparisons:
        d = boot_diff[(a, bb)]
        base = method_ap[bb]
        rel = d / base if base else np.full_like(d, np.nan)
        diff_ci[(a, bb)] = {
            "abs_diff": method_ap[a] - method_ap[bb],
            "abs_diff_ci": ci(d),
            "rel_diff": (method_ap[a] - method_ap[bb]) / base if base else None,
            "rel_diff_ci": [float(np.nanpercentile(rel, 2.5)),
                            float(np.nanpercentile(rel, 97.5))] if base else None,
        }
    return method_ap, method_ci, diff_ci


def paired_permutation(y, sa, sb, n_perm=N_PERM, seed=SEED):
    rng = np.random.default_rng(seed + 1)
    obs = fast_ap(y, sa) - fast_ap(y, sb)
    n = len(y); count = 0
    for _ in range(n_perm):
        swap = rng.random(n) < 0.5
        a2 = np.where(swap, sb, sa)
        b2 = np.where(swap, sa, sb)
        if abs(fast_ap(y, a2) - fast_ap(y, b2)) >= abs(obs):
            count += 1
    return obs, (1 + count) / (n_perm + 1)


def holm(pvals: dict):
    items = sorted(pvals.items(), key=lambda kv: kv[1])
    m = len(items); adj = {}; running = 0.0
    for i, (k, p) in enumerate(items):
        a = min(1.0, (m - i) * p)
        running = max(running, a)
        adj[k] = running
    return adj


def run():
    t0 = time.time()
    print("=" * 72)
    print("  Phase 2: paired bootstrap CIs + permutation significance")
    print("=" * 72)

    print("\n[1/5] Reconstructing frozen per-CVE scores …")
    sv, yv, st, y_test, extra = reconstruct_split_and_probs()
    y_test = np.asarray(y_test).astype(int)
    scores = {
        "RRF_frozen": rrf_fuse(st, k=60),
        "EPSS_frozen": st["epss"],
        "CombSUM_frozen": combsum(st),
    }
    test_df = extra["test_df"]

    print("[2/5] Reconstructing point-in-time scores (retrain) …")
    scores.update(reconstruct_pit(test_df, y_test))

    print("[3/5] Reconstructing tabular ± EPSS (retrain) …")
    scores.update(reconstruct_tab_epss(test_df, y_test))

    # sanity: fast_ap vs sklearn on the real data. Tolerance 1e-4 absorbs
    # negligible tie-handling differences (EPSS has many tied scores); both are
    # valid AP estimators and fast_ap is used consistently for every method and
    # resample, so method *differences* are unaffected.
    max_d = 0.0
    for m, s in scores.items():
        d = abs(fast_ap(y_test, s) - average_precision_score(y_test, s))
        max_d = max(max_d, d)
        assert d < 1e-6, f"fast_ap mismatch for {m}: {d}"
    print(f"  fast_ap matches sklearn (max abs diff {max_d:.2e}) for all methods")

    # ── comparison family; primary = RRF vs point-in-time EPSS ───────────
    comps = {
        "RRF_vs_EPSS_frozen": ("RRF_frozen", "EPSS_frozen"),
        "RRF_vs_EPSS_pointintime": ("RRF_pit", "EPSS_pit"),          # PRIMARY
        "RRF_vs_CombSUM": ("RRF_frozen", "CombSUM_frozen"),
        "tabular_with_vs_without_EPSS": ("tab_with_epss", "tab_without_epss"),
    }
    primary = "RRF_vs_EPSS_pointintime"

    print(f"\n[4/5] Paired bootstrap ({N_BOOT:,}) …")
    method_ap, method_ci, diff_ci = paired_bootstrap(
        y_test, scores, list(comps.values()))
    for m in scores:
        print(f"  {m:<20} PR-AUC={method_ap[m]:.4f}  95% CI"
              f"[{method_ci[m][0]:.4f}, {method_ci[m][1]:.4f}]  "
              f"P@100={p_at_k(y_test, scores[m]):.3f}")

    print(f"\n[5/5] Paired permutation ({N_PERM:,}) …")
    raw_p = {}
    perm = {}
    for name, (a, b) in comps.items():
        obs, p = paired_permutation(y_test, scores[a], scores[b])
        raw_p[name] = p
        perm[name] = {"observed_diff": obs, "p_two_sided": p}
        print(f"  {name:<30} Δ={obs:+.4f}  p={p:.4f}")
    adj_p = holm(raw_p)

    # ── assemble results ─────────────────────────────────────────────────
    table = []
    for name, (a, b) in comps.items():
        dc = diff_ci[(a, b)]
        distinguishable = bool(adj_p[name] < 0.05 and (dc["abs_diff_ci"][0] > 0
                               or dc["abs_diff_ci"][1] < 0))
        row = {
            "comparison": name,
            "is_primary": name == primary,
            "method_a": a, "pr_auc_a": round(method_ap[a], 5),
            "ci_a": [round(x, 5) for x in method_ci[a]],
            "method_b": b, "pr_auc_b": round(method_ap[b], 5),
            "ci_b": [round(x, 5) for x in method_ci[b]],
            "abs_diff": round(dc["abs_diff"], 5),
            "abs_diff_95ci": [round(x, 5) for x in dc["abs_diff_ci"]],
            "rel_diff": round(dc["rel_diff"], 4) if dc["rel_diff"] is not None else None,
            "rel_diff_95ci": [round(x, 4) for x in dc["rel_diff_ci"]] if dc["rel_diff_ci"] else None,
            "p_two_sided_raw": round(raw_p[name], 5),
            "p_holm_adjusted": round(adj_p[name], 5),
            "statistically_distinguishable_alpha0.05": distinguishable,
        }
        table.append(row)

    out = {
        "experiment": "statistical_significance",
        "n_test": int(len(y_test)), "n_positives": int(y_test.sum()),
        "n_bootstrap": N_BOOT, "n_permutation": N_PERM, "seed": SEED,
        "ci_method": "percentile (BCa not used; see docstring)",
        "resampling_unit": "CVE (paired across methods)",
        "primary_comparison": primary,
        "multiple_comparison_correction": "Holm-Bonferroni over the 4-comparison family",
        "note_topk": "Precision@100 reported as point estimate only; no bootstrap "
                     "CI (top-k on a single global ranked list is ill-behaved under "
                     "row bootstrap).",
        "per_method": {m: {"pr_auc": round(method_ap[m], 5),
                            "pr_auc_95ci": [round(x, 5) for x in method_ci[m]],
                            "precision_at_100": round(p_at_k(y_test, scores[m]), 4)}
                       for m in scores},
        "comparisons": table,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "statistical_significance.json").write_text(json.dumps(out, indent=2))
    pd.DataFrame(table).to_csv(RESULTS / "statistical_significance.csv", index=False)

    # human-readable summary
    lines = ["# Statistical significance — headline comparisons\n",
             f"n_test={len(y_test):,}, positives={int(y_test.sum())}, "
             f"bootstrap={N_BOOT:,}, permutation={N_PERM:,}, seed={SEED}. "
             "Percentile 95% CIs; Holm-Bonferroni; primary = RRF vs point-in-time EPSS.\n",
             "| Comparison | A PR-AUC | B PR-AUC | Δ (95% CI) | rel Δ | p (Holm) | distinguishable? |",
             "|---|---|---|---|---|---|---|"]
    for r in table:
        star = " **(primary)**" if r["is_primary"] else ""
        lines.append(
            f"| {r['comparison']}{star} | {r['pr_auc_a']:.4f} | {r['pr_auc_b']:.4f} | "
            f"{r['abs_diff']:+.4f} [{r['abs_diff_95ci'][0]:+.4f}, {r['abs_diff_95ci'][1]:+.4f}] | "
            f"{(str(round(100*r['rel_diff'],1))+'%') if r['rel_diff'] is not None else '-'} | "
            f"{r['p_holm_adjusted']:.4f} | "
            f"{'YES' if r['statistically_distinguishable_alpha0.05'] else 'no'} |")
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "statistical_significance_summary.md").write_text("\n".join(lines) + "\n")

    print("\n" + "\n".join(lines))
    print(f"\n  Saved -> results/statistical_significance.{{json,csv}}, "
          f"reports/statistical_significance_summary.md  ({out['elapsed_seconds']}s)")
    return out


if __name__ == "__main__":
    run()
