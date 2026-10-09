#!/usr/bin/env python3
"""NIST LEV (Likely Exploited Vulnerabilities) as an additional baseline.

SOURCE
------
P. Mell and J. Spring, "Likely Exploited Vulnerabilities: A Proposed Metric for
Vulnerability Exploitation Probability", NIST CSWP 41, May 19, 2025
(https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf).

Sec. 4.1 states the LEV equation (it carries no number there; its derivation
ends in Sec. 5.3 as equation (10)):

    LEV(v, d0, dn) >= 1 - PROD_{d_i in dates(d0, dn, 30)}
                              (1 - epss(v, d_i) * weight(d_i, dn, 30))

with, from Table 4 of the same section,

    d0                 first date on which an EPSS score is available for v
    dn                 date on which the calculation is performed
    dates(d0, dn, w)   d0, d0 + w, d0 + 2w, ... not exceeding dn
    datediff(di, dj)   number of days between di and dj, INCLUSIVE
    winsize(di, dn, w) w if datediff(di, dn) >= w else datediff(di, dn)
    weight(di, dn, w)  winsize(di, dn, w) / w

Every window therefore has weight 1 except the last, whose EPSS score is scaled
by the fraction of the 30-day window that has elapsed by dn.  `lev_exact`
implements the equation verbatim and is checked against both worked examples
printed in Sec. 6 of the paper (see `self_test`).

WHAT THIS EXPERIMENT MEASURES, AND ITS LIMITS
---------------------------------------------
1. Monthly sampling approximates the 30-day windowing.  The local archive
   (data/epss_history/) holds one FIRST EPSS file per calendar month
   (22 files, 2024-06-01 .. 2026-03-01), not daily files.  The windows used
   here start on those snapshot dates, so (a) d0 is the first monthly snapshot
   that scores the CVE rather than its true first EPSS date (0-32 days late),
   and (b) consecutive windows are 28-33 days apart rather than exactly 30.
   The primary variant gives every non-final snapshot weight 1 (each monthly
   snapshot stands for one 30-day window); a sensitivity variant weights each
   snapshot by min(days to next snapshot, 30) / 30.
2. LEV here is RETROSPECTIVE.  It aggregates EPSS scores observed AFTER each
   test CVE was published, up to dn = 2026-03-03.  It answers "has this CVE
   probably been exploited by now", which is what LEV is defined to answer.
   It is therefore comparable to the paper's FROZEN-snapshot setting (EPSS as
   of 2026-03-03) and NOT to its historical / point-in-time EPSS setting.
3. The archive spans two EPSS model versions (v2023.03.01 through early 2025,
   v2025.03.14 afterwards); LEV multiplies scores across that boundary exactly
   as NIST's own computation does.

The database is only read.  Usage (from project root):

    python experiments/lev_baseline.py              # full experiment
    python experiments/lev_baseline.py --self-test  # offline checks, no DB

Results are saved to results/lev_baseline.json.
"""

from __future__ import annotations

import argparse
import glob
import gzip
import json
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.logging import get_logger  # noqa: E402

log = get_logger(__name__)

WINDOW_DAYS = 30
LEV_ASOF = date(2026, 3, 3)          # dn: the feature-snapshot date of the frozen setting
N_BOOT = 2000
SEED = 42
ANCHOR_TOLERANCE = 5e-5              # same tolerance as app/ml/fusion.py

EPSS_DIR = Path("data/epss_history")
RESULTS_PATH = Path("results/lev_baseline.json")


# ── LEV equation ───────────────────────────────────────────────────────────

def datediff_inclusive(di: date, dj: date) -> int:
    """NIST CSWP 41 Table 4: number of days between ``di`` and ``dj`` inclusive."""
    return (dj - di).days + 1


def window_weight(di: date, dn: date, w: int = WINDOW_DAYS) -> float:
    """NIST CSWP 41 Table 4: weight(di, dn, w) = winsize(di, dn, w) / w."""
    return min(datediff_inclusive(di, dn), w) / w


def lev_exact(
    epss: Callable[[date], Optional[float]],
    d0: date,
    dn: date,
    w: int = WINDOW_DAYS,
) -> float:
    """LEV exactly as stated in NIST CSWP 41 Sec. 4.1 (derivation equation (10)).

    ``epss`` returns the EPSS score on a date, or None when no score exists; a
    missing score contributes a factor of 1, i.e. no evidence of exploitation.
    Requires daily EPSS access, so it serves as the reference implementation
    against which the monthly approximation is validated.
    """
    survival = 1.0
    d = d0
    while d <= dn:
        score = epss(d)
        if score is not None:
            survival *= 1.0 - float(score) * window_weight(d, dn, w)
        d += timedelta(days=w)
    return 1.0 - survival


def snapshot_weights(
    snapshot_dates: Sequence[date],
    dn: date,
    mode: str = "unit",
    w: int = WINDOW_DAYS,
) -> np.ndarray:
    """Per-snapshot weights when the archive is sampled irregularly (monthly).

    The final snapshot always receives the NIST weight(d_last, dn, w), because
    its window is cut short by dn.  For the earlier snapshots:

    * ``unit``     — weight 1: each snapshot stands for one full 30-day window.
    * ``interval`` — min(days to the next snapshot, w) / w: the score is only
      credited for the days it actually covers, capped at the 30 days an EPSS
      score is defined to predict.
    """
    if mode not in ("unit", "interval"):
        raise ValueError(f"unknown weighting mode: {mode}")
    dates = list(snapshot_dates)
    if dates != sorted(dates) or len(set(dates)) != len(dates):
        raise ValueError("snapshot dates must be strictly increasing")
    if dates[-1] > dn:
        raise ValueError("snapshots after dn must be excluded before weighting")
    weights = np.ones(len(dates))
    if mode == "interval":
        for j in range(len(dates) - 1):
            weights[j] = min((dates[j + 1] - dates[j]).days, w) / w
    weights[-1] = window_weight(dates[-1], dn, w)
    return weights


def lev_from_matrix(scores: np.ndarray, weights: np.ndarray) -> np.ndarray:
    """Vectorised LEV over a [n_cve, n_snapshot] EPSS matrix.

    NaN marks a snapshot in which the CVE has no EPSS score (before its first
    availability, or absent from the file); it contributes a factor of 1.  A CVE
    with no score in any snapshot therefore receives LEV = 0.
    """
    if scores.shape[1] != len(weights):
        raise ValueError("one weight per snapshot column is required")
    term = np.nan_to_num(scores, nan=0.0) * weights[np.newaxis, :]
    if (term < 0).any() or (term > 1).any():
        raise ValueError("EPSS scores must lie in [0, 1]")
    # log1p keeps precision for the many near-zero EPSS scores.
    with np.errstate(divide="ignore"):            # a term of exactly 1 gives LEV = 1
        return 1.0 - np.exp(np.log1p(-term).sum(axis=1))


# ── Data ───────────────────────────────────────────────────────────────────

def load_snapshots(epss_dir: Path = EPSS_DIR) -> Tuple[List[date], List[pd.Series], List[str]]:
    """Read the monthly FIRST EPSS files (same format as point_in_time_epss.py)."""
    dates: List[date] = []
    series: List[pd.Series] = []
    headers: List[str] = []
    for path in sorted(glob.glob(str(epss_dir / "epss_scores-*.csv.gz"))):
        stamp = Path(path).name.replace("epss_scores-", "").replace(".csv.gz", "")
        with gzip.open(path, "rt") as fh:
            header = fh.readline().strip()        # model version comment
            df = pd.read_csv(fh)
        dates.append(date.fromisoformat(stamp))
        series.append(pd.Series(df["epss"].astype(float).values, index=df["cve"].values))
        headers.append(header)
    if not dates:
        raise FileNotFoundError(f"no EPSS snapshots found under {epss_dir}")
    return dates, series, headers


def build_score_matrix(cve_ids: Sequence[str], series: Sequence[pd.Series]) -> np.ndarray:
    """[n_cve, n_snapshot] EPSS matrix aligned to ``cve_ids``; NaN where unscored."""
    index = pd.Index(cve_ids)
    return np.column_stack([s.reindex(index).values for s in series])


def fetch_cve_ids(vuln_ids: Sequence[str]) -> Dict[str, str]:
    """Read-only lookup of cve_id for the test partition."""
    from app.db.models import Vulnerability
    from app.db.session import get_session

    out: Dict[str, str] = {}
    with get_session() as session:
        for i in range(0, len(vuln_ids), 10000):
            batch = list(vuln_ids[i:i + 10000])
            for vid, cve in session.query(Vulnerability.id, Vulnerability.cve_id).filter(
                Vulnerability.id.in_(batch)
            ).all():
                out[str(vid)] = cve or ""
    return out


# ── Metrics ────────────────────────────────────────────────────────────────

def precision_at_k(y: np.ndarray, p: np.ndarray, k: int) -> float:
    """Same definition as experiments/rrf_k_ablation.py::precision_at_k."""
    order = np.argsort(-p)
    k = min(k, len(y))
    return float(y[order[:k]].sum()) / k if k else 0.0


def metrics(y: np.ndarray, p: np.ndarray) -> Dict[str, float]:
    return {
        "pr_auc": round(float(average_precision_score(y, p)), 5),
        "roc_auc": round(float(roc_auc_score(y, p)), 5),
        "precision@100": round(precision_at_k(y, p, 100), 4),
    }


def rrf_fuse(sources: Dict[str, np.ndarray], k: int = 60) -> np.ndarray:
    """Reciprocal Rank Fusion, identical formula to app/ml/fusion.py::rrf_fuse."""
    n = len(next(iter(sources.values())))
    fused = np.zeros(n)
    for p in sources.values():
        ranks = np.argsort(np.argsort(-p))
        fused += 1.0 / (k + ranks)
    return fused


def paired_bootstrap_diff(
    y: np.ndarray,
    scores: Dict[str, np.ndarray],
    comparisons: Sequence[Tuple[str, str]],
    n_boot: int = N_BOOT,
    seed: int = SEED,
) -> Dict[str, Dict[str, object]]:
    """Percentile 95% CI of PR-AUC differences under a paired bootstrap.

    Each resample draws CVE indices once and scores every method on that same
    draw, so the difference is paired.  Mirrors the resampling scheme of
    experiments/statistical_significance.py::paired_bootstrap.
    """
    rng = np.random.default_rng(seed)
    n = len(y)
    needed = sorted({m for pair in comparisons for m in pair})
    diffs = {pair: np.empty(n_boot) for pair in comparisons}
    for b in range(n_boot):
        idx = rng.integers(0, n, n)
        yb = y[idx]
        while yb.sum() == 0:                       # PR-AUC is undefined without a positive
            idx = rng.integers(0, n, n)
            yb = y[idx]
        ap = {m: float(average_precision_score(yb, scores[m][idx])) for m in needed}
        for a, c in comparisons:
            diffs[(a, c)][b] = ap[a] - ap[c]
    out: Dict[str, Dict[str, object]] = {}
    for a, c in comparisons:
        d = diffs[(a, c)]
        point = float(average_precision_score(y, scores[a]) - average_precision_score(y, scores[c]))
        lo, hi = float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))
        out[f"{a}_minus_{c}"] = {
            "pr_auc_diff": round(point, 5),
            "ci95": [round(lo, 5), round(hi, 5)],
            "ci_excludes_zero": bool(lo > 0 or hi < 0),
            "fraction_resamples_positive": round(float((d > 0).mean()), 4),
        }
    return out


# ── Offline self-test (no database, no network) ────────────────────────────

def self_test() -> None:
    """Verify the equation against NIST's worked examples and the approximations."""
    # NIST CSWP 41 Sec. 6, CVE-2023-1730 computed on 2024-12-12: LEV 0.70.  The
    # printed scores are rounded to two decimals and the last (0.06) is already
    # weight-adjusted from the true 0.08, hence the tolerance.
    d0, dn = date(2023, 5, 2), date(2024, 12, 12)
    printed = [0.00, 0.00, 0.00, 0.05, 0.06, 0.06, 0.06, 0.10, 0.13, 0.16,
               0.08, 0.05, 0.05, 0.04, 0.05, 0.05, 0.05, 0.05, 0.05, 0.08]
    table = {d0 + timedelta(days=30 * i): s for i, s in enumerate(printed)}
    assert max(table) == date(2024, 11, 22)                       # matches the printed dates
    assert datediff_inclusive(date(2024, 11, 22), dn) == 21       # "window size of 21"
    assert abs(0.08 * window_weight(date(2024, 11, 22), dn) - 0.06) < 0.005
    assert abs(lev_exact(table.get, d0, dn) - 0.70) < 0.03

    # NIST CSWP 41 Sec. 6, CVE-2023-29373 computed on 2025-01-22: LEV 0.54350.
    d0, dn = date(2023, 6, 14), date(2025, 1, 22)
    printed = [0.00, 0.05, 0.02, 0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.08,
               0.07, 0.04, 0.04, 0.03, 0.03, 0.03, 0.03, 0.03, 0.03, 0.00]
    table = {d0 + timedelta(days=30 * i): s for i, s in enumerate(printed)}
    assert max(table) == date(2025, 1, 4)
    assert datediff_inclusive(date(2025, 1, 4), dn) == 19         # "window size of 19"
    assert abs(lev_exact(table.get, d0, dn) - 0.54350) < 0.02

    # Weight boundaries.
    assert window_weight(date(2025, 1, 1), date(2025, 1, 1)) == 1 / 30
    assert window_weight(date(2025, 1, 1), date(2025, 1, 30)) == 1.0
    assert window_weight(date(2025, 1, 1), date(2025, 6, 1)) == 1.0

    # On an exact 30-day grid the vectorised form equals the verbatim equation.
    grid = [date(2025, 1, 1) + timedelta(days=30 * i) for i in range(5)]
    dn = grid[-1] + timedelta(days=9)
    row = [0.2, 0.0, 0.5, 0.1, 0.9]
    exact = lev_exact(dict(zip(grid, row)).get, grid[0], dn)
    for mode in ("unit", "interval"):
        w = snapshot_weights(grid, dn, mode)
        assert abs(w[-1] - 10 / 30) < 1e-12 and np.allclose(w[:-1], 1.0)
        assert abs(lev_from_matrix(np.array([row]), w)[0] - exact) < 1e-12

    # Irregular (monthly) spacing: interval weights credit only covered days.
    monthly = [date(2025, 2, 1), date(2025, 3, 1), date(2025, 4, 1)]
    w = snapshot_weights(monthly, date(2025, 4, 3), "interval")
    assert np.allclose(w, [28 / 30, 1.0, 3 / 30])
    assert np.allclose(snapshot_weights(monthly, date(2025, 4, 3), "unit"), [1.0, 1.0, 3 / 30])

    # Missing history: all-NaN row -> 0; NaN before first availability is neutral.
    m = np.array([[np.nan, np.nan, np.nan], [np.nan, 0.5, 0.5], [1.0, 0.0, 0.0]])
    out = lev_from_matrix(m, np.array([1.0, 1.0, 0.5]))
    assert out[0] == 0.0
    assert abs(out[1] - (1 - 0.5 * 0.75)) < 1e-12
    assert abs(out[2] - 1.0) < 1e-12
    # LEV is monotone: an additional window can never lower it.
    assert lev_from_matrix(np.array([[0.3, 0.2]]), np.ones(2))[0] >= 0.3

    # Guards.
    for bad in (lambda: snapshot_weights(monthly[::-1], date(2025, 5, 1)),
                lambda: snapshot_weights(monthly, date(2025, 3, 15)),
                lambda: snapshot_weights(monthly, date(2025, 5, 1), "other"),
                lambda: lev_from_matrix(np.array([[1.5]]), np.ones(1))):
        try:
            bad()
        except ValueError:
            continue
        raise AssertionError("expected ValueError")

    # Score-matrix alignment.
    s1 = pd.Series([0.1, 0.2], index=["CVE-1", "CVE-2"])
    s2 = pd.Series([0.3], index=["CVE-2"])
    mat = build_score_matrix(["CVE-2", "CVE-3", "CVE-1"], [s1, s2])
    assert mat.shape == (3, 2) and mat[0, 0] == 0.2 and mat[0, 1] == 0.3
    assert np.isnan(mat[1]).all() and mat[2, 0] == 0.1 and np.isnan(mat[2, 1])

    # Paired bootstrap: identical rankers give a zero difference; a perfect
    # ranker beats a random one with an interval that excludes zero.
    rng = np.random.default_rng(0)
    y = (rng.random(400) < 0.1).astype(int)
    noise = rng.random(400)
    res = paired_bootstrap_diff(
        y, {"a": y + 0.0, "b": noise, "c": noise.copy()},
        [("a", "b"), ("b", "c")], n_boot=200, seed=1)
    assert res["a_minus_b"]["ci_excludes_zero"] and res["a_minus_b"]["ci95"][0] > 0
    assert res["b_minus_c"]["ci95"] == [0.0, 0.0] and not res["b_minus_c"]["ci_excludes_zero"]
    again = paired_bootstrap_diff(y, {"a": y + 0.0, "b": noise}, [("a", "b")], n_boot=200, seed=1)
    assert again["a_minus_b"] == res["a_minus_b"]                  # seeded, reproducible

    # RRF formula parity with the serving implementation.
    from app.ml.fusion import rrf_fuse as serving_rrf
    src = {"x": rng.random(50), "y": rng.random(50)}
    assert np.array_equal(rrf_fuse(src), serving_rrf(src))
    print("self-test passed")


# ── Experiment ─────────────────────────────────────────────────────────────

def run() -> dict:
    from app.ml.fusion import ANCHORS
    from experiments.rrf_k_ablation import reconstruct_split_and_probs

    t0 = time.time()
    self_test()

    _, _, sources, y, extra = reconstruct_split_and_probs()
    test_df = extra["test_df"]
    y = np.asarray(y).astype(int)
    rrf_paper = rrf_fuse(sources, k=60)

    measured = {name: float(average_precision_score(y, p)) for name, p in sources.items()}
    measured["rrf"] = float(average_precision_score(y, rrf_paper))
    mismatches = {
        name: (round(measured[name], 5), anchor)
        for name, anchor in ANCHORS.items()
        if abs(measured[name] - anchor) > ANCHOR_TOLERANCE
    }
    if mismatches or len(y) != 70831 or int(y.sum()) != 277:
        raise RuntimeError(
            f"Test partition does not reproduce the published evaluation "
            f"(n={len(y)}, positives={int(y.sum())}, anchor mismatches={mismatches})."
        )
    log.info("lev_anchors_verified", **{k: round(v, 5) for k, v in measured.items()})

    cve_map = fetch_cve_ids(test_df["vuln_id"].tolist())
    cve_ids = test_df["vuln_id"].map(cve_map).fillna("").tolist()
    published = pd.to_datetime(test_df["published_at"], errors="coerce", format="ISO8601")
    if getattr(published.dt, "tz", None) is not None:
        published = published.dt.tz_localize(None)

    snap_dates, snap_series, headers = load_snapshots()
    keep = [j for j, d in enumerate(snap_dates) if d <= LEV_ASOF]
    snap_dates = [snap_dates[j] for j in keep]
    snap_series = [snap_series[j] for j in keep]
    headers = [headers[j] for j in keep]
    matrix = build_score_matrix(cve_ids, snap_series)

    w_unit = snapshot_weights(snap_dates, LEV_ASOF, "unit")
    w_interval = snapshot_weights(snap_dates, LEV_ASOF, "interval")
    lev = lev_from_matrix(matrix, w_unit)
    lev_interval = lev_from_matrix(matrix, w_interval)

    # Coverage of the historical EPSS archive over the test partition.
    scored = ~np.isnan(matrix)
    n_windows = scored.sum(axis=1)
    has_history = n_windows > 0
    first_idx = np.where(has_history, scored.argmax(axis=1), -1)
    snap_ts = np.array([pd.Timestamp(d) for d in snap_dates])
    first_ts = pd.Series([snap_ts[i] if i >= 0 else pd.NaT for i in first_idx])
    pub_day = published.dt.normalize().reset_index(drop=True)
    lag_days = (first_ts - pub_day).dt.days[has_history]
    no_hist_pub = published.reset_index(drop=True)[~has_history]
    last_snapshot_ts = pd.Timestamp(snap_dates[-1])
    span = scored.shape[1] - np.where(has_history, first_idx, scored.shape[1])
    internal_gaps = int(((span - n_windows) > 0)[has_history].sum())

    coverage = {
        "n_test": int(len(y)),
        "n_with_at_least_one_historical_epss_score": int(has_history.sum()),
        "fraction_with_history": round(float(has_history.mean()), 5),
        "n_without_history": int((~has_history).sum()),
        "n_without_history_published_after_last_snapshot": int(
            (no_hist_pub > last_snapshot_ts).sum()),
        "n_without_history_missing_cve_id": int(
            sum(1 for c, h in zip(cve_ids, has_history) if not h and not c)),
        "positives_with_history": int(y[has_history].sum()),
        "positives_without_history": int(y[~has_history].sum()),
        "windows_per_covered_cve": {
            "min": int(n_windows[has_history].min()),
            "median": float(np.median(n_windows[has_history])),
            "max": int(n_windows[has_history].max()),
        },
        "days_from_publication_to_first_snapshot_score": {
            "median": float(lag_days.median()),
            "p95": float(lag_days.quantile(0.95)),
            "n_scored_in_a_snapshot_dated_before_publication": int((lag_days < 0).sum()),
        },
        "n_covered_cves_absent_from_a_later_snapshot": internal_gaps,
        "missing_history_handling": (
            "A snapshot in which a CVE has no EPSS score contributes a factor of 1 "
            "to the product (no evidence). A CVE with no score in any snapshot "
            "therefore receives LEV = 0 and is ranked at the bottom; ties are "
            "broken by row order, exactly as the paper's RRF treats EPSS ties."
        ),
    }

    rrf_plus_lev = rrf_fuse({**sources, "lev": lev}, k=60)
    rrf_plus_lev_interval = rrf_fuse({**sources, "lev": lev_interval}, k=60)
    rrf_lev_replaces_epss = rrf_fuse(
        {"xgb_tabular": sources["xgb_tabular"], "xgb_tabemb": sources["xgb_tabemb"], "lev": lev},
        k=60)

    results = {
        "LEV (monthly windows, unit weights)": metrics(y, lev),
        "EPSS frozen (2026-03-03)": metrics(y, sources["epss"]),
        "RRF (paper: tabular, tab+emb, EPSS)": metrics(y, rrf_paper),
        "RRF + LEV as fourth rank source": metrics(y, rrf_plus_lev),
    }
    sensitivity = {
        "LEV (monthly windows, interval weights)": metrics(y, lev_interval),
        "RRF + LEV (interval weights) as fourth rank source": metrics(y, rrf_plus_lev_interval),
        "RRF with LEV replacing EPSS (three sources)": metrics(y, rrf_lev_replaces_epss),
        "spearman_lev_unit_vs_interval": round(float(
            pd.Series(lev).corr(pd.Series(lev_interval), method="spearman")), 5),
        "spearman_lev_vs_frozen_epss": round(float(
            pd.Series(lev).corr(pd.Series(sources["epss"]), method="spearman")), 5),
    }

    boot = paired_bootstrap_diff(
        y,
        {"lev": lev, "epss": sources["epss"], "rrf": rrf_paper, "rrf_plus_lev": rrf_plus_lev},
        [("lev", "epss"), ("rrf", "lev"), ("rrf_plus_lev", "rrf")],
    )

    out = {
        "experiment": "lev_baseline",
        "source": "NIST CSWP 41 (Mell & Spring, May 2025), Sec. 4.1 LEV equation; "
                  "derivation equation (10) in Sec. 5.3",
        "equation": "LEV(v,d0,dn) >= 1 - prod_{d_i in dates(d0,dn,30)} "
                    "(1 - epss(v,d_i) * weight(d_i,dn,30)); "
                    "weight = min(datediff_inclusive(d_i,dn), 30) / 30",
        "cutoff_date": "2024-06-01",
        "label_policy": "kev_strict",
        "n_test": int(len(y)),
        "n_positives_test": int(y.sum()),
        "paper_anchor_check": {k: round(v, 5) for k, v in measured.items()},
        "anchors_verified": True,
        "lev_asof_dn": str(LEV_ASOF),
        "epss_snapshots": [str(d) for d in snap_dates],
        "epss_model_versions": sorted({h.split(",")[0].lstrip("#") for h in headers}),
        "snapshot_weights_unit": [round(float(x), 5) for x in w_unit],
        "snapshot_weights_interval": [round(float(x), 5) for x in w_interval],
        "caveats": [
            "Monthly sampling approximates the 30-day windowing of NIST CSWP 41: "
            "windows start on monthly snapshot dates (28-33 days apart), and d0 is "
            "the first monthly snapshot that scores the CVE, not its first EPSS date.",
            "LEV here is retrospective: it uses EPSS scores observed after each CVE "
            "was published, up to 2026-03-03. It is comparable to the paper's "
            "frozen-snapshot setting, not to its historical (point-in-time) EPSS setting.",
            "LEV is a lower bound by construction (the equation is an inequality).",
            "The archive spans two EPSS model versions; scores are multiplied "
            "across that boundary.",
            "The frozen EPSS source is the 2026-03-03 feature snapshot; the last "
            "LEV window starts at the 2026-03-01 archive file with weight 3/30.",
        ],
        "coverage": coverage,
        "results": results,
        "sensitivity": sensitivity,
        "paired_bootstrap": {
            "n_resamples": N_BOOT,
            "seed": SEED,
            "metric": "PR-AUC (average precision) difference, percentile 95% CI",
            **boot,
        },
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    RESULTS_PATH.write_text(json.dumps(out, indent=2))
    log.info("lev_baseline_saved", path=str(RESULTS_PATH))
    print(json.dumps({k: out[k] for k in ("paper_anchor_check", "coverage", "results",
                                          "sensitivity", "paired_bootstrap")}, indent=2))
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline checks only (no database access)")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        run()
