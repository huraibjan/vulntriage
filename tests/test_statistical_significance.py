"""Synthetic-data tests for the paired significance analysis (Phase 2).

Confirms: fast_ap == sklearn, deterministic output, correct pairing, CI
construction, and comparison direction — without touching the DB.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import average_precision_score

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "experiments"))

from statistical_significance import (  # noqa: E402
    fast_ap,
    holm,
    paired_bootstrap,
    paired_permutation,
)


def _synthetic(n=400, seed=0):
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.1).astype(int)          # ~10% positives
    good = y + rng.normal(0, 0.3, n)               # correlated with label
    weak = y * 0.3 + rng.normal(0, 1.0, n)         # weakly correlated
    rand = rng.random(n)                            # uninformative
    return y, good, weak, rand


def test_fast_ap_matches_sklearn():
    y, good, weak, rand = _synthetic()
    for s in (good, weak, rand):
        assert abs(fast_ap(y, s) - average_precision_score(y, s)) < 1e-9


def test_fast_ap_handles_no_positives():
    assert fast_ap(np.zeros(10, int), np.random.rand(10)) == 0.0


def test_bootstrap_is_deterministic():
    y, good, _, rand = _synthetic()
    scores = {"good": good, "rand": rand}
    comps = [("good", "rand")]
    r1 = paired_bootstrap(y, scores, comps, n_boot=500, seed=7)
    r2 = paired_bootstrap(y, scores, comps, n_boot=500, seed=7)
    assert r1[0] == r2[0]                            # point estimates
    assert r1[2][("good", "rand")]["abs_diff_ci"] == r2[2][("good", "rand")]["abs_diff_ci"]


def test_bootstrap_ci_brackets_point_estimate():
    y, good, _, rand = _synthetic()
    ap, ci, _ = paired_bootstrap(y, {"good": good, "rand": rand},
                                 [("good", "rand")], n_boot=1000, seed=1)
    for m in ("good", "rand"):
        lo, hi = ci[m]
        assert lo <= ap[m] <= hi


def test_pairing_direction_good_beats_random():
    """A good ranker should have a positive, significant difference vs random."""
    y, good, _, rand = _synthetic(n=600, seed=3)
    ap, _, diff = paired_bootstrap(y, {"good": good, "rand": rand},
                                   [("good", "rand")], n_boot=1000, seed=3)
    d = diff[("good", "rand")]
    assert d["abs_diff"] > 0                          # correct direction
    assert d["abs_diff_ci"][0] > 0                    # CI excludes 0
    obs, p = paired_permutation(y, good, rand, n_perm=1000, seed=3)
    assert obs > 0 and p < 0.05                        # significant


def test_identical_scores_are_indistinguishable():
    """Same scores => zero difference and non-significant permutation p."""
    y, good, _, _ = _synthetic()
    obs, p = paired_permutation(y, good, good.copy(), n_perm=1000, seed=5)
    assert obs == 0.0
    assert p == pytest.approx(1.0, abs=1e-6)


def test_holm_monotone_and_bounded():
    adj = holm({"a": 0.001, "b": 0.02, "c": 0.5})
    assert all(0 <= v <= 1 for v in adj.values())
    assert adj["a"] <= adj["b"] <= adj["c"]           # step-down monotonicity
