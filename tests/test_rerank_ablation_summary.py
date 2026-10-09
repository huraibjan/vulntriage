"""Offline tests for the A/B aggregation math in rag_rerank_ablation.

No DB/Qdrant/OpenAI — only the pure summarize()/_compare() functions, which are
what turn per-brief rows into the paper-facing comparison.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "rag_rerank_ablation",
    Path(__file__).resolve().parent.parent / "experiments" / "rag_rerank_ablation.py",
)
AB = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(AB)


def _row(nt, rel, over, adv=1, fab=0, faith=1.0):
    return {"n_techniques": nt, "judge_relevant": rel, "over_rationalized": over,
            "advisory_cited": adv, "fabricated_id": fab, "faithfulness": faith}


def test_summarize_empty():
    assert AB.summarize([]) == {"n_briefs": 0}


def test_relevance_excludes_abstentions():
    # 2 briefs cite a technique (1 relevant), 1 abstains (0 techniques).
    rows = [_row(1, 1, 0), _row(1, 0, 1), _row(0, 0, 0)]
    s = AB.summarize(rows)
    assert s["abstain_rate"] == round(1 / 3, 4)
    # relevance denominator is the 2 briefs WITH a technique, not all 3
    assert s["technique_relevant_rate"] == 0.5
    assert s["over_rationalization_rate"] == round(1 / 3, 4)


def test_faithfulness_skips_none():
    rows = [_row(1, 1, 0, faith=1.0), _row(1, 1, 0, faith=0.5), _row(1, 1, 0, faith=None)]
    s = AB.summarize(rows)
    assert s["faithfulness_mean"] == 0.75          # mean(1.0, 0.5), None skipped
    assert s["n_faithfulness_scored"] == 2


def test_compare_direction_reflects_improvement():
    base = AB.summarize([_row(1, 0, 1, faith=0.6), _row(1, 1, 1, faith=0.6)])
    imp = AB.summarize([_row(1, 1, 0, faith=0.9), _row(1, 1, 0, faith=0.9)])
    d = AB._compare(base, imp)
    assert d["technique_relevant_rate"] > 0         # relevance up
    assert d["over_rationalization_rate"] < 0        # over-rationalisation down
    assert d["faithfulness_mean"] > 0                # faithfulness up


def test_fabricated_ids_stay_measured():
    rows = [_row(1, 1, 0, fab=0), _row(1, 1, 0, fab=0)]
    assert AB.summarize(rows)["fabricated_id_rate"] == 0.0
