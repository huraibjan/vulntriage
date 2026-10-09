"""Offline unit tests for the cross-encoder re-ranker and CRAG relevance gate.

The real cross-encoder is mocked so these run without downloading weights or
touching Qdrant — they verify the re-ranking/gating LOGIC, which is what the
RAG-quality improvement rests on.
"""

from __future__ import annotations

import app.rag.reranker as R


class _FakeModel:
    """Stand-in cross-encoder: returns a preset logit per (query, passage)."""

    def __init__(self, logit_for):
        self._logit_for = logit_for  # callable(passage_text) -> float

    def predict(self, pairs):
        return [self._logit_for(passage) for _q, passage in pairs]


def _techs():
    # Bi-encoder order deliberately WRONG: the apt technique is last.
    return [
        {"technique_id": "T1000", "technique_name": "Off Topic A",
         "description": "unrelated credential thing", "similarity_score": 0.61},
        {"technique_id": "T1001", "technique_name": "Off Topic B",
         "description": "unrelated phishing thing", "similarity_score": 0.60},
        {"technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
         "description": "adversaries exploit a public-facing application via sql injection",
         "similarity_score": 0.55},
    ]


def test_rerank_reorders_apt_technique_to_top(monkeypatch):
    # High logit when the passage mentions sql injection, else strongly negative.
    fake = _FakeModel(lambda p: 3.0 if "sql injection" in p else -3.0)
    monkeypatch.setattr(R, "get_reranker", lambda: fake)

    out = R.rerank_techniques("sql injection in web app", _techs(), top_k=3)
    assert out[0]["technique_id"] == "T1190"          # apt one promoted to top
    assert 0.0 <= out[0]["rerank_score"] <= 1.0
    assert out[0]["reranked"] is True


def test_relevance_gate_declines_low_scores(monkeypatch):
    fake = _FakeModel(lambda p: 3.0 if "sql injection" in p else -3.0)
    monkeypatch.setattr(R, "get_reranker", lambda: fake)

    out = R.rerank_techniques("sql injection in web app", _techs(),
                              top_k=3, min_relevance=0.3, apply_gate=True)
    # Only the apt technique clears sigmoid(-3)=0.047 < 0.3 < sigmoid(3)=0.95.
    assert [t["technique_id"] for t in out] == ["T1190"]


def test_gate_can_decline_everything(monkeypatch):
    fake = _FakeModel(lambda p: -5.0)  # nothing is relevant
    monkeypatch.setattr(R, "get_reranker", lambda: fake)

    out = R.rerank_techniques("totally unrelated", _techs(), top_k=3,
                              min_relevance=0.3, apply_gate=True)
    assert out == []                                   # abstain, don't force a citation


def test_apply_gate_false_keeps_topk_in_score_order(monkeypatch):
    fake = _FakeModel(lambda p: 3.0 if "sql injection" in p else -3.0)
    monkeypatch.setattr(R, "get_reranker", lambda: fake)

    out = R.rerank_techniques("sql injection", _techs(), top_k=3, apply_gate=False)
    assert len(out) == 3                               # no gate => keep all top_k
    assert out[0]["technique_id"] == "T1190"           # still ranked best-first
    assert out[0]["rerank_score"] >= out[-1]["rerank_score"]


def test_graceful_fallback_when_model_unavailable(monkeypatch):
    monkeypatch.setattr(R, "get_reranker", lambda: None)
    techs = _techs()
    out = R.rerank_techniques("anything", techs, top_k=2)
    # Falls back to bi-encoder order, unchanged, truncated to top_k.
    assert out == techs[:2]


def test_empty_input_returns_empty(monkeypatch):
    monkeypatch.setattr(R, "get_reranker", lambda: _FakeModel(lambda p: 1.0))
    assert R.rerank_techniques("q", [], top_k=3) == []


def test_sigmoid_bounds():
    assert R._sigmoid(0.0) == 0.5
    assert 0.0 < R._sigmoid(-20.0) < 0.01
    assert 0.99 < R._sigmoid(20.0) < 1.0


class _KeyedModel:
    """Returns a preset logit chosen by a substring found in the passage text."""

    def __init__(self, mapping):
        self.mapping = mapping  # {substring: logit}

    def predict(self, pairs):
        out = []
        for _q, passage in pairs:
            val = -10.0
            for key, logit in self.mapping.items():
                if key in passage:
                    val = logit
                    break
            out.append(val)
        return out


def _tiered_techs():
    return [
        {"technique_id": "TOP", "technique_name": "TOP tier", "description": "d",
         "similarity_score": 0.5},
        {"technique_id": "MID", "technique_name": "MID tier", "description": "d",
         "similarity_score": 0.5},
        {"technique_id": "LOW", "technique_name": "LOW tier", "description": "d",
         "similarity_score": 0.5},
    ]


def test_modest_top_score_is_kept_not_abstained(monkeypatch):
    # Reproduces the CVE-2024-4879 case: best score ~0.22 (below the OLD 0.30
    # threshold) must NOT abstain now — it clears the 0.05 floor and is kept.
    # logits: sigmoid(-1.266)=0.22, sigmoid(-1.735)=0.15, sigmoid(-3.476)=0.03
    fake = _KeyedModel({"TOP": -1.266, "MID": -1.735, "LOW": -3.476})
    monkeypatch.setattr(R, "get_reranker", lambda: fake)

    out = R.rerank_techniques("q", _tiered_techs(), top_k=3)   # default gate
    ids = [t["technique_id"] for t in out]
    assert "TOP" in ids                       # does not abstain on a modest best
    assert "LOW" not in ids                    # tail below rel_ratio*top is dropped
    # rel cutoff = max(0.05, 0.22*0.6=0.132) -> keeps TOP(0.22) and MID(0.15)
    assert ids == ["TOP", "MID"]


def test_abstains_only_when_best_below_floor(monkeypatch):
    fake = _KeyedModel({"TOP": -4.0, "MID": -4.5, "LOW": -5.0})  # sigmoid(-4)=0.018
    monkeypatch.setattr(R, "get_reranker", lambda: fake)
    out = R.rerank_techniques("q", _tiered_techs(), top_k=3)     # floor 0.05
    assert out == []                           # best 0.018 < 0.05 floor -> abstain
