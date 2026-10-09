"""Cross-encoder re-ranking with a CRAG-style relevance gate for ATT&CK retrieval.

The base retriever (``app.rag.retriever``) uses an SBERT **bi-encoder**: the CVE
text and every ATT&CK technique are embedded independently and compared by cosine
similarity. Bi-encoders are fast but flatten fine-grained semantics, so a
technique that is *lexically* close to the CVE but *operationally* inappropriate
can still rank highly — the retrieved-but-inapt failure mode that drives brief
over-rationalisation.

This module adds the standard fix: retrieve a wider candidate pool with the
bi-encoder, then re-score each (CVE, technique) pair with a **cross-encoder**
that reads both texts jointly, and keep the best few. A CRAG-inspired relevance
gate then *declines* candidates whose re-rank confidence is too low rather than
forcing a citation — so a CVE with no genuinely relevant technique yields no
mapping instead of a rationalised wrong one.

References:
  - Reimers & Gurevych, "Sentence-BERT" (EMNLP 2019) — bi- vs cross-encoders.
  - Yan et al., "Corrective Retrieval Augmented Generation" (arXiv:2401.15884) —
    retrieval evaluator that grades confidence and triggers corrective actions.

The cross-encoder is optional: if ``sentence-transformers`` or the model weights
are unavailable, re-ranking degrades gracefully to the bi-encoder order so the
pipeline never hard-fails.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from app.core.logging import get_logger

log = get_logger(__name__)

# A small, widely-used passage re-ranker. Downloaded on first use (~80 MB) and
# cached locally by sentence-transformers thereafter.
RERANKER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"

# CRAG relevance gate (relative-with-floor). ms-marco cross-encoders are trained
# on short web queries, so absolute scores on long CVE->ATT&CK pairs run low and
# a fixed high threshold declines everything. Instead we abstain only when even
# the BEST candidate is below an absolute garbage floor, and otherwise keep the
# top candidate plus any within a fraction of its score (dropping the long tail).
DEFAULT_MIN_RELEVANCE = 0.05   # absolute floor: best < this => abstain entirely
DEFAULT_REL_RATIO = 0.60       # keep candidates scoring >= rel_ratio * top score

# The cross-encoder truncates (query + passage) to 512 tokens; a 2,700-char CVE
# query would crowd out the technique text and deflate every score. Cap the query
# so the technique description still fits in the budget.
QUERY_MAX_CHARS = 900
PASSAGE_MAX_CHARS = 500

_reranker = None            # lazy CrossEncoder singleton
_reranker_failed = False    # remember a load failure to avoid retry storms


def get_reranker():
    """Lazily load the cross-encoder singleton, or return None if unavailable."""
    global _reranker, _reranker_failed
    if _reranker is not None or _reranker_failed:
        return _reranker
    try:
        from sentence_transformers import CrossEncoder
        _reranker = CrossEncoder(RERANKER_MODEL)
        log.info("reranker_loaded", model=RERANKER_MODEL)
    except Exception as e:  # noqa: BLE001 - any failure => graceful fallback
        _reranker_failed = True
        log.warning("reranker_unavailable", error=str(e), model=RERANKER_MODEL)
    return _reranker


def _sigmoid(x: float) -> float:
    # ms-marco cross-encoders emit an unbounded relevance logit; squash to [0,1].
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    ex = math.exp(x)
    return ex / (1.0 + ex)


def _technique_text(t: Dict[str, Any]) -> str:
    """The passage a technique is judged on: its name plus description."""
    name = t.get("technique_name", "")
    desc = (t.get("description", "") or "")[:PASSAGE_MAX_CHARS]
    return f"{name}. {desc}".strip()


def rerank_techniques(
    query_text: str,
    techniques: List[Dict[str, Any]],
    *,
    top_k: int = 3,
    min_relevance: float = DEFAULT_MIN_RELEVANCE,
    rel_ratio: float = DEFAULT_REL_RATIO,
    apply_gate: bool = True,
) -> List[Dict[str, Any]]:
    """Re-rank bi-encoder candidates with a cross-encoder and apply the gate.

    The gate is *relative with an absolute floor*: it abstains (returns nothing)
    only when even the best candidate scores below ``min_relevance``; otherwise
    it keeps the top candidate plus any scoring within ``rel_ratio`` of the top,
    dropping the clearly-worse tail. This filters retrieved-but-inapt techniques
    without over-declining when a reasonable best match exists.

    Args:
        query_text: The CVE query (truncated to QUERY_MAX_CHARS for scoring so
            the technique text still fits the cross-encoder's token budget).
        techniques: Candidate technique dicts from ``retrieve_techniques``.
        top_k: Maximum techniques to return after re-ranking.
        min_relevance: Absolute floor in [0,1]; if the best candidate is below
            it, abstain. Ignored when ``apply_gate`` is False.
        rel_ratio: Keep candidates scoring >= rel_ratio * top score.
        apply_gate: If False, keep the top_k re-ranked candidates without the
            relevance gate (isolates the ranking effect in ablations).

    Returns:
        Re-ordered technique dicts (subset of the input), each annotated with
        ``rerank_score`` (calibrated relevance in [0,1]) and ``reranked``=True.
        If the cross-encoder is unavailable, returns the first ``top_k`` inputs
        unchanged (bi-encoder order) so the caller behaviour is preserved.
    """
    if not techniques:
        return []

    model = get_reranker()
    if model is None:
        # Graceful fallback: preserve bi-encoder behaviour exactly.
        return techniques[:top_k]

    q = (query_text or "")[:QUERY_MAX_CHARS]
    pairs = [(q, _technique_text(t)) for t in techniques]
    try:
        raw_scores = model.predict(pairs)
    except Exception as e:  # noqa: BLE001
        log.warning("rerank_predict_failed", error=str(e))
        return techniques[:top_k]

    scored: List[Dict[str, Any]] = []
    for t, raw in zip(techniques, raw_scores):
        rel = _sigmoid(float(raw))
        item = dict(t)
        item["rerank_score"] = round(rel, 4)
        item["reranked"] = True
        scored.append(item)

    scored.sort(key=lambda x: x["rerank_score"], reverse=True)
    top = scored[0]["rerank_score"]

    if not apply_gate:
        kept = scored
    elif top < min_relevance:
        kept = []                                   # nothing is relevant → abstain
    else:
        cutoff = max(min_relevance, top * rel_ratio)
        kept = [t for t in scored if t["rerank_score"] >= cutoff]

    log.info(
        "techniques_reranked",
        n_in=len(techniques),
        n_kept=len(kept[:top_k]),
        gated=apply_gate,
        top_rerank=top,
    )
    return kept[:top_k]
