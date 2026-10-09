"""ATT&CK technique retriever using Qdrant semantic search."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.logging import get_logger
from app.ingest.qdrant_loader import (
    ATTCK_COLLECTION,
    get_qdrant_client,
    search_similar,
)
from app.rag.reranker import DEFAULT_MIN_RELEVANCE, rerank_techniques

log = get_logger(__name__)

# When re-ranking is enabled, pull a wider bi-encoder candidate pool so the
# cross-encoder has enough to choose from (retrieve-then-rerank).
RERANK_CANDIDATE_POOL = 15


def retrieve_techniques(
    query_text: str,
    *,
    top_k: int = 5,
    min_score: float = 0.3,
    rerank: bool = False,
    candidate_pool: int | None = None,
    min_relevance: float = DEFAULT_MIN_RELEVANCE,
    apply_gate: bool = True,
) -> List[Dict[str, Any]]:
    """Retrieve the most relevant ATT&CK techniques for a vulnerability.

    Builds a semantic query from the vulnerability description, CWE, and
    product information, then searches the ATT&CK Qdrant collection. When
    ``rerank`` is set, a wider bi-encoder pool is retrieved and re-scored by a
    cross-encoder with a CRAG-style relevance gate (see ``app.rag.reranker``).

    Args:
        query_text: Combined text (description + CWE + product info).
        top_k: Maximum number of techniques to return.
        min_score: Minimum bi-encoder similarity threshold.
        rerank: Enable cross-encoder re-ranking + relevance gate.
        candidate_pool: Bi-encoder candidates to fetch before re-ranking
            (defaults to RERANK_CANDIDATE_POOL). Ignored when rerank is False.
        min_relevance: CRAG gate threshold for re-ranked relevance in [0,1].
        apply_gate: When False, skip the relevance gate (rank-only ablation).

    Returns:
        List of technique dicts with score, technique_id, name, description
        (and, when re-ranked, ``rerank_score``).
    """
    fetch_k = (candidate_pool or RERANK_CANDIDATE_POOL) if rerank else top_k
    results = search_similar(
        query_text=query_text,
        collection=ATTCK_COLLECTION,
        top_k=fetch_k,
    )

    # Filter by minimum score and structure output
    techniques = []
    for hit in results:
        if hit["score"] < min_score:
            continue

        payload = hit.get("payload", {})
        techniques.append({
            "technique_id": payload.get("technique_id", ""),
            "technique_name": payload.get("technique_name", ""),
            "description": payload.get("description", ""),
            "tactics": payload.get("tactics", []),
            "stix_id": payload.get("stix_id", ""),
            "similarity_score": hit["score"],
        })

    if rerank:
        techniques = rerank_techniques(
            query_text, techniques,
            top_k=top_k, min_relevance=min_relevance, apply_gate=apply_gate,
        )
    else:
        techniques = techniques[:top_k]

    log.info(
        "techniques_retrieved",
        query_len=len(query_text),
        n_retrieved=len(techniques),
        reranked=rerank,
        top_score=techniques[0]["similarity_score"] if techniques else 0,
    )
    return techniques


def build_query_text(
    description: str,
    cwe_ids: Optional[List[str]] = None,
    products: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Build a rich query text for technique retrieval.

    Combines vulnerability description with CWE and product context
    to improve retrieval accuracy.
    """
    parts = [description]

    if cwe_ids:
        cwe_text = "Weakness types: " + ", ".join(cwe_ids)
        parts.append(cwe_text)

    if products:
        product_names = [
            f"{p.get('vendor', '')} {p.get('product', '')}".strip()
            for p in products
        ]
        if product_names:
            parts.append("Affected software: " + ", ".join(product_names))

    return " ".join(parts)
