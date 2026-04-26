"""ATT&CK technique retriever using Qdrant semantic search."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.logging import get_logger
from app.ingest.qdrant_loader import (
    ATTCK_COLLECTION,
    get_qdrant_client,
    search_similar,
)

log = get_logger(__name__)


def retrieve_techniques(
    query_text: str,
    *,
    top_k: int = 5,
    min_score: float = 0.3,
) -> List[Dict[str, Any]]:
    """Retrieve the most relevant ATT&CK techniques for a vulnerability.

    Builds a semantic query from the vulnerability description, CWE, and
    product information, then searches the ATT&CK Qdrant collection.

    Args:
        query_text: Combined text (description + CWE + product info).
        top_k: Maximum number of techniques to retrieve.
        min_score: Minimum similarity score threshold.

    Returns:
        List of technique dicts with score, technique_id, name, description.
    """
    results = search_similar(
        query_text=query_text,
        collection=ATTCK_COLLECTION,
        top_k=top_k,
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

    log.info(
        "techniques_retrieved",
        query_len=len(query_text),
        n_retrieved=len(techniques),
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
