"""Qdrant vector store operations – embedding, upserting, searching."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from qdrant_client import QdrantClient
from qdrant_client.http.models import (
    Distance,
    PointStruct,
    VectorParams,
    Filter,
    FieldCondition,
    MatchValue,
)

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)

VULN_COLLECTION = "vuln_text"
ATTCK_COLLECTION = "attck_text"


def get_qdrant_client() -> QdrantClient:
    """Create and return a Qdrant client."""
    settings = get_settings()
    kwargs: Dict[str, Any] = {
        "host": settings.qdrant_host,
        "port": settings.qdrant_http_port,
    }
    if settings.qdrant_api_key:
        kwargs["api_key"] = settings.qdrant_api_key
    return QdrantClient(**kwargs)


def ensure_collections(client: Optional[QdrantClient] = None) -> None:
    """Create Qdrant collections if they don't exist."""
    settings = get_settings()
    c = client or get_qdrant_client()

    for name in [VULN_COLLECTION, ATTCK_COLLECTION]:
        existing = [col.name for col in c.get_collections().collections]
        if name not in existing:
            c.create_collection(
                collection_name=name,
                vectors_config=VectorParams(
                    size=settings.embedding_dim,
                    distance=Distance.COSINE,
                ),
            )
            log.info("qdrant_collection_created", name=name)


def get_embedding_model():
    """Lazily load the sentence-transformer model."""
    from sentence_transformers import SentenceTransformer
    settings = get_settings()
    return SentenceTransformer(settings.embedding_model)


def embed_texts(texts: List[str], model=None) -> List[List[float]]:
    """Embed a list of texts using sentence-transformers."""
    if model is None:
        model = get_embedding_model()
    embeddings = model.encode(texts, show_progress_bar=False, convert_to_numpy=True)
    return embeddings.tolist()


def upsert_vulnerability_embeddings(
    records: List[Dict[str, Any]],
    client: Optional[QdrantClient] = None,
    model=None,
) -> int:
    """Embed vulnerability descriptions and upsert into Qdrant.

    Each record must have: id (str/uuid), description (str).
    Optional payload: cve_id, vuldb_id, published_at, cvss_base_score.
    """
    c = client or get_qdrant_client()
    if model is None:
        model = get_embedding_model()

    texts = [r.get("description", "") or "" for r in records]
    if not texts:
        return 0

    vectors = embed_texts(texts, model=model)

    points = []
    for rec, vec in zip(records, vectors):
        point_id = str(rec.get("id", uuid4()))
        points.append(
            PointStruct(
                id=point_id,
                vector=vec,
                payload={
                    "vuln_id": str(rec.get("id", "")),
                    "cve_id": rec.get("cve_id", ""),
                    "vuldb_id": rec.get("vuldb_id", ""),
                    "description": rec.get("description", "")[:500],
                    "published_at": str(rec.get("published_at", "")),
                    "cvss_base_score": rec.get("cvss_base_score"),
                },
            )
        )

    c.upsert(collection_name=VULN_COLLECTION, points=points)
    log.info("vuln_embeddings_upserted", count=len(points))
    return len(points)


def upsert_attck_embeddings(
    techniques: List[Dict[str, Any]],
    client: Optional[QdrantClient] = None,
    model=None,
) -> int:
    """Embed ATT&CK technique descriptions and upsert into Qdrant."""
    c = client or get_qdrant_client()
    if model is None:
        model = get_embedding_model()

    texts = [t.get("description", "") for t in techniques]
    if not texts:
        return 0

    vectors = embed_texts(texts, model=model)

    points = []
    for tech, vec in zip(techniques, vectors):
        # Use UUID for point ID (Qdrant requires UUID or int, not strings like "T1190")
        point_id = str(uuid4())
        points.append(
            PointStruct(
                id=point_id,
                vector=vec,
                payload={
                    "technique_id": tech["technique_id"],
                    "technique_name": tech.get("technique_name", ""),
                    "description": tech.get("description", "")[:1000],
                    "tactics": tech.get("tactics", []),
                    "stix_id": tech.get("stix_id", ""),
                },
            )
        )

    c.upsert(collection_name=ATTCK_COLLECTION, points=points)
    log.info("attck_embeddings_upserted", count=len(points))
    return len(points)


def search_similar(
    query_text: str,
    collection: str = VULN_COLLECTION,
    top_k: int = 5,
    client: Optional[QdrantClient] = None,
    model=None,
    filters: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Semantic search against a Qdrant collection."""
    c = client or get_qdrant_client()
    if model is None:
        model = get_embedding_model()

    query_vec = embed_texts([query_text], model=model)[0]

    qdrant_filter = None
    if filters:
        conditions = []
        for key, val in filters.items():
            conditions.append(FieldCondition(key=key, match=MatchValue(value=val)))
        qdrant_filter = Filter(must=conditions)

    results = c.query_points(
        collection_name=collection,
        query=query_vec,
        limit=top_k,
        query_filter=qdrant_filter,
    )

    return [
        {
            "id": str(hit.id),
            "score": hit.score,
            "payload": hit.payload or {},
        }
        for hit in results.points
    ]
