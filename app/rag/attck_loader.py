"""ATT&CK STIX corpus loader – parses and stores techniques for RAG retrieval."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from app.core.logging import get_logger
from app.ingest.enrichment_providers import ATTCKProvider
from app.ingest.qdrant_loader import (
    ATTCK_COLLECTION,
    ensure_collections,
    get_qdrant_client,
    upsert_attck_embeddings,
)

log = get_logger(__name__)

# In-memory technique registry for verification
_TECHNIQUE_REGISTRY: Dict[str, Dict[str, Any]] = {}


def load_attck_corpus(source_path: str) -> int:
    """Load ATT&CK STIX bundle, embed techniques, store in Qdrant.

    Also populates the in-memory technique registry for verification.

    Args:
        source_path: Path to enterprise-attack.json STIX bundle.

    Returns:
        Number of techniques loaded.
    """
    provider = ATTCKProvider()
    techniques = provider.fetch(source=source_path)

    # Populate registry
    for tech in techniques:
        _TECHNIQUE_REGISTRY[tech["technique_id"]] = tech

    # Ensure Qdrant collection exists
    client = get_qdrant_client()
    ensure_collections(client)

    # Embed and store
    count = upsert_attck_embeddings(techniques, client=client)
    log.info("attck_corpus_loaded", n_techniques=count)
    return count


def get_technique_registry() -> Dict[str, Dict[str, Any]]:
    """Return the in-memory technique registry."""
    return _TECHNIQUE_REGISTRY


def technique_exists(technique_id: str) -> bool:
    """Check if a technique ID exists in the loaded ATT&CK corpus."""
    return technique_id in _TECHNIQUE_REGISTRY


def get_technique_info(technique_id: str) -> Dict[str, Any]:
    """Get technique details by ID."""
    return _TECHNIQUE_REGISTRY.get(technique_id, {})
