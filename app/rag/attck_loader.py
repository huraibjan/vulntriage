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


def _default_bundle_path() -> Path | None:
    """Locate the ATT&CK STIX bundle, preferring the full corpus."""
    from app.core.settings import get_settings

    attck_dir = Path(get_settings().data_dir) / "attck"
    for name in ("enterprise-attack-full.json", "enterprise-attack.json"):
        path = attck_dir / name
        if path.exists():
            return path
    return None


def ensure_registry() -> int:
    """Lazily populate the in-memory registry from the STIX bundle.

    Unlike load_attck_corpus(), this does NOT touch Qdrant — it only parses
    the bundle so that technique-ID verification works in any process
    (API, CLI, experiments) without an explicit corpus load.
    """
    if _TECHNIQUE_REGISTRY:
        return len(_TECHNIQUE_REGISTRY)
    path = _default_bundle_path()
    if path is None:
        log.warning("attck_bundle_missing", msg="No ATT&CK STIX bundle found")
        return 0
    provider = ATTCKProvider()
    for tech in provider.fetch(source=str(path)):
        _TECHNIQUE_REGISTRY[tech["technique_id"]] = tech
    log.info("attck_registry_loaded", n_techniques=len(_TECHNIQUE_REGISTRY),
             source=path.name)
    return len(_TECHNIQUE_REGISTRY)


def get_technique_registry() -> Dict[str, Dict[str, Any]]:
    """Return the in-memory technique registry (lazily loaded)."""
    ensure_registry()
    return _TECHNIQUE_REGISTRY


def technique_exists(technique_id: str) -> bool:
    """Check if a technique ID exists in the loaded ATT&CK corpus."""
    ensure_registry()
    return technique_id in _TECHNIQUE_REGISTRY


def get_technique_info(technique_id: str) -> Dict[str, Any]:
    """Get technique details by ID."""
    ensure_registry()
    return _TECHNIQUE_REGISTRY.get(technique_id, {})
