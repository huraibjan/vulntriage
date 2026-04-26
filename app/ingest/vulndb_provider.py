"""VulnDB provider – loads vulnerability data from local JSON export.

This is the *primary* data source. It supports:
  - Offline ingestion from a local JSON file (for CI / demos).
  - A placeholder for live API ingestion (requires commercial API key).

The local JSON file should be an array of objects, each representing one
vulnerability record as exported from VulnDB.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.logging import get_logger
from app.ingest.base_provider import BaseProvider

log = get_logger(__name__)


class VulnDBProvider(BaseProvider):
    """Load vulnerabilities from a VulnDB JSON export file."""

    def __init__(self, input_path: Optional[str] = None) -> None:
        self._input_path = input_path

    def name(self) -> str:
        return "vulndb"

    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        input_path = kwargs.get("input") or self._input_path
        if not input_path:
            raise ValueError("VulnDBProvider requires --input <path> to a JSON file.")

        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"VulnDB file not found: {path}")

        log.info("loading_vulndb_file", path=str(path))
        with open(path, "r", encoding="utf-8") as f:
            raw_records = json.load(f)

        if not isinstance(raw_records, list):
            raw_records = [raw_records]

        normalised: List[Dict[str, Any]] = []
        for rec in raw_records:
            normalised.append(self._normalise(rec))

        log.info("vulndb_records_loaded", count=len(normalised))
        return normalised

    def _normalise(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        """Map VulnDB fields to our canonical schema."""
        # Extract CVSS info
        cvss = rec.get("cvss", {}) or {}
        cvss3 = rec.get("cvss3", {}) or cvss

        # Parse published date
        published_raw = rec.get("published_at") or rec.get("publish_date") or rec.get("date_published")
        published_at = None
        if published_raw:
            try:
                published_at = datetime.fromisoformat(str(published_raw).replace("Z", "+00:00"))
            except (ValueError, TypeError):
                published_at = None

        # Extract CWE
        cwe_raw = rec.get("cwe_ids") or rec.get("cwe") or []
        if isinstance(cwe_raw, str):
            cwe_ids = [cwe_raw]
        elif isinstance(cwe_raw, list):
            cwe_ids = [c.get("cwe_id", c) if isinstance(c, dict) else str(c) for c in cwe_raw]
        else:
            cwe_ids = []

        # Extract references
        refs = rec.get("references") or rec.get("ext_references") or []
        if isinstance(refs, list):
            references = [
                {"url": r.get("url", r) if isinstance(r, dict) else str(r),
                 "source": r.get("source", "unknown") if isinstance(r, dict) else "unknown"}
                for r in refs
            ]
        else:
            references = []

        # Extract affected products
        products = rec.get("affected_products") or rec.get("products") or []

        # Extract exploit signals (metadata only – NO exploit code)
        signals = rec.get("signals", {}) or {}

        return {
            "source": "vulndb",
            "cve_id": rec.get("cve_id") or rec.get("cve"),
            "vuldb_id": str(rec.get("vuldb_id") or rec.get("id", "")),
            "published_at": published_at,
            "last_modified_at": None,
            "title": rec.get("title") or rec.get("name"),
            "description": rec.get("description") or rec.get("summary") or "",
            "cvss_version": cvss3.get("version", "3.1"),
            "cvss_vector": cvss3.get("vector") or cvss3.get("vectorString"),
            "cvss_base_score": _safe_float(cvss3.get("base_score") or cvss3.get("baseScore")),
            "cwe_ids": cwe_ids,
            "references_json": references,
            "affected_products_json": products,
            "raw_source_json": rec,
            # Signal metadata (stored in signal_observation table, not here)
            "_signals": {
                "epss_score": _safe_float(rec.get("epss_score") or signals.get("epss_score")),
                "kev_flag": bool(rec.get("kev_flag") or signals.get("kev_flag", False)),
                "poc_exploitdb": bool(rec.get("poc_exploitdb") or signals.get("poc_exploitdb", False)),
                "metasploit_module": bool(rec.get("metasploit_module") or signals.get("metasploit_module", False)),
            },
        }


def _safe_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None
