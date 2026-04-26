"""Optional enrichment providers for EPSS, CISA KEV, and MITRE ATT&CK.

These are behind config flags and can be skipped for the happy path.
They add signal_observation rows and vector store entries.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from app.core.logging import get_logger
from app.ingest.base_provider import BaseProvider

log = get_logger(__name__)


# ── EPSS Provider ─────────────────────────────────────────────────────────

class EPSSProvider(BaseProvider):
    """Fetch EPSS scores from the FIRST.org API or local CSV cache."""

    API_URL = "https://api.first.org/data/v1/epss"

    def name(self) -> str:
        return "epss"

    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Fetch EPSS for a list of CVE IDs or a date.

        kwargs:
            cve_ids: List[str] – specific CVEs to query
            asof: str – date (YYYY-MM-DD), used as the observation timestamp
        """
        cve_ids: List[str] = kwargs.get("cve_ids", [])
        asof = kwargs.get("asof", datetime.utcnow().strftime("%Y-%m-%d"))

        if not cve_ids:
            log.warning("epss_no_cve_ids", msg="No CVE IDs provided; skipping EPSS fetch.")
            return []

        results: List[Dict[str, Any]] = []
        # API supports up to 30 CVEs per request
        batch_size = 30
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i : i + batch_size]
            try:
                resp = httpx.get(
                    self.API_URL,
                    params={"cve": ",".join(batch)},
                    timeout=30.0,
                )
                resp.raise_for_status()
                data = resp.json().get("data", [])
                for item in data:
                    results.append({
                        "cve_id": item.get("cve"),
                        "signal_type": "epss",
                        "observed_at": asof,
                        "value_num": float(item.get("epss", 0)),
                        "value_text": str(item.get("percentile", "")),
                        "source": "first.org",
                    })
            except Exception as e:
                log.error("epss_fetch_error", batch=batch, error=str(e))

        log.info("epss_fetched", count=len(results))
        return results


# ── CISA KEV Provider ─────────────────────────────────────────────────────

class KEVProvider(BaseProvider):
    """Fetch CISA Known Exploited Vulnerabilities catalog."""

    CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def name(self) -> str:
        return "kev"

    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Download KEV catalog and return signal dicts."""
        asof = kwargs.get("asof", datetime.utcnow().strftime("%Y-%m-%d"))
        try:
            resp = httpx.get(self.CATALOG_URL, timeout=60.0)
            resp.raise_for_status()
            catalog = resp.json()
        except Exception as e:
            log.error("kev_fetch_error", error=str(e))
            return []

        vulns = catalog.get("vulnerabilities", [])
        results: List[Dict[str, Any]] = []
        for v in vulns:
            results.append({
                "cve_id": v.get("cveID"),
                "signal_type": "kev",
                "observed_at": v.get("dateAdded", asof),
                "value_bool": True,
                "value_text": v.get("shortDescription", ""),
                "source": "cisa_kev",
                "evidence_ref": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            })

        log.info("kev_fetched", count=len(results))
        return results


# ── ATT&CK STIX Provider ─────────────────────────────────────────────────

class ATTCKProvider(BaseProvider):
    """Load MITRE ATT&CK Enterprise techniques from a local STIX 2.1 JSON bundle."""

    def name(self) -> str:
        return "attck"

    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Parse ATT&CK STIX bundle and return technique dicts.

        kwargs:
            source: str – path to enterprise-attack.json
        """
        source = kwargs.get("source")
        if not source:
            raise ValueError("ATTCKProvider requires --source <path> to STIX JSON.")

        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(f"ATT&CK file not found: {path}")

        log.info("loading_attck_stix", path=str(path))
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        techniques: List[Dict[str, Any]] = []

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            # Skip revoked / deprecated
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            if not technique_id:
                continue

            # Extract tactic names from kill_chain_phases
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name", ""))

            techniques.append({
                "technique_id": technique_id,
                "technique_name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "stix_id": obj.get("id", ""),
                "object_ref": obj.get("id", ""),
            })

        log.info("attck_techniques_loaded", count=len(techniques))
        return techniques
