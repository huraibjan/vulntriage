"""Abstract base provider for vulnerability data ingestion."""

from __future__ import annotations

import abc
from typing import Any, Dict, List


class BaseProvider(abc.ABC):
    """Interface that every data provider must implement.

    Providers are responsible for:
    1. Loading raw data from their source (file, API, feed).
    2. Normalising records into a common dict schema understood by the
       ingestion orchestrator.
    3. Providing deduplication keys so the orchestrator can upsert.
    """

    @abc.abstractmethod
    def name(self) -> str:
        """Short identifier, e.g. 'vulndb', 'nvd', 'epss'."""
        ...

    @abc.abstractmethod
    def fetch(self, **kwargs: Any) -> List[Dict[str, Any]]:
        """Return a list of normalised records.

        Each record is a dict with at minimum:
            - cve_id  (str | None)
            - vuldb_id (str | None)
            - published_at (str | None)  ISO-8601
            - description (str)

        Extra keys are provider-specific and stored in raw_source_json.
        """
        ...

    def dedupe_key(self, record: Dict[str, Any]) -> str:
        """Return a string key used to detect duplicates.

        Default: prefer cve_id, fall back to vuldb_id.
        """
        return record.get("cve_id") or record.get("vuldb_id") or ""
