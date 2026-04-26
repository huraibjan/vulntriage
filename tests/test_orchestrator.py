"""Unit tests for ingestion orchestrator logic."""

from __future__ import annotations

from datetime import datetime

import pytest

from app.ingest.vulndb_provider import VulnDBProvider


class TestVulnDBProviderParsing:
    """Test VulnDB provider record normalization."""

    def _sample_record(self, **overrides) -> dict:
        rec = {
            "id": 12345,
            "title": "Test Vulnerability",
            "description": "A test vulnerability for unit testing.",
            "published": "2024-06-15T00:00:00Z",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cvss_version": "3.1",
            "cve_id": "CVE-2024-0001",
            "cwe_ids": ["CWE-79"],
            "references": [{"url": "https://example.com", "source": "cve"}],
            "products": [{"vendor": "Acme", "product": "Widget"}],
        }
        rec.update(overrides)
        return rec

    def test_dedupe_key_uses_vuldb_id(self):
        provider = VulnDBProvider(input_path="dummy.json")
        rec = self._sample_record()
        key = provider.dedupe_key(rec)
        assert "12345" in str(key)

    def test_provider_name(self):
        provider = VulnDBProvider(input_path="dummy.json")
        assert provider.name() == "vulndb"


class TestIngestionDedup:
    """Test deduplication logic (pure function tests, no DB)."""

    def test_unique_cve_ids(self):
        """Records with different CVE IDs should produce different dedupe keys."""
        provider = VulnDBProvider(input_path="dummy.json")
        rec1 = {"id": 1, "cve_id": "CVE-2024-0001"}
        rec2 = {"id": 2, "cve_id": "CVE-2024-0002"}
        assert provider.dedupe_key(rec1) != provider.dedupe_key(rec2)

    def test_same_id_same_key(self):
        """Same vulndb_id should produce same dedupe key."""
        provider = VulnDBProvider(input_path="dummy.json")
        rec1 = {"id": 42, "cve_id": "CVE-2024-0001"}
        rec2 = {"id": 42, "cve_id": "CVE-2024-0001"}
        assert provider.dedupe_key(rec1) == provider.dedupe_key(rec2)
