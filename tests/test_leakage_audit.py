"""Tests for the leakage audit module."""

from __future__ import annotations

from datetime import date

import numpy as np
import pandas as pd
import pytest

from app.features.leakage_audit import (
    _check_entity_leakage,
    _check_suspicious_correlations,
    _check_temporal_leakage,
    audit_feature_set,
)


class TestTemporalLeakage:
    """Test temporal leakage detection."""

    def test_no_leakage(self):
        df = pd.DataFrame({
            "cve_id": ["CVE-2023-001", "CVE-2023-002"],
            "published_at": ["2023-01-01", "2023-06-01"],
            "cvss_base_score": [7.5, 5.0],
        })
        result = _check_temporal_leakage(df, date(2024, 1, 1))
        assert result["pass"] is True
        assert result["future_samples"] == 0

    def test_temporal_leakage_detected(self):
        df = pd.DataFrame({
            "cve_id": ["CVE-2023-001", "CVE-2025-001"],
            "published_at": ["2023-01-01", "2025-06-01"],
            "cvss_base_score": [7.5, 9.0],
        })
        result = _check_temporal_leakage(df, date(2024, 1, 1))
        assert result["pass"] is False
        assert result["future_samples"] == 1

    def test_no_published_at_column(self):
        df = pd.DataFrame({
            "cve_id": ["CVE-2023-001"],
            "cvss_base_score": [7.5],
        })
        result = _check_temporal_leakage(df, date(2024, 1, 1))
        assert result["pass"] is True
        assert "note" in result


class TestEntityLeakage:
    """Test entity leakage detection."""

    def test_no_overlap(self):
        train = {"a", "b", "c"}
        test = {"d", "e", "f"}
        result = _check_entity_leakage(train, test)
        assert result["pass"] is True
        assert result["overlap_count"] == 0

    def test_overlap_detected(self):
        train = {"a", "b", "c"}
        test = {"c", "d", "e"}
        result = _check_entity_leakage(train, test)
        assert result["pass"] is False
        assert result["overlap_count"] == 1

    def test_full_overlap(self):
        ids = {"a", "b", "c"}
        result = _check_entity_leakage(ids, ids)
        assert result["pass"] is False
        assert result["overlap_count"] == 3


class TestSuspiciousCorrelations:
    """Test suspicious correlation detection."""

    def test_no_suspicious_features(self):
        np.random.seed(42)
        n = 100
        features_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "feat_a": np.random.randn(n),
            "feat_b": np.random.randn(n),
        })
        labels_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "exploited": np.random.randint(0, 2, n),
        })
        result = _check_suspicious_correlations(features_df, labels_df, "exploited")
        assert result["pass"] is True

    def test_perfect_correlation_detected(self):
        n = 100
        features_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "leaked_feat": list(range(n)),
        })
        labels_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "exploited": list(range(n)),
        })
        result = _check_suspicious_correlations(
            features_df, labels_df, "exploited", threshold=0.95
        )
        assert result["pass"] is False
        assert len(result["suspicious_features"]) >= 1


class TestFullAudit:
    """Test the full audit pipeline."""

    def test_clean_audit_passes(self):
        np.random.seed(42)
        n = 50
        features_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "published_at": ["2023-06-01"] * n,
            "cvss_base_score": np.random.uniform(0, 10, n),
            "epss_score": np.random.uniform(0, 1, n),
        })
        labels_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "exploited": np.random.randint(0, 2, n),
        })

        report = audit_feature_set(
            features_df, labels_df, date(2024, 1, 1),
        )
        assert report["overall_pass"] is True
        assert report["summary"]["verdict"] == "PASS"

    def test_audit_with_violations(self):
        n = 50
        features_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "published_at": ["2025-06-01"] * n,  # future dates
            "cvss_base_score": np.random.uniform(0, 10, n),
        })
        labels_df = pd.DataFrame({
            "vuln_id": [f"v{i}" for i in range(n)],
            "exploited": np.random.randint(0, 2, n),
        })

        report = audit_feature_set(
            features_df, labels_df, date(2024, 1, 1),
        )
        assert report["overall_pass"] is False
        assert len(report["violations"]) > 0
