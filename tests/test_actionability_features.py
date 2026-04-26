"""Tests for actionability feature builder."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, patch

import pytest

from app.features.actionability import (
    ACTIONABILITY_FEATURES,
    CRITICALITY_SCORE_MAP,
    VEX_STATUS_MAP,
    build_actionability_features,
    _best_confidence,
    _best_vex_status,
    _extract_vuln_products,
)


class TestActionabilityFeatureList:
    """Verify the feature list is complete and correct."""

    def test_feature_count(self):
        assert len(ACTIONABILITY_FEATURES) == 13

    def test_all_features_are_strings(self):
        for f in ACTIONABILITY_FEATURES:
            assert isinstance(f, str)

    def test_layer_a_features(self):
        layer_a = {"affected_product_confirmed", "vex_status_enum", "sbom_match_confidence"}
        assert layer_a.issubset(set(ACTIONABILITY_FEATURES))

    def test_layer_b_features(self):
        layer_b = {"network_reachable_flag", "internet_facing_flag", "code_path_reachable"}
        assert layer_b.issubset(set(ACTIONABILITY_FEATURES))

    def test_layer_d_features(self):
        layer_d = {"has_waf", "has_edr", "has_ips", "has_network_segmentation", "control_coverage_score"}
        assert layer_d.issubset(set(ACTIONABILITY_FEATURES))

    def test_decision_context_features(self):
        context = {"asset_criticality_score", "days_since_disclosure"}
        assert context.issubset(set(ACTIONABILITY_FEATURES))


class TestVexStatusMapping:
    """VEX status enum encoding."""

    def test_not_affected_is_zero(self):
        assert VEX_STATUS_MAP["not_affected"] == 0.0

    def test_affected_is_one(self):
        assert VEX_STATUS_MAP["affected"] == 1.0

    def test_under_investigation_is_between(self):
        val = VEX_STATUS_MAP["under_investigation"]
        assert 0.0 < val < 1.0


class TestCriticalityMapping:
    def test_critical_is_one(self):
        assert CRITICALITY_SCORE_MAP["critical"] == 1.0

    def test_low_is_quarter(self):
        assert CRITICALITY_SCORE_MAP["low"] == 0.25

    def test_all_values_between_0_and_1(self):
        for v in CRITICALITY_SCORE_MAP.values():
            assert 0.0 <= v <= 1.0


class TestHelperFunctions:
    def test_best_confidence_empty(self):
        assert _best_confidence([]) == 0.0

    def test_best_confidence_no_conf_value(self):
        obs = MagicMock()
        obs.confidence = None
        assert _best_confidence([obs]) == 0.8  # default

    def test_best_confidence_with_values(self):
        obs1 = MagicMock()
        obs1.confidence = 0.7
        obs2 = MagicMock()
        obs2.confidence = 0.9
        assert _best_confidence([obs1, obs2]) == 0.9

    def test_best_vex_status_empty(self):
        assert _best_vex_status([]) == -1.0

    def test_best_vex_status_affected(self):
        obs = MagicMock()
        obs.status = "affected"
        assert _best_vex_status([obs]) == 1.0

    def test_extract_vuln_products_dict(self):
        vuln = MagicMock()
        vuln.affected_products_json = [
            {"vendor": "Apache", "product": "HTTP_Server"},
        ]
        result = _extract_vuln_products(vuln)
        assert ("apache", "http_server") in result

    def test_extract_vuln_products_cpe(self):
        vuln = MagicMock()
        vuln.affected_products_json = [
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        ]
        result = _extract_vuln_products(vuln)
        assert ("apache", "http_server") in result

    def test_extract_vuln_products_empty(self):
        vuln = MagicMock()
        vuln.affected_products_json = None
        result = _extract_vuln_products(vuln)
        assert result == set()


class TestBuildActionabilityFeatures:
    """Test the full feature builder with mocked DB."""

    def test_returns_all_features(self):
        asset = MagicMock()
        asset.id = "test-asset-id"
        asset.criticality = "high"
        asset.is_internet_facing = True

        vuln = MagicMock()
        vuln.id = "test-vuln-id"
        vuln.published_at = date(2023, 1, 1)
        vuln.affected_products_json = []

        session = MagicMock()
        asof = date(2024, 1, 1)

        # Provide empty prefetched data
        prefetched = {
            "software_obs": [],
            "vex_obs": [],
            "reachability_obs": [],
            "control_obs": [],
        }

        features = build_actionability_features(
            asset, vuln, session, asof, prefetched=prefetched
        )

        for f in ACTIONABILITY_FEATURES:
            assert f in features, f"Missing feature: {f}"

    def test_all_values_are_numeric(self):
        asset = MagicMock()
        asset.id = "test-asset-id"
        asset.criticality = "medium"
        asset.is_internet_facing = False

        vuln = MagicMock()
        vuln.id = "test-vuln-id"
        vuln.published_at = date(2023, 6, 1)
        vuln.affected_products_json = []

        session = MagicMock()
        asof = date(2024, 6, 1)

        prefetched = {
            "software_obs": [],
            "vex_obs": [],
            "reachability_obs": [],
            "control_obs": [],
        }

        features = build_actionability_features(
            asset, vuln, session, asof, prefetched=prefetched
        )

        for key, val in features.items():
            assert isinstance(val, (int, float)), f"Feature {key} is {type(val)}, expected numeric"

    def test_internet_facing_flag(self):
        asset = MagicMock()
        asset.id = "id"
        asset.criticality = "low"
        asset.is_internet_facing = True

        vuln = MagicMock()
        vuln.id = "vid"
        vuln.published_at = None
        vuln.affected_products_json = []

        prefetched = {
            "software_obs": [],
            "vex_obs": [],
            "reachability_obs": [],
            "control_obs": [],
        }

        features = build_actionability_features(
            asset, vuln, MagicMock(), date(2024, 1, 1), prefetched=prefetched
        )

        assert features["internet_facing_flag"] == 1.0

    def test_days_since_disclosure(self):
        asset = MagicMock()
        asset.id = "id"
        asset.criticality = "medium"
        asset.is_internet_facing = False

        vuln = MagicMock()
        vuln.id = "vid"
        vuln.published_at = date(2024, 1, 1)
        vuln.affected_products_json = []

        prefetched = {
            "software_obs": [],
            "vex_obs": [],
            "reachability_obs": [],
            "control_obs": [],
        }

        features = build_actionability_features(
            asset, vuln, MagicMock(), date(2024, 7, 1), prefetched=prefetched
        )

        assert features["days_since_disclosure"] == 182.0
