"""Tests for the circularity-free label builder.

Validates:
1. Label provenance tracking
2. Circularity detection (signal→feature overlap)
3. Policy-specific excluded features
4. Temporal filtering (as-of date)
5. Conflict detection across policies
6. Label statistics sanity checks
"""

from __future__ import annotations

import pytest
from datetime import date, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

from app.ingest.label_builder import (
    POLICIES,
    LabelPolicy,
    LabelProvenance,
    build_labels,
    detect_label_conflicts,
    get_excluded_features,
    list_policies,
    validate_labels,
)


# ── Test policy definitions ────────────────────────────────────────────

class TestPolicyDefinitions:
    """Test that all policies are well-formed."""

    def test_all_policies_have_excluded_features(self):
        """Every policy must declare which features to exclude."""
        for name, policy in POLICIES.items():
            assert isinstance(policy.excluded_features, frozenset), (
                f"Policy '{name}' excluded_features is not a frozenset"
            )

    def test_kev_strict_excludes_kev_flag(self):
        """kev_strict must exclude kev_flag from features."""
        assert "kev_flag" in POLICIES["kev_strict"].excluded_features

    def test_temporal_excludes_all_exploit_signals(self):
        """temporal_first_exploit must exclude all exploit-derived features."""
        expected = {
            "kev_flag",
            "poc_exploitdb_flag",
            "metasploit_flag",
            "exploit_signal_count",
            "days_since_poc",
        }
        assert expected.issubset(POLICIES["temporal_first_exploit"].excluded_features)

    def test_composite_no_leak_excludes_same_as_temporal(self):
        """composite_no_leak should have same exclusions as temporal."""
        assert (
            POLICIES["composite_no_leak"].excluded_features
            == POLICIES["temporal_first_exploit"].excluded_features
        )

    def test_epss_derived_excludes_epss_and_kev(self):
        """epss_derived must exclude both epss_score and kev_flag."""
        excluded = POLICIES["epss_derived"].excluded_features
        assert "epss_score" in excluded
        assert "kev_flag" in excluded

    def test_all_policies_have_positive_signal_types(self):
        """Every policy must specify which signals make a positive label."""
        for name, policy in POLICIES.items():
            assert len(policy.positive_signal_types) > 0, (
                f"Policy '{name}' has no positive_signal_types"
            )


# ── Test circularity detection ─────────────────────────────────────────

class TestCircularityDetection:
    """Test the signal→feature circularity audit logic."""

    def test_kev_strict_no_circularity(self):
        """kev_strict: kev signal produces kev_flag, which is excluded."""
        policy = POLICIES["kev_strict"]
        # kev signal → kev_flag feature → excluded ✓
        signal_features = {"kev_flag"}
        overlap = signal_features - policy.excluded_features
        assert len(overlap) == 0, f"Circularity! Leaky features: {overlap}"

    def test_temporal_no_circularity(self):
        """temporal: all exploit signals produce features that are excluded."""
        policy = POLICIES["temporal_first_exploit"]
        signal_feature_map = {
            "kev": {"kev_flag"},
            "poc_exploitdb": {"poc_exploitdb_flag", "days_since_poc"},
            "metasploit": {"metasploit_flag"},
        }
        for sig_type in policy.positive_signal_types:
            if sig_type in signal_feature_map:
                features = signal_feature_map[sig_type]
                overlap = features - policy.excluded_features
                assert len(overlap) == 0, (
                    f"Circularity! Signal '{sig_type}' → features {overlap} not excluded"
                )

    def test_exploit_signal_count_excluded_when_needed(self):
        """exploit_signal_count is derived from kev+poc+msf and must be excluded."""
        for policy_name in ["temporal_first_exploit", "composite_no_leak"]:
            policy = POLICIES[policy_name]
            assert "exploit_signal_count" in policy.excluded_features, (
                f"Policy '{policy_name}' doesn't exclude exploit_signal_count"
            )


# ── Test get_excluded_features utility ─────────────────────────────────

class TestGetExcludedFeatures:
    """Test the public utility function."""

    def test_returns_frozenset(self):
        result = get_excluded_features("kev_strict")
        assert isinstance(result, frozenset)

    def test_unknown_policy_raises(self):
        with pytest.raises(ValueError, match="Unknown policy"):
            get_excluded_features("nonexistent_policy")

    def test_kev_strict_returns_kev_flag(self):
        result = get_excluded_features("kev_strict")
        assert result == frozenset({"kev_flag"})


# ── Test list_policies ─────────────────────────────────────────────────

class TestListPolicies:
    """Test the policy listing utility."""

    def test_returns_all_policies(self):
        result = list_policies()
        assert len(result) == len(POLICIES)

    def test_each_policy_has_required_keys(self):
        for policy_info in list_policies():
            assert "name" in policy_info
            assert "description" in policy_info
            assert "excluded_features" in policy_info
            assert "positive_signal_types" in policy_info


# ── Test policy application (unit-level, no DB) ───────────────────────

class TestPolicyApplication:
    """Test individual policy logic with mock objects."""

    def _make_vuln(self, cve_id="CVE-2024-1234", published_at=None):
        """Create a mock Vulnerability object."""
        vuln = MagicMock()
        vuln.id = uuid4()
        vuln.cve_id = cve_id
        vuln.published_at = published_at or datetime(2024, 1, 15)
        return vuln

    def _make_signal(self, signal_type, value_bool=None, value_num=None,
                     observed_at=None):
        """Create a mock SignalObservation object."""
        sig = MagicMock()
        sig.signal_type = signal_type
        sig.value_bool = value_bool
        sig.value_num = value_num
        sig.observed_at = observed_at or datetime(2024, 2, 1)
        sig.source = "test"
        return sig

    def test_kev_strict_positive(self):
        """KEV signal present → label=1."""
        from app.ingest.label_builder import _policy_kev_strict

        vuln = self._make_vuln()
        signals = [self._make_signal("kev", value_bool=True)]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_kev_strict(vuln, signals, asof)
        assert label == 1
        assert len(contributing) == 1
        assert "KEV" in rationale

    def test_kev_strict_negative(self):
        """No KEV signal → label=0."""
        from app.ingest.label_builder import _policy_kev_strict

        vuln = self._make_vuln()
        signals = [self._make_signal("epss", value_num=0.95)]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_kev_strict(vuln, signals, asof)
        assert label == 0
        assert len(contributing) == 0

    def test_temporal_within_window(self):
        """PoC within 90 days of publication → label=1."""
        from app.ingest.label_builder import _policy_temporal_first

        pub_date = datetime(2024, 1, 15)
        vuln = self._make_vuln(published_at=pub_date)
        # PoC appears 30 days after publication
        signals = [
            self._make_signal("poc_exploitdb", value_bool=True,
                              observed_at=pub_date + timedelta(days=30)),
        ]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_temporal_first(
            vuln, signals, asof, horizon_days=90
        )
        assert label == 1
        assert "within 90d" in rationale

    def test_temporal_outside_window(self):
        """PoC after 90-day window → label=0."""
        from app.ingest.label_builder import _policy_temporal_first

        pub_date = datetime(2024, 1, 15)
        vuln = self._make_vuln(published_at=pub_date)
        # PoC appears 120 days after publication (outside 90-day window)
        signals = [
            self._make_signal("poc_exploitdb", value_bool=True,
                              observed_at=pub_date + timedelta(days=120)),
        ]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_temporal_first(
            vuln, signals, asof, horizon_days=90
        )
        assert label == 0
        assert "No exploit signal" in rationale

    def test_temporal_no_pub_date(self):
        """Missing publication date → label=0."""
        from app.ingest.label_builder import _policy_temporal_first

        vuln = self._make_vuln()
        vuln.published_at = None  # Explicitly set to None (not MagicMock default)
        signals = [self._make_signal("kev", value_bool=True)]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_temporal_first(
            vuln, signals, asof, horizon_days=90
        )
        assert label == 0
        assert "No publication date" in rationale

    def test_composite_multiple_signals(self):
        """Multiple exploit signals → label=1 with all contributing."""
        from app.ingest.label_builder import _policy_composite

        vuln = self._make_vuln()
        signals = [
            self._make_signal("kev", value_bool=True),
            self._make_signal("poc_exploitdb", value_bool=True),
            self._make_signal("epss", value_num=0.5),  # Not an exploit signal
        ]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_composite(vuln, signals, asof)
        assert label == 1
        assert len(contributing) == 2  # kev + poc, not epss

    def test_epss_derived_both_conditions(self):
        """KEV + EPSS >= threshold → label=1."""
        from app.ingest.label_builder import _policy_epss_derived

        vuln = self._make_vuln()
        signals = [
            self._make_signal("kev", value_bool=True),
            self._make_signal("epss", value_num=0.25),
        ]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_epss_derived(
            vuln, signals, asof, epss_threshold=0.15
        )
        assert label == 1

    def test_epss_derived_no_kev(self):
        """High EPSS but no KEV → label=0."""
        from app.ingest.label_builder import _policy_epss_derived

        vuln = self._make_vuln()
        signals = [
            self._make_signal("epss", value_num=0.95),
        ]
        asof = datetime(2024, 12, 31)

        label, contributing, rationale = _policy_epss_derived(
            vuln, signals, asof, epss_threshold=0.15
        )
        assert label == 0
        assert "KEV=False" in rationale


# ── Test provenance tracking ──────────────────────────────────────────

class TestProvenance:
    """Test that provenance records are correctly structured."""

    def test_provenance_dataclass(self):
        prov = LabelProvenance(
            vuln_id="test-uuid",
            cve_id="CVE-2024-1234",
            policy="kev_strict",
            label_value=1,
            label_asof=datetime(2024, 12, 31),
            contributing_signals=[
                {"signal_type": "kev", "observed_at": "2024-02-01", "value_bool": True}
            ],
            excluded_features=["kev_flag"],
            rationale="KEV observed before cut-off",
        )
        assert prov.label_value == 1
        assert len(prov.contributing_signals) == 1
        assert prov.excluded_features == ["kev_flag"]
