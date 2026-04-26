"""Tests for the policy engine — DB-wired decision making."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, patch

import pytest

from app.features.policy_engine import (
    _DEFAULT_CONFIG,
    build_evidence_input,
    load_policy_config,
)
from app.schemas.decision import (
    Action,
    Affectedness,
    ControlStatus,
    Criticality,
    DecisionOutput,
    EvidenceInput,
    Exploitation,
    Reachability,
    decide,
)


class TestPolicyConfig:
    """Test policy configuration loading."""

    def test_default_config_structure(self):
        config = _DEFAULT_CONFIG
        assert "thresholds" in config
        assert "sla_hours" in config
        assert "policy" in config

    def test_default_thresholds(self):
        thresholds = _DEFAULT_CONFIG["thresholds"]
        assert thresholds["epss_high"] == 0.5
        assert thresholds["cvss_critical"] == 9.0
        assert thresholds["control_full_effectiveness"] == 0.9

    def test_load_config_returns_dict(self):
        config = load_policy_config()
        assert isinstance(config, dict)
        assert "thresholds" in config


class TestDecisionTree:
    """Test the SSVC-inspired decision tree logic."""

    def test_vex_not_affected_returns_accept(self):
        evidence = EvidenceInput(
            affectedness=Affectedness.NOT_AFFECTED,
        )
        decision = decide(evidence)
        assert decision.action == Action.ACCEPT
        assert decision.confidence >= 0.9

    def test_active_exploit_critical_asset_returns_patch_now(self):
        evidence = EvidenceInput(
            affectedness=Affectedness.AFFECTED,
            exploitation=Exploitation.ACTIVE,
            asset_criticality=Criticality.CRITICAL,
            control_status=ControlStatus.NO_CONTROLS,
        )
        decision = decide(evidence)
        assert decision.action == Action.PATCH_NOW

    def test_active_exploit_low_asset_returns_mitigate(self):
        evidence = EvidenceInput(
            affectedness=Affectedness.AFFECTED,
            exploitation=Exploitation.ACTIVE,
            asset_criticality=Criticality.LOW,
            control_status=ControlStatus.NO_CONTROLS,
        )
        decision = decide(evidence)
        assert decision.action == Action.MITIGATE_NOW

    def test_active_exploit_fully_mitigated_critical_returns_patch_window(self):
        evidence = EvidenceInput(
            affectedness=Affectedness.AFFECTED,
            exploitation=Exploitation.ACTIVE,
            asset_criticality=Criticality.CRITICAL,
            control_status=ControlStatus.FULLY_MITIGATED,
        )
        decision = decide(evidence)
        assert decision.action == Action.PATCH_WINDOW

    def test_poc_public_high_risk_reachable_critical_returns_patch_now(self):
        evidence = EvidenceInput(
            affectedness=Affectedness.AFFECTED,
            exploitation=Exploitation.POC_PUBLIC,
            asset_criticality=Criticality.CRITICAL,
            reachability=Reachability.REACHABLE,
            cvss_base_score=9.8,
        )
        decision = decide(evidence)
        assert decision.action == Action.PATCH_NOW

    def test_no_exploit_low_risk_returns_accept(self):
        evidence = EvidenceInput(
            affectedness=Affectedness.AFFECTED,
            exploitation=Exploitation.NONE,
            epss_score=0.01,
            cvss_base_score=2.0,
            asset_criticality=Criticality.LOW,
        )
        decision = decide(evidence)
        assert decision.action in (Action.ACCEPT, Action.MONITOR)

    def test_decision_output_has_rationale(self):
        evidence = EvidenceInput()
        decision = decide(evidence)
        assert isinstance(decision.rationale, list)
        assert len(decision.rationale) > 0

    def test_decision_output_has_sla(self):
        evidence = EvidenceInput(
            exploitation=Exploitation.ACTIVE,
            asset_criticality=Criticality.CRITICAL,
            control_status=ControlStatus.NO_CONTROLS,
        )
        decision = decide(evidence)
        assert decision.sla_hours is not None
        assert decision.sla_hours > 0

    def test_all_actions_have_sla(self):
        from app.schemas.decision import SLA_HOURS
        for action in Action:
            assert action in SLA_HOURS or action.value in SLA_HOURS


class TestBuildEvidenceInput:
    """Test building EvidenceInput from mocked DB objects."""

    def _make_asset(self, criticality="high", internet_facing=True):
        asset = MagicMock()
        asset.id = "asset-123"
        asset.criticality = criticality
        asset.is_internet_facing = internet_facing
        return asset

    def _make_vuln(self, cvss=7.5, published="2023-06-01"):
        vuln = MagicMock()
        vuln.id = "vuln-456"
        vuln.cve_id = "CVE-2023-12345"
        vuln.cvss_base_score = cvss
        vuln.published_at = date.fromisoformat(published)
        vuln.affected_products_json = [
            {"vendor": "apache", "product": "http_server"}
        ]
        return vuln

    @patch("app.features.policy_engine._resolve_weaponization")
    @patch("app.features.policy_engine._resolve_controls")
    @patch("app.features.policy_engine._resolve_reachability")
    @patch("app.features.policy_engine._resolve_affectedness")
    def test_builds_evidence_input(
        self, mock_affect, mock_reach, mock_ctrl, mock_weapon
    ):
        mock_affect.return_value = (Affectedness.AFFECTED, "affected")
        mock_reach.return_value = Reachability.REACHABLE
        mock_weapon.return_value = (Exploitation.POC_PUBLIC, 0.3)
        mock_ctrl.return_value = (ControlStatus.NO_CONTROLS, 0.0)

        asset = self._make_asset()
        vuln = self._make_vuln()
        session = MagicMock()

        evidence = build_evidence_input(
            asset, vuln, session, date(2024, 6, 1)
        )

        assert isinstance(evidence, EvidenceInput)
        assert evidence.cvss_base_score == 7.5
        assert evidence.is_internet_facing is True

    @patch("app.features.policy_engine._resolve_weaponization")
    @patch("app.features.policy_engine._resolve_controls")
    @patch("app.features.policy_engine._resolve_reachability")
    @patch("app.features.policy_engine._resolve_affectedness")
    def test_ml_prob_passed_through(
        self, mock_affect, mock_reach, mock_ctrl, mock_weapon
    ):
        mock_affect.return_value = (Affectedness.UNKNOWN, None)
        mock_reach.return_value = Reachability.UNKNOWN
        mock_weapon.return_value = (Exploitation.NONE, 0.05)
        mock_ctrl.return_value = (ControlStatus.UNKNOWN, 0.0)

        evidence = build_evidence_input(
            self._make_asset(), self._make_vuln(),
            MagicMock(), date(2024, 6, 1),
            ml_exploit_prob=0.82,
        )

        assert evidence.ml_exploit_prob == 0.82
