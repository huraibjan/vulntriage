"""Unit tests for CVSS v3 vector parser."""

import pytest
from app.features.cvss_parser import CVSSMetrics, parse_cvss_vector


# ─────────────────────────────────────────────────────────────
#  Valid vectors
# ─────────────────────────────────────────────────────────────

class TestParseCVSSVector:
    """Test CVSS vector string parsing."""

    def test_full_v31_vector(self):
        """Parse a standard CVSS 3.1 vector."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        m = parse_cvss_vector(vec)
        assert isinstance(m, CVSSMetrics)
        assert m.is_valid is True
        assert m.AV == "N"
        assert m.AC == "L"
        assert m.PR == "N"
        assert m.UI == "N"
        assert m.S == "U"
        assert m.C == "H"
        assert m.I == "H"
        assert m.A == "H"

    def test_v30_vector(self):
        vec = "CVSS:3.0/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:N"
        m = parse_cvss_vector(vec)
        assert m.is_valid is True
        assert m.version == "3.0"
        assert m.AV == "A"
        assert m.AC == "H"
        assert m.PR == "L"
        assert m.UI == "R"
        assert m.S == "C"
        assert m.C == "L"
        assert m.I == "L"
        assert m.A == "N"

    def test_physical_access_vector(self):
        vec = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        m = parse_cvss_vector(vec)
        assert m.is_valid is True
        assert m.AV == "P"

    def test_local_access_vector(self):
        vec = "CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:L"
        m = parse_cvss_vector(vec)
        assert m.is_valid is True
        assert m.AV == "L"
        assert m.PR == "H"

    def test_none_input(self):
        m = parse_cvss_vector(None)
        assert m.is_valid is False
        assert m.parse_error is not None

    def test_empty_string(self):
        m = parse_cvss_vector("")
        assert m.is_valid is False

    def test_invalid_string(self):
        m = parse_cvss_vector("not-a-cvss-vector")
        assert m.is_valid is False

    def test_malformed_value(self):
        """AV:X is not a valid metric value."""
        m = parse_cvss_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m.is_valid is False
        assert "Invalid value" in m.parse_error

    def test_missing_metrics(self):
        """Missing several required metrics should fail validation."""
        m = parse_cvss_vector("CVSS:3.1/AV:N/AC:L")
        assert m.is_valid is False
        assert "Missing metrics" in m.parse_error

    def test_duplicate_metric(self):
        m = parse_cvss_vector("CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m.is_valid is False
        assert "Duplicate" in m.parse_error

    def test_ordinal_encoding(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        m = parse_cvss_vector(vec)
        assert m.ordinal("AV") == 3  # N=3
        assert m.ordinal("AC") == 1  # L=1
        assert m.ordinal("PR") == 2  # N=2
        assert m.ordinal("C") == 2   # H=2


# ─────────────────────────────────────────────────────────────
#  Feature dict conversion
# ─────────────────────────────────────────────────────────────

class TestToFeatureDict:
    """Test conversion of CVSSMetrics to feature dict."""

    def test_network_no_auth_critical(self):
        """A network-accessible, no-priv, critical vuln should flag hot features."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        m = parse_cvss_vector(vec)
        d = m.to_feature_dict()

        assert d["cvss_attack_vector"] == 3.0    # N ordinal
        assert d["cvss_attack_complexity"] == 1.0  # L ordinal
        assert d["cvss_privileges_required"] == 2.0  # N ordinal (higher = less privs needed)
        assert d["cvss_user_interaction"] == 1.0  # N ordinal
        assert d["cvss_is_network"] == 1.0
        assert d["cvss_no_privs"] == 1.0
        assert d["cvss_cia_total"] == 6.0  # 2+2+2

    def test_local_high_priv_low_impact(self):
        vec = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:L/A:N"
        m = parse_cvss_vector(vec)
        d = m.to_feature_dict()

        assert d["cvss_attack_vector"] == 1.0   # L ordinal
        assert d["cvss_attack_complexity"] == 0.0  # H ordinal (0 = harder)
        assert d["cvss_privileges_required"] == 0.0  # H ordinal (0 = needs most privs)
        assert d["cvss_user_interaction"] == 0.0  # R ordinal
        assert d["cvss_is_network"] == 0.0
        assert d["cvss_no_privs"] == 0.0
        assert d["cvss_cia_total"] == 1.0  # 0+1+0

    def test_all_feature_keys_present(self):
        """Ensure all expected feature keys are present."""
        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        m = parse_cvss_vector(vec)
        d = m.to_feature_dict()

        expected_keys = {
            "cvss_attack_vector", "cvss_attack_complexity",
            "cvss_privileges_required", "cvss_user_interaction",
            "cvss_scope", "cvss_confidentiality_impact",
            "cvss_integrity_impact", "cvss_availability_impact",
            "cvss_is_network", "cvss_no_privs",
            "cvss_no_interaction", "cvss_scope_changed",
            "cvss_cia_total",
        }
        assert set(d.keys()) == expected_keys

    def test_feature_values_are_numeric(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
        m = parse_cvss_vector(vec)
        d = m.to_feature_dict()

        for key, val in d.items():
            assert isinstance(val, (int, float)), f"{key} is not numeric: {val}"

    def test_scope_changed_flag(self):
        vec = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"
        m = parse_cvss_vector(vec)
        d = m.to_feature_dict()
        assert d["cvss_scope_changed"] == 1.0

        vec2 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
        m2 = parse_cvss_vector(vec2)
        d2 = m2.to_feature_dict()
        assert d2["cvss_scope_changed"] == 0.0
