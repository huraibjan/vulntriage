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


# ─────────────────────────────────────────────────────────────
#  CVSS v4.0 vectors (projected onto the v3 feature schema)
# ─────────────────────────────────────────────────────────────

V4_BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

# Full-length form as published by NVD: every optional metric is present,
# and the supplemental Safety metric reuses the v3 Scope abbreviation "S".
V4_NVD_FULL = (
    "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"
    "/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X"
    "/MSC:X/MSI:X/MSA:X/S:P/AU:Y/R:A/V:X/RE:M/U:Amber"
)


class TestParseCVSSv4Vector:
    """Test CVSS v4.0 parsing and its projection onto v3 metric fields."""

    def test_base_vector_is_valid(self):
        m = parse_cvss_vector(V4_BASE)
        assert m.is_valid is True
        assert m.parse_error is None
        assert m.version == "4.0"
        assert m.raw_vector == V4_BASE
        assert (m.AV, m.AC, m.PR, m.UI) == ("N", "L", "N", "N")
        assert (m.C, m.I, m.A) == ("H", "H", "H")
        assert m.S == "U"

    def test_vulnerable_system_impacts_map_to_cia(self):
        m = parse_cvss_vector(
            "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N"
        )
        assert m.is_valid is True
        assert (m.AV, m.AC, m.PR) == ("L", "H", "H")
        assert (m.C, m.I, m.A) == ("L", "N", "H")

    @pytest.mark.parametrize("ui,expected", [("N", "N"), ("P", "R"), ("A", "R")])
    def test_user_interaction_mapping(self, ui, expected):
        """Passive and active interaction both map to v3 'required'."""
        m = parse_cvss_vector(V4_BASE.replace("UI:N", f"UI:{ui}"))
        assert m.is_valid is True
        assert m.UI == expected

    @pytest.mark.parametrize(
        "subsequent,expected",
        [
            ("SC:N/SI:N/SA:N", "U"),
            ("SC:L/SI:N/SA:N", "C"),
            ("SC:N/SI:H/SA:N", "C"),
            ("SC:N/SI:N/SA:L", "C"),
            ("SC:H/SI:H/SA:H", "C"),
        ],
    )
    def test_scope_derived_from_subsequent_system_impact(self, subsequent, expected):
        m = parse_cvss_vector(V4_BASE.replace("SC:N/SI:N/SA:N", subsequent))
        assert m.is_valid is True
        assert m.S == expected

    def test_subsequent_impact_does_not_inflate_cia(self):
        """SC/SI/SA drive scope only; C/I/A come from VC/VI/VA."""
        m = parse_cvss_vector(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H"
        )
        assert m.is_valid is True
        assert (m.C, m.I, m.A) == ("N", "N", "N")
        assert m.to_feature_dict()["cvss_cia_total"] == 0.0

    def test_nvd_full_vector_ignores_optional_metrics(self):
        """Supplemental 'S' (Safety) must not be read as v3 Scope."""
        m = parse_cvss_vector(V4_NVD_FULL)
        assert m.is_valid is True
        assert m.UI == "R"
        assert m.S == "C"
        assert (m.C, m.I, m.A) == ("H", "H", "N")

    def test_supplemental_safety_does_not_set_scope(self):
        m = parse_cvss_vector(V4_BASE + "/S:P")
        assert m.is_valid is True
        assert m.S == "U"

    def test_attack_requirements_has_no_feature(self):
        """AT has no v3 counterpart: it must not change any feature."""
        d_n = parse_cvss_vector(V4_BASE).to_feature_dict()
        d_p = parse_cvss_vector(V4_BASE.replace("AT:N", "AT:P")).to_feature_dict()
        assert d_n == d_p
        assert not any("requirement" in k or k.endswith("_at") for k in d_n)

    def test_missing_base_metric(self):
        m = parse_cvss_vector(V4_BASE.replace("/SA:N", ""))
        assert m.is_valid is False
        assert "Missing metrics" in m.parse_error
        assert "SA" in m.parse_error

    def test_invalid_value(self):
        m = parse_cvss_vector(V4_BASE.replace("UI:N", "UI:R"))
        assert m.is_valid is False
        assert "Invalid value for UI" in m.parse_error

    def test_duplicate_metric(self):
        m = parse_cvss_vector(V4_BASE + "/AV:L")
        assert m.is_valid is False
        assert "Duplicate" in m.parse_error

    def test_malformed_component(self):
        m = parse_cvss_vector(V4_BASE + "/garbage")
        assert m.is_valid is False
        assert "Invalid metric component" in m.parse_error

    def test_v3_metrics_under_v4_prefix_rejected(self):
        m = parse_cvss_vector("CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert m.is_valid is False

    def test_v4_metrics_under_v3_prefix_rejected(self):
        m = parse_cvss_vector(V4_BASE.replace("CVSS:4.0", "CVSS:3.1"))
        assert m.is_valid is False

    def test_unsupported_version_rejected(self):
        m = parse_cvss_vector(V4_BASE.replace("CVSS:4.0", "CVSS:4.1"))
        assert m.is_valid is False


class TestV4FeatureDict:
    """A v4.0 vector must yield the v3 feature schema and encodings."""

    def test_same_keys_as_v3(self):
        v3 = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        v4 = parse_cvss_vector(V4_NVD_FULL)
        assert set(v4.to_feature_dict()) == set(v3.to_feature_dict())

    def test_equivalent_vectors_give_identical_features(self):
        v3 = parse_cvss_vector("CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:C/C:L/I:H/A:N")
        v4 = parse_cvss_vector(
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:A/VC:L/VI:H/VA:N/SC:L/SI:N/SA:N"
        )
        assert v4.is_valid is True
        assert v4.to_feature_dict() == v3.to_feature_dict()

    def test_explicit_encodings(self):
        d = parse_cvss_vector(V4_NVD_FULL).to_feature_dict()
        assert d == {
            "cvss_attack_vector": 3.0,
            "cvss_attack_complexity": 1.0,
            "cvss_privileges_required": 2.0,
            "cvss_user_interaction": 0.0,
            "cvss_scope": 1.0,
            "cvss_confidentiality_impact": 2.0,
            "cvss_integrity_impact": 2.0,
            "cvss_availability_impact": 0.0,
            "cvss_is_network": 1.0,
            "cvss_no_privs": 1.0,
            "cvss_no_interaction": 0.0,
            "cvss_scope_changed": 1.0,
            "cvss_cia_total": 4.0,
        }

    def test_no_negative_ordinals(self):
        """Every projected value must be a known v3 value (ordinal != -1)."""
        d = parse_cvss_vector(V4_NVD_FULL).to_feature_dict()
        assert all(v >= 0.0 for v in d.values())
