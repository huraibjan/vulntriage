"""Tests for the standard CISA SSVC decision (app/schemas/ssvc_cisa.py).

The reference rows below are the body of the CERT/CC SSVC file
data/csv/cisa/cisa_coordinator_2_0_3.csv (CISA Coordinator v2.0.3), kept in
its original text form so the module's table is checked against a second,
independent representation of the published source.  Offline: no database
and no network access.
"""

from __future__ import annotations

import itertools

import pytest

from app.schemas.decision import Criticality
from app.schemas.ssvc_cisa import (
    CISA_COORDINATOR_TABLE,
    PROVENANCE_DEFAULT,
    PROVENANCE_DERIVED,
    PROVENANCE_OBSERVED,
    CisaAutomatable,
    CisaExploitation,
    CisaMissionWellbeing,
    CisaOutcome,
    CisaTechnicalImpact,
    derive_decision_points,
    ssvc_cisa_decide,
)

# row,Exploitation,Automatable,Technical Impact,Mission and Well-Being Impact,CISA Levels
REFERENCE_CSV = """\
0,none,no,partial,low,track
1,none,no,partial,medium,track
2,none,no,partial,high,track
3,none,no,total,low,track
4,none,no,total,medium,track
5,none,no,total,high,track*
6,none,yes,partial,low,track
7,none,yes,partial,medium,track
8,none,yes,partial,high,attend
9,none,yes,total,low,track
10,none,yes,total,medium,track
11,none,yes,total,high,attend
12,public poc,no,partial,low,track
13,public poc,no,partial,medium,track
14,public poc,no,partial,high,track*
15,public poc,no,total,low,track
16,public poc,no,total,medium,track*
17,public poc,no,total,high,attend
18,public poc,yes,partial,low,track
19,public poc,yes,partial,medium,track
20,public poc,yes,partial,high,attend
21,public poc,yes,total,low,track
22,public poc,yes,total,medium,track*
23,public poc,yes,total,high,attend
24,active,no,partial,low,track
25,active,no,partial,medium,track
26,active,no,partial,high,attend
27,active,no,total,low,track
28,active,no,total,medium,attend
29,active,no,total,high,act
30,active,yes,partial,low,attend
31,active,yes,partial,medium,attend
32,active,yes,partial,high,act
33,active,yes,total,low,attend
34,active,yes,total,medium,act
35,active,yes,total,high,act
"""

_OUTCOME = {"track": "Track", "track*": "Track*", "attend": "Attend", "act": "Act"}

REFERENCE_ROWS = [
    tuple(line.split(",")[1:]) for line in REFERENCE_CSV.strip().splitlines()
]

V3_AUTO_TOTAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_LOCAL_PARTIAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"


# ── Decision table ─────────────────────────────────────────────────────

def test_reference_covers_all_36_combinations_once():
    assert len(REFERENCE_ROWS) == 36
    assert len({row[:4] for row in REFERENCE_ROWS}) == 36
    assert len(CISA_COORDINATOR_TABLE) == 36


def test_table_keys_are_the_full_cartesian_product():
    expected = set(itertools.product(
        CisaExploitation, CisaAutomatable, CisaTechnicalImpact, CisaMissionWellbeing,
    ))
    assert set(CISA_COORDINATOR_TABLE) == expected


@pytest.mark.parametrize(
    "exploitation,automatable,technical_impact,mission,expected", REFERENCE_ROWS,
)
def test_decide_matches_published_table(
    exploitation, automatable, technical_impact, mission, expected,
):
    outcome = ssvc_cisa_decide(exploitation, automatable, technical_impact, mission)
    assert isinstance(outcome, CisaOutcome)
    assert outcome.value == _OUTCOME[expected]


def test_outcome_distribution_matches_source():
    counts = {o: 0 for o in CisaOutcome}
    for outcome in CISA_COORDINATOR_TABLE.values():
        counts[outcome] += 1
    assert counts == {
        CisaOutcome.TRACK: 18,
        CisaOutcome.TRACK_STAR: 4,
        CisaOutcome.ATTEND: 10,
        CisaOutcome.ACT: 4,
    }


def test_decide_accepts_enums_strings_and_aliases():
    by_enum = ssvc_cisa_decide(
        CisaExploitation.POC, CisaAutomatable.YES,
        CisaTechnicalImpact.TOTAL, CisaMissionWellbeing.HIGH,
    )
    assert by_enum is CisaOutcome.ATTEND
    assert ssvc_cisa_decide("poc", "yes", "total", "high") is by_enum
    assert ssvc_cisa_decide(" Public PoC ", True, "TOTAL", "High") is by_enum
    assert ssvc_cisa_decide("active", False, "total", "high") is CisaOutcome.ACT


@pytest.mark.parametrize("args", [
    ("exploited", "yes", "total", "high"),
    ("active", "maybe", "total", "high"),
    ("active", "yes", "complete", "high"),
    ("active", "yes", "total", "critical"),
    ("active", "yes", "total", None),
])
def test_decide_rejects_invalid_values(args):
    with pytest.raises(ValueError):
        ssvc_cisa_decide(*args)


# ── Derivation: exploitation ───────────────────────────────────────────

@pytest.mark.parametrize("kev,poc,expected", [
    (True, True, "active"),
    (True, False, "active"),
    (False, True, "poc"),
    (False, False, "none"),
])
def test_exploitation_from_kev_and_poc(kev, poc, expected):
    points = derive_decision_points(
        in_kev=kev, has_public_poc=poc, cvss_vector=V3_AUTO_TOTAL,
    )
    assert points.exploitation.value == expected
    assert points.exploitation.provenance == PROVENANCE_OBSERVED


# ── Derivation: automatable ────────────────────────────────────────────

def test_automatable_yes_for_unauthenticated_network_vector():
    points = derive_decision_points(
        in_kev=False, has_public_poc=False, cvss_vector=V3_AUTO_TOTAL,
    )
    assert points.automatable.value == "yes"
    assert points.automatable.provenance == PROVENANCE_DERIVED


@pytest.mark.parametrize("vector", [
    "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
])
def test_automatable_no_when_any_condition_fails(vector):
    points = derive_decision_points(in_kev=False, has_public_poc=False, cvss_vector=vector)
    assert points.automatable.value == "no"
    assert points.automatable.provenance == PROVENANCE_DERIVED


# ── Derivation: technical impact ───────────────────────────────────────

@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "total"),
    ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H", "total"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "partial"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", "partial"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:H", "partial"),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", "partial"),
])
def test_technical_impact_total_only_when_cia_all_high(vector, expected):
    points = derive_decision_points(in_kev=False, has_public_poc=False, cvss_vector=vector)
    assert points.technical_impact.value == expected
    assert points.technical_impact.provenance == PROVENANCE_DERIVED


@pytest.mark.parametrize("vector", [
    None,
    "",
    "not a vector",
    "AV:N/AC:L/Au:N/C:C/I:C/A:C",                                   # CVSS v2
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # CVSS v4
    "CVSS:3.1/AV:N",                                                # truncated
])
def test_unusable_vector_falls_back_to_less_urgent_defaults(vector):
    points = derive_decision_points(in_kev=False, has_public_poc=False, cvss_vector=vector)
    assert points.automatable.value == "no"
    assert points.automatable.provenance == PROVENANCE_DEFAULT
    assert points.technical_impact.value == "partial"
    assert points.technical_impact.provenance == PROVENANCE_DEFAULT


def test_vector_parsing_is_case_and_whitespace_tolerant():
    points = derive_decision_points(
        in_kev=False, has_public_poc=False,
        cvss_vector="  cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h ",
    )
    assert points.automatable.value == "yes"
    assert points.technical_impact.value == "total"


# ── Derivation: mission and well-being ─────────────────────────────────

@pytest.mark.parametrize("criticality,expected", [
    ("critical", "high"),
    ("high", "high"),
    ("medium", "medium"),
    ("low", "low"),
    ("HIGH", "high"),
    (Criticality.CRITICAL, "high"),
    (Criticality.LOW, "low"),
])
def test_mission_wellbeing_from_asset_criticality(criticality, expected):
    points = derive_decision_points(
        in_kev=False, has_public_poc=False, cvss_vector=V3_AUTO_TOTAL,
        asset_criticality=criticality,
    )
    assert points.mission_wellbeing.value == expected
    assert points.mission_wellbeing.provenance == PROVENANCE_DERIVED


def test_mission_wellbeing_defaults_to_medium_without_asset():
    points = derive_decision_points(
        in_kev=False, has_public_poc=False, cvss_vector=V3_AUTO_TOTAL,
    )
    assert points.mission_wellbeing.value == "medium"
    assert points.mission_wellbeing.provenance == PROVENANCE_DEFAULT


def test_unknown_asset_criticality_is_rejected():
    with pytest.raises(ValueError):
        derive_decision_points(
            in_kev=False, has_public_poc=False, cvss_vector=V3_AUTO_TOTAL,
            asset_criticality="severe",
        )


# ── End to end ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("kev,poc,vector,criticality,expected", [
    (True, False, V3_AUTO_TOTAL, "critical", "Act"),       # row 35
    (True, False, V3_AUTO_TOTAL, None, "Act"),             # row 34
    (True, False, V3_LOCAL_PARTIAL, None, "Track"),        # row 25
    (False, True, V3_AUTO_TOTAL, None, "Track*"),          # row 22
    (False, True, V3_AUTO_TOTAL, "high", "Attend"),        # row 23
    (False, False, V3_AUTO_TOTAL, "low", "Track"),         # row 9
    (False, False, None, None, "Track"),                   # row 1
])
def test_derived_points_feed_the_decision_table(kev, poc, vector, criticality, expected):
    points = derive_decision_points(
        in_kev=kev, has_public_poc=poc, cvss_vector=vector, asset_criticality=criticality,
    )
    assert points.decide().value == expected


def test_to_dict_exposes_values_provenance_and_source():
    payload = derive_decision_points(
        in_kev=True, has_public_poc=True, cvss_vector=V3_AUTO_TOTAL,
    ).to_dict()
    assert payload["outcome"] == "Act"
    assert set(payload["decision_points"]) == {
        "exploitation", "automatable", "technical_impact", "mission_wellbeing",
    }
    for point in payload["decision_points"].values():
        assert set(point) == {"value", "provenance", "detail"}
        assert point["provenance"] in {
            PROVENANCE_OBSERVED, PROVENANCE_DERIVED, PROVENANCE_DEFAULT,
        }
        assert point["detail"]
    assert payload["decision_points"]["exploitation"]["provenance"] == PROVENANCE_OBSERVED
    assert payload["decision_points"]["mission_wellbeing"]["provenance"] == PROVENANCE_DEFAULT
    assert payload["table"]["version"] == "2.0.3"
    assert payload["table"]["source"].startswith("https://github.com/CERTCC/SSVC/")
