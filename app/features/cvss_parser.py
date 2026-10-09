"""CVSS v3.x and v4.0 vector string parser.

Parses a CVSS:3.x/... or CVSS:4.0/... vector into its constituent metric
values and provides numeric encodings suitable for ML feature engineering.

A v4.0 vector is projected onto the v3 base-metric schema so that both
versions yield the same feature keys with the same ordinal encodings; the
rank models were trained on that schema and cannot consume a second one.
The projection is documented at ``_parse_v4``.

References:
    https://www.first.org/cvss/v3.1/specification-document
    https://www.first.org/cvss/v4.0/specification-document
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional

# ── Metric value ordinal maps (higher = more severe / easier to exploit) ──
METRIC_ORDINALS: Dict[str, Dict[str, int]] = {
    "AV": {"N": 3, "A": 2, "L": 1, "P": 0},         # Attack Vector
    "AC": {"L": 1, "H": 0},                           # Attack Complexity
    "PR": {"N": 2, "L": 1, "H": 0},                   # Privileges Required
    "UI": {"N": 1, "R": 0},                           # User Interaction
    "S":  {"C": 1, "U": 0},                           # Scope
    "C":  {"H": 2, "L": 1, "N": 0},                   # Confidentiality Impact
    "I":  {"H": 2, "L": 1, "N": 0},                   # Integrity Impact
    "A":  {"H": 2, "L": 1, "N": 0},                   # Availability Impact
}

# Full metric name mapping for readability
METRIC_NAMES: Dict[str, str] = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "PR": "privileges_required",
    "UI": "user_interaction",
    "S": "scope",
    "C": "confidentiality_impact",
    "I": "integrity_impact",
    "A": "availability_impact",
}

_VECTOR_PATTERN = re.compile(
    r"^CVSS:3\.[01]/(.+)$", re.IGNORECASE
)

# ── CVSS v4.0 ────────────────────────────────────────────────────────────
# Permitted values of the eleven mandatory v4.0 base metrics. Threat,
# environmental and supplemental metrics are ignored: they are optional,
# and several reuse v3 abbreviations with a different meaning (v4 "S" is
# Safety, not Scope), which is why v4 is validated against its own table.
V4_BASE_METRIC_VALUES: Dict[str, frozenset] = {
    "AV": frozenset("NALP"),   # Attack Vector
    "AC": frozenset("LH"),     # Attack Complexity
    "AT": frozenset("NP"),     # Attack Requirements (validated, not encoded)
    "PR": frozenset("NLH"),    # Privileges Required
    "UI": frozenset("NPA"),    # User Interaction: None / Passive / Active
    "VC": frozenset("HLN"),    # Vulnerable-system Confidentiality
    "VI": frozenset("HLN"),    # Vulnerable-system Integrity
    "VA": frozenset("HLN"),    # Vulnerable-system Availability
    "SC": frozenset("HLN"),    # Subsequent-system Confidentiality
    "SI": frozenset("HLN"),    # Subsequent-system Integrity
    "SA": frozenset("HLN"),    # Subsequent-system Availability
}

_V4_VECTOR_PATTERN = re.compile(r"^CVSS:4\.0/(.+)$", re.IGNORECASE)


@dataclass
class CVSSMetrics:
    """Parsed CVSS metrics with ordinal encodings.

    The metric fields always hold v3 base-metric values. For a v4.0 vector
    (``version == "4.0"``) they hold the v3-equivalent projection described
    at ``_parse_v4``; ``raw_vector`` retains the original string.
    """

    raw_vector: str
    version: str = "3.1"

    # Raw metric values
    AV: str = ""
    AC: str = ""
    PR: str = ""
    UI: str = ""
    S: str = ""
    C: str = ""
    I: str = ""
    A: str = ""

    # Computed
    is_valid: bool = False
    parse_error: Optional[str] = None

    def ordinal(self, metric: str) -> int:
        """Return the ordinal encoding for a metric (higher = more severe)."""
        val = getattr(self, metric, "")
        return METRIC_ORDINALS.get(metric, {}).get(val, -1)

    def to_feature_dict(self) -> Dict[str, float]:
        """Return a flat dict of numeric features for ML."""
        d: Dict[str, float] = {}
        for short, full in METRIC_NAMES.items():
            d[f"cvss_{full}"] = float(self.ordinal(short))
        d["cvss_is_network"] = float(self.AV == "N")
        d["cvss_no_privs"] = float(self.PR == "N")
        d["cvss_no_interaction"] = float(self.UI == "N")
        d["cvss_scope_changed"] = float(self.S == "C")
        d["cvss_cia_total"] = float(
            self.ordinal("C") + self.ordinal("I") + self.ordinal("A")
        )
        return d


def parse_cvss_vector(vector: Optional[str]) -> CVSSMetrics:
    """Parse a CVSS v3.x or v4.0 vector string into a CVSSMetrics dataclass.

    Args:
        vector: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" or
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

    Returns:
        CVSSMetrics with parsed values. Check `is_valid` for success.
    """
    if not vector:
        return CVSSMetrics(raw_vector="", parse_error="Empty vector")

    m = CVSSMetrics(raw_vector=vector)

    v4_match = _V4_VECTOR_PATTERN.match(vector.strip())
    if v4_match:
        return _parse_v4(m, v4_match.group(1))

    match = _VECTOR_PATTERN.match(vector.strip())
    if not match:
        m.parse_error = f"Does not match CVSS:3.x pattern: {vector}"
        return m

    # Extract version
    if "3.0" in vector:
        m.version = "3.0"

    parts = match.group(1).split("/")
    seen = set()
    for part in parts:
        kv = part.split(":")
        if len(kv) != 2:
            m.parse_error = f"Invalid metric component: {part}"
            return m

        key, val = kv
        key = key.upper()
        if key not in METRIC_ORDINALS:
            # Skip temporal/environmental metrics gracefully
            continue

        if key in seen:
            m.parse_error = f"Duplicate metric: {key}"
            return m
        seen.add(key)

        if val not in METRIC_ORDINALS[key]:
            m.parse_error = f"Invalid value for {key}: {val}"
            return m

        setattr(m, key, val)

    # Validate all base metrics are present
    required = set(METRIC_ORDINALS.keys())
    missing = required - seen
    if missing:
        m.parse_error = f"Missing metrics: {missing}"
        return m

    m.is_valid = True
    return m


def _parse_v4(m: CVSSMetrics, body: str) -> CVSSMetrics:
    """Validate a CVSS v4.0 metric string and project it onto v3 fields.

    Projection of the v4.0 base metrics (the encodings are those of
    ``METRIC_ORDINALS``, so v3 and v4 features are directly comparable):

    * AV, AC, PR carry over unchanged; the value sets are identical.
    * UI: N stays N; P (passive) and A (active) both become R. v3 only
      distinguishes whether a second party must act, and both v4 levels
      require such an action.
    * VC / VI / VA become C / I / A. The v3 impact metrics describe the
      vulnerable component, which is what the v4 vulnerable-system metrics
      measure.
    * S (Scope) does not exist in v4.0. It is derived as changed (C) when
      any subsequent-system impact SC / SI / SA is not N, and unchanged (U)
      otherwise: an impact beyond the vulnerable system is the condition
      that v3 Scope:Changed expressed. The derivation is one-directional,
      since v3 Scope also altered how PR was scored, which v4 does not do.
    * AT (Attack Requirements) has no v3 counterpart. It is validated as a
      mandatory base metric but deliberately yields no feature.

    Subsequent-system impact magnitudes are not added to the C / I / A
    ordinals, so ``cvss_cia_total`` keeps its v3 range of 0-6.
    """
    m.version = "4.0"

    values: Dict[str, str] = {}
    for part in body.split("/"):
        kv = part.split(":")
        if len(kv) != 2:
            m.parse_error = f"Invalid metric component: {part}"
            return m

        key, val = kv
        key = key.upper()
        if key not in V4_BASE_METRIC_VALUES:
            # Skip threat/environmental/supplemental metrics gracefully
            continue

        if key in values:
            m.parse_error = f"Duplicate metric: {key}"
            return m

        if val not in V4_BASE_METRIC_VALUES[key]:
            m.parse_error = f"Invalid value for {key}: {val}"
            return m

        values[key] = val

    missing = set(V4_BASE_METRIC_VALUES) - set(values)
    if missing:
        m.parse_error = f"Missing metrics: {missing}"
        return m

    m.AV = values["AV"]
    m.AC = values["AC"]
    m.PR = values["PR"]
    m.UI = "N" if values["UI"] == "N" else "R"
    m.S = "C" if any(values[k] != "N" for k in ("SC", "SI", "SA")) else "U"
    m.C = values["VC"]
    m.I = values["VI"]
    m.A = values["VA"]

    m.is_valid = True
    return m
