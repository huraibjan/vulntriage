"""CVSS v3.1 vector string parser.

Parses a CVSS:3.1/... vector into its constituent metric values
and provides numeric encodings suitable for ML feature engineering.

Reference: https://www.first.org/cvss/v3.1/specification-document
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


@dataclass
class CVSSMetrics:
    """Parsed CVSS v3.x metrics with ordinal encodings."""

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
    """Parse a CVSS v3.x vector string into a CVSSMetrics dataclass.

    Args:
        vector: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Returns:
        CVSSMetrics with parsed values. Check `is_valid` for success.
    """
    if not vector:
        return CVSSMetrics(raw_vector="", parse_error="Empty vector")

    m = CVSSMetrics(raw_vector=vector)

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
