"""Standard CISA SSVC decision (Track / Track* / Attend / Act).

This module implements the published CISA Coordinator decision table as a
pure function.  It complements, and does not replace, the five-tier
"SSVC-inspired" engine in :mod:`app.schemas.decision`: that engine consumes
ML scores and asset evidence, whereas this one reproduces the reference CISA
decision points so that results can be compared against the standard.

Source of the decision table
----------------------------
Transcribed row for row from the CERT/CC SSVC repository (retrieved
2026-10-08, branch ``main``):

    https://github.com/CERTCC/SSVC/blob/main/data/csv/cisa/cisa_coordinator_2_0_3.csv

    Decision table : CISA Coordinator, namespace ``cisa``, key ``DT_CO``,
                     version 2.0.3
    Decision points: Exploitation v1.1.0, Automatable v2.0.0,
                     Technical Impact v1.0.0,
                     Mission and Well-Being Impact v1.0.0
    Outcome        : CISA Levels v1.1.0
    File SHA-256   : b8ab4ac8739b9eb0e1f90e67f7de4a03485fe4070bc1b3d2397be3dd3e2a478d

The source file names the middle Exploitation value "public poc"; it is
exposed here as ``poc``.  No other value was renamed.

Derivation of the decision points
---------------------------------
CISA's own assessments of Automatable and Technical Impact are published
through the Vulnrichment programme, which VulnTriage does not ingest.
:func:`derive_decision_points` therefore infers those two inputs from the
CVSS v3 vector, and infers Mission and Well-Being Impact from asset
criticality.  Every derived value carries a provenance string so that a
consumer can distinguish an observed input from an inferred or assumed one.
The inferred inputs are heuristics and are not CISA assessments.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple, Type, TypeVar, Union

# ── Source metadata ────────────────────────────────────────────────────

CISA_SSVC_TABLE_NAME = "CISA Coordinator"
CISA_SSVC_TABLE_VERSION = "2.0.3"
CISA_SSVC_TABLE_SOURCE = (
    "https://github.com/CERTCC/SSVC/blob/main/data/csv/cisa/"
    "cisa_coordinator_2_0_3.csv"
)

# ── Provenance labels ──────────────────────────────────────────────────

PROVENANCE_OBSERVED = "observed"
PROVENANCE_DERIVED = "derived heuristic"
# Used when no evidence was available and a fixed fallback value was applied.
PROVENANCE_DEFAULT = "default assumption"


# ── Decision points and outcome ────────────────────────────────────────

class CisaExploitation(str, Enum):
    """Exploitation v1.1.0 — present state of exploitation."""
    NONE = "none"
    POC = "poc"        # "public poc" in the source table
    ACTIVE = "active"


class CisaAutomatable(str, Enum):
    """Automatable v2.0.0 — can kill-chain steps 1-4 be reliably automated."""
    NO = "no"
    YES = "yes"


class CisaTechnicalImpact(str, Enum):
    """Technical Impact v1.0.0 — control gained over the vulnerable software."""
    PARTIAL = "partial"
    TOTAL = "total"


class CisaMissionWellbeing(str, Enum):
    """Mission and Well-Being Impact v1.0.0."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CisaOutcome(str, Enum):
    """CISA Levels v1.1.0 — ordered from least to most urgent."""
    TRACK = "Track"
    TRACK_STAR = "Track*"
    ATTEND = "Attend"
    ACT = "Act"


_E = CisaExploitation
_A = CisaAutomatable
_T = CisaTechnicalImpact
_M = CisaMissionWellbeing
_O = CisaOutcome

_Key = Tuple[CisaExploitation, CisaAutomatable, CisaTechnicalImpact, CisaMissionWellbeing]

# Rows appear in the order of the source CSV (row 0 to row 35).
CISA_COORDINATOR_TABLE: Dict[_Key, CisaOutcome] = {
    (_E.NONE, _A.NO, _T.PARTIAL, _M.LOW): _O.TRACK,            # 0
    (_E.NONE, _A.NO, _T.PARTIAL, _M.MEDIUM): _O.TRACK,         # 1
    (_E.NONE, _A.NO, _T.PARTIAL, _M.HIGH): _O.TRACK,           # 2
    (_E.NONE, _A.NO, _T.TOTAL, _M.LOW): _O.TRACK,              # 3
    (_E.NONE, _A.NO, _T.TOTAL, _M.MEDIUM): _O.TRACK,           # 4
    (_E.NONE, _A.NO, _T.TOTAL, _M.HIGH): _O.TRACK_STAR,        # 5
    (_E.NONE, _A.YES, _T.PARTIAL, _M.LOW): _O.TRACK,           # 6
    (_E.NONE, _A.YES, _T.PARTIAL, _M.MEDIUM): _O.TRACK,        # 7
    (_E.NONE, _A.YES, _T.PARTIAL, _M.HIGH): _O.ATTEND,         # 8
    (_E.NONE, _A.YES, _T.TOTAL, _M.LOW): _O.TRACK,             # 9
    (_E.NONE, _A.YES, _T.TOTAL, _M.MEDIUM): _O.TRACK,          # 10
    (_E.NONE, _A.YES, _T.TOTAL, _M.HIGH): _O.ATTEND,           # 11
    (_E.POC, _A.NO, _T.PARTIAL, _M.LOW): _O.TRACK,             # 12
    (_E.POC, _A.NO, _T.PARTIAL, _M.MEDIUM): _O.TRACK,          # 13
    (_E.POC, _A.NO, _T.PARTIAL, _M.HIGH): _O.TRACK_STAR,       # 14
    (_E.POC, _A.NO, _T.TOTAL, _M.LOW): _O.TRACK,               # 15
    (_E.POC, _A.NO, _T.TOTAL, _M.MEDIUM): _O.TRACK_STAR,       # 16
    (_E.POC, _A.NO, _T.TOTAL, _M.HIGH): _O.ATTEND,             # 17
    (_E.POC, _A.YES, _T.PARTIAL, _M.LOW): _O.TRACK,            # 18
    (_E.POC, _A.YES, _T.PARTIAL, _M.MEDIUM): _O.TRACK,         # 19
    (_E.POC, _A.YES, _T.PARTIAL, _M.HIGH): _O.ATTEND,          # 20
    (_E.POC, _A.YES, _T.TOTAL, _M.LOW): _O.TRACK,              # 21
    (_E.POC, _A.YES, _T.TOTAL, _M.MEDIUM): _O.TRACK_STAR,      # 22
    (_E.POC, _A.YES, _T.TOTAL, _M.HIGH): _O.ATTEND,            # 23
    (_E.ACTIVE, _A.NO, _T.PARTIAL, _M.LOW): _O.TRACK,          # 24
    (_E.ACTIVE, _A.NO, _T.PARTIAL, _M.MEDIUM): _O.TRACK,       # 25
    (_E.ACTIVE, _A.NO, _T.PARTIAL, _M.HIGH): _O.ATTEND,        # 26
    (_E.ACTIVE, _A.NO, _T.TOTAL, _M.LOW): _O.TRACK,            # 27
    (_E.ACTIVE, _A.NO, _T.TOTAL, _M.MEDIUM): _O.ATTEND,        # 28
    (_E.ACTIVE, _A.NO, _T.TOTAL, _M.HIGH): _O.ACT,             # 29
    (_E.ACTIVE, _A.YES, _T.PARTIAL, _M.LOW): _O.ATTEND,        # 30
    (_E.ACTIVE, _A.YES, _T.PARTIAL, _M.MEDIUM): _O.ATTEND,     # 31
    (_E.ACTIVE, _A.YES, _T.PARTIAL, _M.HIGH): _O.ACT,          # 32
    (_E.ACTIVE, _A.YES, _T.TOTAL, _M.LOW): _O.ATTEND,          # 33
    (_E.ACTIVE, _A.YES, _T.TOTAL, _M.MEDIUM): _O.ACT,          # 34
    (_E.ACTIVE, _A.YES, _T.TOTAL, _M.HIGH): _O.ACT,            # 35
}

_EnumT = TypeVar("_EnumT", bound=Enum)

# Spellings accepted in addition to the enum values themselves.
_ALIASES: Dict[Type[Enum], Dict[str, str]] = {
    CisaExploitation: {"public poc": "poc", "public_poc": "poc", "poc_public": "poc"},
    CisaAutomatable: {"true": "yes", "false": "no"},
}


def _coerce(enum_cls: Type[_EnumT], value: Any, name: str) -> _EnumT:
    """Normalise a string, bool or enum member to ``enum_cls``.

    Unknown values raise ``ValueError`` rather than falling back to a
    default, because a silent fallback would yield a wrong decision.
    """
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, bool):
        token = "true" if value else "false"
    elif isinstance(value, Enum):
        token = str(value.value)
    else:
        token = str(value)
    token = token.strip().lower()
    token = _ALIASES.get(enum_cls, {}).get(token, token)
    try:
        return enum_cls(token)
    except ValueError:
        allowed = ", ".join(str(m.value) for m in enum_cls)
        raise ValueError(f"Invalid {name} {value!r}; expected one of: {allowed}") from None


def ssvc_cisa_decide(
    exploitation: Union[CisaExploitation, str],
    automatable: Union[CisaAutomatable, str, bool],
    technical_impact: Union[CisaTechnicalImpact, str],
    mission_wellbeing: Union[CisaMissionWellbeing, str],
) -> CisaOutcome:
    """Return the CISA SSVC outcome for one combination of decision points.

    The function is a lookup in :data:`CISA_COORDINATOR_TABLE` and applies no
    logic of its own, so its output is exactly the published CISA decision.

    Raises
    ------
    ValueError
        If any argument is not a valid value of its decision point.
    """
    key = (
        _coerce(CisaExploitation, exploitation, "exploitation"),
        _coerce(CisaAutomatable, automatable, "automatable"),
        _coerce(CisaTechnicalImpact, technical_impact, "technical_impact"),
        _coerce(CisaMissionWellbeing, mission_wellbeing, "mission_wellbeing"),
    )
    return CISA_COORDINATOR_TABLE[key]


# ── Derivation from VulnTriage data ────────────────────────────────────

@dataclass(frozen=True)
class DerivedPoint:
    """One decision-point value together with how it was obtained."""

    value: str
    provenance: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"value": self.value, "provenance": self.provenance, "detail": self.detail}


@dataclass(frozen=True)
class DerivedDecisionPoints:
    """The four CISA decision points derived for one vulnerability."""

    exploitation: DerivedPoint
    automatable: DerivedPoint
    technical_impact: DerivedPoint
    mission_wellbeing: DerivedPoint

    def decide(self) -> CisaOutcome:
        """Apply the CISA decision table to the derived values."""
        return ssvc_cisa_decide(
            self.exploitation.value,
            self.automatable.value,
            self.technical_impact.value,
            self.mission_wellbeing.value,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the inputs, their provenance and the resulting outcome."""
        return {
            "outcome": self.decide().value,
            "decision_points": {
                "exploitation": self.exploitation.to_dict(),
                "automatable": self.automatable.to_dict(),
                "technical_impact": self.technical_impact.to_dict(),
                "mission_wellbeing": self.mission_wellbeing.to_dict(),
            },
            "table": {
                "name": CISA_SSVC_TABLE_NAME,
                "version": CISA_SSVC_TABLE_VERSION,
                "source": CISA_SSVC_TABLE_SOURCE,
            },
        }


def _parse_cvss3(vector: Optional[str]) -> Optional[Dict[str, str]]:
    """Return the metrics of a CVSS v3.x vector, or ``None`` otherwise.

    Only v3.0 and v3.1 are accepted: the heuristics below are defined on v3
    metric names, and v2 or v4 vectors use different metrics.
    """
    if not vector or not isinstance(vector, str):
        return None
    parts = vector.strip().upper().split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: Dict[str, str] = {}
    for part in parts[1:]:
        key, sep, val = part.partition(":")
        if sep and key and val:
            metrics[key] = val
    return metrics


def _has_all(metrics: Mapping[str, str], keys: Tuple[str, ...]) -> bool:
    return all(k in metrics for k in keys)


_AUTOMATABLE_KEYS = ("AV", "AC", "PR", "UI")
_IMPACT_KEYS = ("C", "I", "A")

_CRITICALITY_TO_MISSION: Dict[str, CisaMissionWellbeing] = {
    "critical": CisaMissionWellbeing.HIGH,
    "high": CisaMissionWellbeing.HIGH,
    "medium": CisaMissionWellbeing.MEDIUM,
    "low": CisaMissionWellbeing.LOW,
}


def _derive_exploitation(in_kev: bool, has_public_poc: bool) -> DerivedPoint:
    if in_kev:
        return DerivedPoint(
            CisaExploitation.ACTIVE.value, PROVENANCE_OBSERVED,
            "Listed in the CISA Known Exploited Vulnerabilities catalog.",
        )
    if has_public_poc:
        return DerivedPoint(
            CisaExploitation.POC.value, PROVENANCE_OBSERVED,
            "Public exploit code recorded (Exploit-DB or Metasploit); not listed in KEV.",
        )
    return DerivedPoint(
        CisaExploitation.NONE.value, PROVENANCE_OBSERVED,
        "No KEV listing and no public exploit code in the ingested sources.",
    )


def _derive_automatable(metrics: Optional[Mapping[str, str]]) -> DerivedPoint:
    if metrics is None or not _has_all(metrics, _AUTOMATABLE_KEYS):
        return DerivedPoint(
            CisaAutomatable.NO.value, PROVENANCE_DEFAULT,
            "No usable CVSS v3 vector; Automatable assumed 'no'.",
        )
    observed = "/".join(f"{k}:{metrics[k]}" for k in _AUTOMATABLE_KEYS)
    if (metrics["AV"], metrics["AC"], metrics["PR"], metrics["UI"]) == ("N", "L", "N", "N"):
        return DerivedPoint(
            CisaAutomatable.YES.value, PROVENANCE_DERIVED,
            f"CVSS v3 {observed}: network vector, low complexity, no privileges, "
            "no user interaction. Heuristic; not a CISA Vulnrichment assessment.",
        )
    return DerivedPoint(
        CisaAutomatable.NO.value, PROVENANCE_DERIVED,
        f"CVSS v3 {observed} does not meet AV:N/AC:L/PR:N/UI:N. "
        "Heuristic; not a CISA Vulnrichment assessment.",
    )


def _derive_technical_impact(metrics: Optional[Mapping[str, str]]) -> DerivedPoint:
    if metrics is None or not _has_all(metrics, _IMPACT_KEYS):
        return DerivedPoint(
            CisaTechnicalImpact.PARTIAL.value, PROVENANCE_DEFAULT,
            "No usable CVSS v3 vector; Technical Impact assumed 'partial'.",
        )
    observed = "/".join(f"{k}:{metrics[k]}" for k in _IMPACT_KEYS)
    if all(metrics[k] == "H" for k in _IMPACT_KEYS):
        return DerivedPoint(
            CisaTechnicalImpact.TOTAL.value, PROVENANCE_DERIVED,
            f"CVSS v3 {observed}: high impact on confidentiality, integrity and "
            "availability. Heuristic; not a CISA Vulnrichment assessment.",
        )
    return DerivedPoint(
        CisaTechnicalImpact.PARTIAL.value, PROVENANCE_DERIVED,
        f"CVSS v3 {observed}: not high on all of confidentiality, integrity and "
        "availability. Heuristic; not a CISA Vulnrichment assessment.",
    )


def _derive_mission_wellbeing(asset_criticality: Any) -> DerivedPoint:
    if asset_criticality is None:
        return DerivedPoint(
            CisaMissionWellbeing.MEDIUM.value, PROVENANCE_DEFAULT,
            "No asset context; Mission and Well-Being Impact assumed 'medium'.",
        )
    raw = asset_criticality.value if isinstance(asset_criticality, Enum) else asset_criticality
    token = str(raw).strip().lower()
    if token not in _CRITICALITY_TO_MISSION:
        allowed = ", ".join(_CRITICALITY_TO_MISSION)
        raise ValueError(
            f"Invalid asset_criticality {asset_criticality!r}; expected one of: {allowed}"
        )
    mission = _CRITICALITY_TO_MISSION[token]
    return DerivedPoint(
        mission.value, PROVENANCE_DERIVED,
        f"Mapped from asset criticality '{token}'.",
    )


def derive_decision_points(
    *,
    in_kev: bool,
    has_public_poc: bool,
    cvss_vector: Optional[str],
    asset_criticality: Any = None,
) -> DerivedDecisionPoints:
    """Derive the four CISA decision points from data VulnTriage holds.

    Parameters
    ----------
    in_kev : bool
        The CVE is listed in the CISA KEV catalog (Exploitation = active).
    has_public_poc : bool
        Public exploit code is recorded, e.g. an Exploit-DB entry or a
        Metasploit module (Exploitation = poc when not in KEV).
    cvss_vector : str, optional
        CVSS vector string.  Only v3.0 and v3.1 vectors are interpreted.
        Automatable is 'yes' for AV:N/AC:L/PR:N/UI:N; Technical Impact is
        'total' for C:H/I:H/A:H.  With any other or missing vector both take
        the less urgent value ('no', 'partial') and are marked as a default
        assumption.
    asset_criticality : str or Enum, optional
        ``critical`` and ``high`` map to high, ``medium`` to medium and
        ``low`` to low.  ``None`` (no asset) yields medium, marked as a
        default assumption.

    Returns
    -------
    DerivedDecisionPoints
        Each value with a provenance of :data:`PROVENANCE_OBSERVED`,
        :data:`PROVENANCE_DERIVED` or :data:`PROVENANCE_DEFAULT`.
    """
    metrics = _parse_cvss3(cvss_vector)
    return DerivedDecisionPoints(
        exploitation=_derive_exploitation(bool(in_kev), bool(has_public_poc)),
        automatable=_derive_automatable(metrics),
        technical_impact=_derive_technical_impact(metrics),
        mission_wellbeing=_derive_mission_wellbeing(asset_criticality),
    )


__all__ = [
    "CISA_COORDINATOR_TABLE",
    "CISA_SSVC_TABLE_NAME",
    "CISA_SSVC_TABLE_SOURCE",
    "CISA_SSVC_TABLE_VERSION",
    "CisaAutomatable",
    "CisaExploitation",
    "CisaMissionWellbeing",
    "CisaOutcome",
    "CisaTechnicalImpact",
    "DerivedDecisionPoints",
    "DerivedPoint",
    "PROVENANCE_DEFAULT",
    "PROVENANCE_DERIVED",
    "PROVENANCE_OBSERVED",
    "derive_decision_points",
    "ssvc_cisa_decide",
]
