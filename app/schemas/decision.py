"""SSVC-inspired decision policy engine.

Transforms 5-layer evidence into a concrete defender action using
deterministic, auditable rules.  This is NOT an ML model — it is the
policy layer that sits on top of ML predictions and contextual evidence.

Decision Taxonomy
-----------------
- **patch_now**:     Apply vendor patch immediately.  SLA: 24 hours.
- **mitigate_now**:  Apply compensating control immediately.  SLA: 24 hours.
- **patch_window**:  Schedule patch in next maintenance window.  SLA: 7–30 days.
- **monitor**:       Add to watch list, re-evaluate periodically.
- **accept**:        Risk accepted with documentation.

Evidence Model
--------------
::

    Layer A: Affectedness  →  Is this asset running the vulnerable software?
    Layer B: Reachability  →  Can an attacker reach the vulnerable code?
    Layer C: Weaponization →  Does exploit code exist? Is it in-the-wild?
    Layer D: Controls      →  Are compensating controls already in place?
    Layer E: Decision      →  What should the defender do?

Policy Rules
------------
The decision tree follows SSVC principles but is adapted for ML-augmented
input.  The tree is deterministic given the evidence inputs — no
randomness, no learned weights.  This makes it auditable and explainable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.core.logging import get_logger

log = get_logger(__name__)


# ── Enums ──────────────────────────────────────────────────────────────

class Action(str, Enum):
    """Triage action — ordered by urgency (most urgent first)."""
    PATCH_NOW = "patch_now"
    MITIGATE_NOW = "mitigate_now"
    PATCH_WINDOW = "patch_window"
    MONITOR = "monitor"
    ACCEPT = "accept"


class Criticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Exploitation(str, Enum):
    """Weaponization state."""
    ACTIVE = "active"          # In-the-wild (KEV or confirmed attack)
    POC_PUBLIC = "poc_public"  # PoC exists publicly
    THEORETICAL = "theoretical"  # No known exploit code
    NONE = "none"


class Reachability(str, Enum):
    REACHABLE = "reachable"
    PARTIALLY = "partially"  # Behind controls but not fully blocked
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class Affectedness(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"
    UNKNOWN = "unknown"


class ControlStatus(str, Enum):
    FULLY_MITIGATED = "fully_mitigated"      # Control effectiveness ≥ 0.9
    PARTIALLY_MITIGATED = "partially_mitigated"  # 0.3 ≤ effectiveness < 0.9
    NO_CONTROLS = "no_controls"
    UNKNOWN = "unknown"


# ── Evidence Input ─────────────────────────────────────────────────────

class EvidenceInput(BaseModel):
    """Structured input to the decision engine.

    Each field corresponds to one evidence layer.  Fields can be
    populated from DB observations or from ML predictions.
    """
    # Layer A: Affectedness
    affectedness: Affectedness = Affectedness.UNKNOWN
    vex_status: Optional[str] = None  # "not_affected", "affected", "fixed"

    # Layer B: Reachability
    reachability: Reachability = Reachability.UNKNOWN
    is_internet_facing: bool = False

    # Layer C: Weaponization
    exploitation: Exploitation = Exploitation.NONE
    epss_score: float = 0.0
    ml_exploit_prob: Optional[float] = None  # from our model
    days_since_published: int = 0

    # Layer D: Controls
    control_status: ControlStatus = ControlStatus.UNKNOWN
    control_effectiveness: float = 0.0

    # Asset context
    asset_criticality: Criticality = Criticality.MEDIUM
    cvss_base_score: float = 0.0

    class Config:
        use_enum_values = True


# ── Decision Output ────────────────────────────────────────────────────

class DecisionOutput(BaseModel):
    """Structured output from the decision engine."""

    action: Action
    confidence: float = Field(ge=0.0, le=1.0)
    sla_hours: Optional[int] = None
    rationale: List[str] = Field(default_factory=list)
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    policy_name: str = "ssvc_v1"
    policy_version: str = "1.0"

    class Config:
        use_enum_values = True


# ── SLA mapping ────────────────────────────────────────────────────────

SLA_HOURS: Dict[str, int] = {
    Action.PATCH_NOW: 24,
    Action.MITIGATE_NOW: 24,
    Action.PATCH_WINDOW: 720,   # 30 days
    Action.MONITOR: 2160,       # 90 days (re-evaluate)
    Action.ACCEPT: 8760,        # 1 year (annual review)
}


# ── Decision Tree ──────────────────────────────────────────────────────

def decide(evidence: EvidenceInput) -> DecisionOutput:
    """Apply the SSVC-inspired decision tree to produce a triage action.

    The tree is evaluated top-down.  First applicable rule wins.

    Parameters
    ----------
    evidence : EvidenceInput
        Populated evidence from all 5 layers.

    Returns
    -------
    DecisionOutput
        Action, confidence, SLA, and rationale.
    """
    rationale: List[str] = []

    # ── Gate 0: VEX Not-Affected ─────────────────────────────────────
    if evidence.affectedness == Affectedness.NOT_AFFECTED:
        rationale.append("VEX status: not_affected — vendor confirms no impact")
        return DecisionOutput(
            action=Action.ACCEPT,
            confidence=0.95,
            sla_hours=SLA_HOURS[Action.ACCEPT],
            rationale=rationale,
            evidence_summary=_build_summary(evidence),
        )

    # ── Gate 1: Affectedness unknown → lower confidence ──────────────
    affectedness_known = evidence.affectedness in (
        Affectedness.AFFECTED,
        Affectedness.NOT_AFFECTED,
    )
    if not affectedness_known:
        rationale.append("Affectedness unknown — assuming potentially affected")

    # ── Gate 2: Active exploitation (KEV / confirmed in-the-wild) ────
    if evidence.exploitation == Exploitation.ACTIVE:
        rationale.append("Active exploitation detected (CISA KEV or confirmed)")

        if evidence.asset_criticality in (Criticality.CRITICAL, Criticality.HIGH):
            rationale.append(f"Asset criticality: {evidence.asset_criticality}")

            if evidence.control_status == ControlStatus.FULLY_MITIGATED:
                rationale.append("Compensating control fully mitigating — patch in window")
                return DecisionOutput(
                    action=Action.PATCH_WINDOW,
                    confidence=0.85,
                    sla_hours=SLA_HOURS[Action.PATCH_WINDOW],
                    rationale=rationale,
                    evidence_summary=_build_summary(evidence),
                )
            else:
                rationale.append("No full mitigation — PATCH NOW")
                return DecisionOutput(
                    action=Action.PATCH_NOW,
                    confidence=0.95,
                    sla_hours=SLA_HOURS[Action.PATCH_NOW],
                    rationale=rationale,
                    evidence_summary=_build_summary(evidence),
                )
        else:
            # Medium/Low criticality asset with active exploitation
            if evidence.control_status == ControlStatus.FULLY_MITIGATED:
                rationale.append("Lower criticality + full control → monitor")
                return DecisionOutput(
                    action=Action.MONITOR,
                    confidence=0.80,
                    sla_hours=SLA_HOURS[Action.MONITOR],
                    rationale=rationale,
                    evidence_summary=_build_summary(evidence),
                )
            else:
                rationale.append("Active exploit on unmitigated asset → mitigate now")
                return DecisionOutput(
                    action=Action.MITIGATE_NOW,
                    confidence=0.90,
                    sla_hours=SLA_HOURS[Action.MITIGATE_NOW],
                    rationale=rationale,
                    evidence_summary=_build_summary(evidence),
                )

    # ── Gate 3: PoC exists publicly ──────────────────────────────────
    if evidence.exploitation == Exploitation.POC_PUBLIC:
        rationale.append("Public PoC / exploit code exists")

        high_risk = (
            evidence.cvss_base_score >= 9.0
            or (evidence.ml_exploit_prob is not None and evidence.ml_exploit_prob >= 0.7)
            or evidence.epss_score >= 0.5
        )

        if high_risk and evidence.asset_criticality in (Criticality.CRITICAL, Criticality.HIGH):
            if evidence.reachability == Reachability.REACHABLE:
                rationale.append("High risk + reachable + critical asset → patch now")
                return DecisionOutput(
                    action=Action.PATCH_NOW,
                    confidence=0.85,
                    sla_hours=SLA_HOURS[Action.PATCH_NOW],
                    rationale=rationale,
                    evidence_summary=_build_summary(evidence),
                )
            else:
                rationale.append("High risk but not confirmed reachable → mitigate now")
                return DecisionOutput(
                    action=Action.MITIGATE_NOW,
                    confidence=0.80,
                    sla_hours=SLA_HOURS[Action.MITIGATE_NOW],
                    rationale=rationale,
                    evidence_summary=_build_summary(evidence),
                )
        else:
            rationale.append("PoC exists but risk profile is moderate → patch window")
            return DecisionOutput(
                action=Action.PATCH_WINDOW,
                confidence=0.75,
                sla_hours=SLA_HOURS[Action.PATCH_WINDOW],
                rationale=rationale,
                evidence_summary=_build_summary(evidence),
            )

    # ── Gate 4: No known exploit — use ML + CVSS + EPSS ──────────────
    rationale.append("No known exploit code")

    # Compute a risk score from available signals
    risk_score = _compute_risk_score(evidence)
    rationale.append(f"Computed risk score: {risk_score:.3f}")

    if risk_score >= 0.7:
        if evidence.asset_criticality in (Criticality.CRITICAL, Criticality.HIGH):
            rationale.append("High risk score + critical asset → patch window")
            return DecisionOutput(
                action=Action.PATCH_WINDOW,
                confidence=0.70,
                sla_hours=SLA_HOURS[Action.PATCH_WINDOW],
                rationale=rationale,
                evidence_summary=_build_summary(evidence),
            )
        else:
            rationale.append("High risk score + lower criticality → monitor")
            return DecisionOutput(
                action=Action.MONITOR,
                confidence=0.65,
                sla_hours=SLA_HOURS[Action.MONITOR],
                rationale=rationale,
                evidence_summary=_build_summary(evidence),
            )
    elif risk_score >= 0.3:
        rationale.append("Moderate risk score → monitor")
        return DecisionOutput(
            action=Action.MONITOR,
            confidence=0.60,
            sla_hours=SLA_HOURS[Action.MONITOR],
            rationale=rationale,
            evidence_summary=_build_summary(evidence),
        )
    else:
        rationale.append("Low risk score → accept")
        return DecisionOutput(
            action=Action.ACCEPT,
            confidence=0.70,
            sla_hours=SLA_HOURS[Action.ACCEPT],
            rationale=rationale,
            evidence_summary=_build_summary(evidence),
        )


# ── Helpers ────────────────────────────────────────────────────────────

def _compute_risk_score(evidence: EvidenceInput) -> float:
    """Compute a simple weighted risk score from available signals.

    NOT an ML model — just a deterministic combination for the
    decision tree's "no exploit" branch.
    """
    score = 0.0

    # CVSS contribution (0–0.3)
    score += 0.3 * min(evidence.cvss_base_score / 10.0, 1.0)

    # EPSS contribution (0–0.3)
    score += 0.3 * evidence.epss_score

    # ML prediction contribution (0–0.3)
    if evidence.ml_exploit_prob is not None:
        score += 0.3 * evidence.ml_exploit_prob
    else:
        # If no ML prediction, redistribute to CVSS and EPSS
        score += 0.15 * min(evidence.cvss_base_score / 10.0, 1.0)
        score += 0.15 * evidence.epss_score

    # Reachability modifier (0–0.1)
    if evidence.reachability == Reachability.REACHABLE:
        score += 0.10
    elif evidence.reachability == Reachability.PARTIALLY:
        score += 0.05

    # Control reduction
    if evidence.control_status == ControlStatus.FULLY_MITIGATED:
        score *= 0.3  # Major reduction
    elif evidence.control_status == ControlStatus.PARTIALLY_MITIGATED:
        score *= (1.0 - 0.5 * evidence.control_effectiveness)

    return min(score, 1.0)


def _build_summary(evidence: EvidenceInput) -> Dict[str, Any]:
    """Build a structured evidence summary for the decision record."""
    return {
        "affectedness": {
            "status": evidence.affectedness,
            "vex": evidence.vex_status,
        },
        "reachability": {
            "status": evidence.reachability,
            "internet_facing": evidence.is_internet_facing,
        },
        "weaponization": {
            "exploitation": evidence.exploitation,
            "epss": evidence.epss_score,
            "ml_prob": evidence.ml_exploit_prob,
        },
        "controls": {
            "status": evidence.control_status,
            "effectiveness": evidence.control_effectiveness,
        },
        "asset": {
            "criticality": evidence.asset_criticality,
            "cvss": evidence.cvss_base_score,
        },
    }


# ── Batch decision ─────────────────────────────────────────────────────

def decide_batch(
    evidence_list: List[EvidenceInput],
) -> List[DecisionOutput]:
    """Apply decision policy to a batch of evidence inputs.

    Parameters
    ----------
    evidence_list : list[EvidenceInput]
        One EvidenceInput per (asset, vulnerability) pair.

    Returns
    -------
    list[DecisionOutput]
        Corresponding decisions.
    """
    results = []
    for ev in evidence_list:
        results.append(decide(ev))

    # Log distribution
    from collections import Counter
    dist = Counter(d.action for d in results)
    log.info(
        "batch_decisions",
        total=len(results),
        distribution={k.value if hasattr(k, 'value') else k: v for k, v in dist.items()},
    )
    return results


# ── Policy introspection ──────────────────────────────────────────────

def get_policy_description() -> Dict[str, Any]:
    """Return a human-readable description of the decision policy."""
    return {
        "name": "ssvc_v1",
        "version": "1.0",
        "description": (
            "SSVC-inspired deterministic decision tree combining "
            "5 evidence layers (Affectedness, Reachability, Weaponization, "
            "Controls, Asset Criticality) into 5 actionable outcomes."
        ),
        "actions": {
            a.value: {
                "sla_hours": SLA_HOURS[a],
                "sla_human": f"{SLA_HOURS[a] // 24} days" if SLA_HOURS[a] >= 24 else f"{SLA_HOURS[a]}h",
            }
            for a in Action
        },
        "decision_tree_gates": [
            "Gate 0: VEX Not-Affected → ACCEPT",
            "Gate 1: Affectedness check",
            "Gate 2: Active exploitation (KEV) → PATCH_NOW / MITIGATE_NOW",
            "Gate 3: Public PoC → PATCH_NOW / MITIGATE_NOW / PATCH_WINDOW",
            "Gate 4: No exploit → risk score → PATCH_WINDOW / MONITOR / ACCEPT",
        ],
    }
