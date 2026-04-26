"""Policy engine — wires DB observations to the SSVC-inspired decision tree.

This module bridges the gap between raw observation tables and the
deterministic ``decide()`` function in ``schemas/decision.py``.

It queries the 5-layer evidence hierarchy from the database, maps
observation rows into :class:`EvidenceInput` objects, and invokes
the decision tree to produce auditable :class:`DecisionOutput` results.

Thresholds and SLA values are loaded from ``app/core/policy_config.yaml``
if present, falling back to sensible defaults.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.asset_models import (
    Asset,
    AssetSoftwareObs,
    ControlObs,
    DecisionObs,
    ReachabilityObs,
    VexStatementObs,
)
from app.db.models import SignalObservation, Vulnerability
from app.schemas.decision import (
    Action,
    Affectedness,
    ControlStatus,
    Criticality,
    DecisionOutput,
    EvidenceInput,
    Exploitation,
    Reachability,
    SLA_HOURS,
    decide,
)

log = get_logger(__name__)


# ── Policy configuration ────────────────────────────────────────────

_CONFIG_PATH = Path(__file__).resolve().parent.parent / "core" / "policy_config.yaml"

_DEFAULT_CONFIG: Dict[str, Any] = {
    "thresholds": {
        "epss_high": 0.5,
        "epss_moderate": 0.1,
        "cvss_critical": 9.0,
        "cvss_high": 7.0,
        "ml_exploit_high": 0.7,
        "control_full_effectiveness": 0.9,
        "control_partial_effectiveness": 0.3,
    },
    "sla_hours": {
        "patch_now": 24,
        "mitigate_now": 24,
        "patch_window": 720,
        "monitor": 2160,
        "accept": 8760,
    },
    "policy": {
        "name": "ssvc_v1",
        "version": "1.0",
    },
}


def load_policy_config() -> Dict[str, Any]:
    """Load policy config from YAML file, with defaults fallback."""
    if _CONFIG_PATH.exists():
        try:
            with open(_CONFIG_PATH) as f:
                user_config = yaml.safe_load(f) or {}
            # Merge with defaults (user overrides take precedence)
            config = _DEFAULT_CONFIG.copy()
            for section in ("thresholds", "sla_hours", "policy"):
                if section in user_config:
                    config[section] = {**config[section], **user_config[section]}
            return config
        except Exception as e:
            log.warning("policy_config_load_error", error=str(e))
    return _DEFAULT_CONFIG.copy()


# ── Single asset×CVE scoring ────────────────────────────────────────

def build_evidence_input(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    *,
    ml_exploit_prob: Optional[float] = None,
    config: Optional[Dict[str, Any]] = None,
) -> EvidenceInput:
    """Populate an EvidenceInput from database observations.

    Parameters
    ----------
    asset : Asset
        Organizational asset.
    vuln : Vulnerability
        Vulnerability record.
    session : Session
        DB session for querying observations.
    asof : date
        Temporal cutoff for observation filtering.
    ml_exploit_prob : float, optional
        ML model's predicted exploit probability for this CVE.
    config : dict, optional
        Policy configuration (thresholds). If None, loads from file/defaults.

    Returns
    -------
    EvidenceInput
        Fully populated evidence for the decision tree.
    """
    if config is None:
        config = load_policy_config()
    thresholds = config["thresholds"]

    # ── Layer A: Affectedness ────────────────────────────────────────
    affectedness, vex_status = _resolve_affectedness(asset, vuln, session, asof)

    # ── Layer B: Reachability ────────────────────────────────────────
    reachability = _resolve_reachability(asset, vuln, session, asof)

    # ── Layer C: Weaponization ───────────────────────────────────────
    exploitation, epss_score = _resolve_weaponization(vuln, session, asof)

    # ── Layer D: Controls ────────────────────────────────────────────
    control_status, control_effectiveness = _resolve_controls(
        asset, vuln, session, asof, thresholds
    )

    # ── Asset context ────────────────────────────────────────────────
    criticality_map = {
        "critical": Criticality.CRITICAL,
        "high": Criticality.HIGH,
        "medium": Criticality.MEDIUM,
        "low": Criticality.LOW,
    }
    asset_criticality = criticality_map.get(
        (asset.criticality or "medium").lower(),
        Criticality.MEDIUM,
    )

    days_since = 0
    if vuln.published_at:
        pub_date = vuln.published_at.date() if isinstance(vuln.published_at, datetime) else vuln.published_at
        if pub_date <= asof:
            days_since = (asof - pub_date).days

    return EvidenceInput(
        affectedness=affectedness,
        vex_status=vex_status,
        reachability=reachability,
        is_internet_facing=bool(asset.is_internet_facing),
        exploitation=exploitation,
        epss_score=epss_score,
        ml_exploit_prob=ml_exploit_prob,
        days_since_published=days_since,
        control_status=control_status,
        control_effectiveness=control_effectiveness,
        asset_criticality=asset_criticality,
        cvss_base_score=vuln.cvss_base_score or 0.0,
    )


def score_asset_cve(
    asset_id: Any,
    cve_id: str,
    session: Session,
    asof: date,
    *,
    ml_exploit_prob: Optional[float] = None,
    persist: bool = True,
) -> DecisionOutput:
    """Score a single (asset, CVE) pair and optionally persist the decision.

    Parameters
    ----------
    asset_id : UUID
        Asset identifier.
    cve_id : str
        CVE identifier (e.g., "CVE-2024-1234").
    session : Session
        DB session.
    asof : date
        Temporal cutoff.
    ml_exploit_prob : float, optional
        ML-predicted exploit probability.
    persist : bool
        If True, write a DecisionObs row to the database.

    Returns
    -------
    DecisionOutput
        Decision with action, confidence, SLA, and rationale.
    """
    asset = session.query(Asset).filter(Asset.id == asset_id).one_or_none()
    if asset is None:
        raise ValueError(f"Asset {asset_id} not found")

    vuln = session.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).one_or_none()
    if vuln is None:
        raise ValueError(f"Vulnerability {cve_id} not found")

    evidence = build_evidence_input(
        asset, vuln, session, asof, ml_exploit_prob=ml_exploit_prob,
    )
    decision = decide(evidence)

    if persist:
        _persist_decision(asset, vuln, decision, session)

    return decision


def score_batch(
    asset_cve_pairs: List[Tuple[Any, str]],
    session: Session,
    asof: date,
    *,
    ml_probs: Optional[Dict[str, float]] = None,
    persist: bool = True,
) -> List[Dict[str, Any]]:
    """Score multiple (asset_id, cve_id) pairs.

    Parameters
    ----------
    asset_cve_pairs : list of (asset_id, cve_id)
        Pairs to score.
    session : Session
        DB session.
    asof : date
        Temporal cutoff.
    ml_probs : dict, optional
        Mapping from cve_id → ML exploit probability.
    persist : bool
        If True, persist DecisionObs rows.

    Returns
    -------
    list[dict]
        One dict per pair with asset_id, cve_id, action, confidence, rationale.
    """
    config = load_policy_config()

    # Pre-fetch assets and vulns
    asset_ids = list({pair[0] for pair in asset_cve_pairs})
    cve_ids_list = list({pair[1] for pair in asset_cve_pairs})

    assets_by_id = {
        a.id: a
        for a in session.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    }
    vulns_by_cve = {
        v.cve_id: v
        for v in session.query(Vulnerability).filter(
            Vulnerability.cve_id.in_(cve_ids_list)
        ).all()
    }

    results: List[Dict[str, Any]] = []
    for asset_id, cve_id in asset_cve_pairs:
        asset = assets_by_id.get(asset_id)
        vuln = vulns_by_cve.get(cve_id)

        if asset is None or vuln is None:
            log.warning("pair_not_found", asset_id=str(asset_id), cve_id=cve_id)
            continue

        ml_prob = (ml_probs or {}).get(cve_id)
        evidence = build_evidence_input(
            asset, vuln, session, asof,
            ml_exploit_prob=ml_prob, config=config,
        )
        decision = decide(evidence)

        if persist:
            _persist_decision(asset, vuln, decision, session)

        results.append({
            "asset_id": str(asset.id),
            "asset_name": asset.name,
            "cve_id": cve_id,
            "action": decision.action.value if hasattr(decision.action, "value") else decision.action,
            "confidence": decision.confidence,
            "sla_hours": decision.sla_hours,
            "rationale": decision.rationale,
        })

    session.commit()
    log.info("batch_scored", total=len(results))
    return results


# ── Layer resolvers ──────────────────────────────────────────────────

def _resolve_affectedness(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
) -> Tuple[Affectedness, Optional[str]]:
    """Determine affectedness from VEX statements and SBOM matches."""
    # Check VEX statements
    vex_obs = (
        session.query(VexStatementObs)
        .filter(
            VexStatementObs.vulnerability_id == vuln.id,
            VexStatementObs.observed_at <= asof,
        )
        .order_by(VexStatementObs.observed_at.desc())
        .all()
    )

    # If asset_id-specific VEX exists, prefer it
    asset_vex = [v for v in vex_obs if v.asset_id == asset.id]
    best_vex = asset_vex[0] if asset_vex else (vex_obs[0] if vex_obs else None)

    if best_vex:
        status_map = {
            "not_affected": Affectedness.NOT_AFFECTED,
            "affected": Affectedness.AFFECTED,
            "under_investigation": Affectedness.UNDER_INVESTIGATION,
            "fixed": Affectedness.NOT_AFFECTED,  # fixed = no longer affected
        }
        return (
            status_map.get(best_vex.status, Affectedness.UNKNOWN),
            best_vex.status,
        )

    # Check SBOM for product match
    from app.features.actionability import _extract_vuln_products
    vuln_products = _extract_vuln_products(vuln)
    if vuln_products:
        sw_match = (
            session.query(AssetSoftwareObs)
            .filter(
                AssetSoftwareObs.asset_id == asset.id,
                AssetSoftwareObs.observed_at <= asof,
            )
            .all()
        )
        for sw in sw_match:
            if (sw.vendor.lower(), sw.product.lower()) in vuln_products:
                return Affectedness.AFFECTED, "sbom_match"

    return Affectedness.UNKNOWN, None


def _resolve_reachability(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
) -> Reachability:
    """Determine reachability from observation records."""
    reach_obs = (
        session.query(ReachabilityObs)
        .filter(
            ReachabilityObs.asset_id == asset.id,
            ReachabilityObs.vulnerability_id == vuln.id,
            ReachabilityObs.observed_at <= asof,
        )
        .order_by(ReachabilityObs.observed_at.desc())
        .all()
    )

    if not reach_obs:
        # Infer from asset properties
        if asset.is_internet_facing:
            return Reachability.PARTIALLY
        return Reachability.UNKNOWN

    # Latest observation wins
    latest = reach_obs[0]
    if latest.is_reachable:
        return Reachability.REACHABLE
    else:
        return Reachability.UNREACHABLE


def _resolve_weaponization(
    vuln: Vulnerability,
    session: Session,
    asof: date,
) -> Tuple[Exploitation, float]:
    """Determine exploitation state from signal observations."""
    signals = (
        session.query(SignalObservation)
        .filter(
            SignalObservation.vulnerability_id == vuln.id,
            SignalObservation.observed_at <= asof,
        )
        .all()
    )

    has_kev = False
    has_poc = False
    has_msf = False
    epss_score = 0.0

    for sig in signals:
        if sig.signal_type == "kev" and sig.value_bool:
            has_kev = True
        elif sig.signal_type == "poc_exploitdb" and sig.value_bool:
            has_poc = True
        elif sig.signal_type == "metasploit" and sig.value_bool:
            has_msf = True
        elif sig.signal_type == "epss" and sig.value_num is not None:
            epss_score = max(epss_score, sig.value_num)

    if has_kev:
        return Exploitation.ACTIVE, epss_score
    elif has_poc or has_msf:
        return Exploitation.POC_PUBLIC, epss_score
    elif epss_score > 0.0:
        return Exploitation.THEORETICAL, epss_score
    else:
        return Exploitation.NONE, epss_score


def _resolve_controls(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    thresholds: Dict[str, float],
) -> Tuple[ControlStatus, float]:
    """Determine control status from control observations."""
    ctrl_obs = (
        session.query(ControlObs)
        .filter(
            ControlObs.asset_id == asset.id,
            ControlObs.observed_at <= asof,
        )
        .filter(
            (ControlObs.vulnerability_id == vuln.id)
            | (ControlObs.vulnerability_id.is_(None))
        )
        .all()
    )

    if not ctrl_obs:
        return ControlStatus.NO_CONTROLS, 0.0

    active_controls = [c for c in ctrl_obs if c.is_active]
    if not active_controls:
        return ControlStatus.NO_CONTROLS, 0.0

    # Compute aggregate effectiveness
    effectiveness_values = [
        c.effectiveness for c in active_controls
        if c.effectiveness is not None
    ]
    if effectiveness_values:
        # Use max effectiveness (best control)
        best_eff = max(effectiveness_values)
    else:
        best_eff = 0.5  # default when no effectiveness data

    full_threshold = thresholds.get("control_full_effectiveness", 0.9)
    partial_threshold = thresholds.get("control_partial_effectiveness", 0.3)

    if best_eff >= full_threshold:
        return ControlStatus.FULLY_MITIGATED, best_eff
    elif best_eff >= partial_threshold:
        return ControlStatus.PARTIALLY_MITIGATED, best_eff
    else:
        return ControlStatus.NO_CONTROLS, best_eff


# ── Persistence ──────────────────────────────────────────────────────

def _persist_decision(
    asset: Asset,
    vuln: Vulnerability,
    decision: DecisionOutput,
    session: Session,
) -> None:
    """Write a DecisionObs row to the database."""
    action_value = decision.action.value if hasattr(decision.action, "value") else decision.action
    sla_deadline = None
    if decision.sla_hours:
        sla_deadline = datetime.utcnow() + __import__("datetime").timedelta(hours=decision.sla_hours)

    obs = DecisionObs(
        asset_id=asset.id,
        vulnerability_id=vuln.id,
        action=action_value,
        confidence=decision.confidence,
        evidence_chain_json=decision.evidence_summary,
        policy_name=decision.policy_name,
        policy_version=decision.policy_version,
        sla_deadline=sla_deadline,
    )
    session.add(obs)
