"""Asset-level label builder — ground truth for actionability evaluation.

Produces 4 label types for (asset, vulnerability) pairs:

1. **affected_asset_label** — Is the asset actually running the vulnerable
   software?  Derived from SBOM + VEX with provenance.
2. **reachable_label** — Is the vulnerable code path reachable on this
   asset?  Derived from reachability observations.
3. **control_gap_label** — Are compensating controls insufficient?
   Derived from control observations vs. effectiveness thresholds.
4. **action_required_label** — Composite: should the defender take
   action?  Combines affectedness, reachability, weaponization, and
   control evidence into a binary "requires action" signal.

Circularity Prevention
----------------------
- Control observations are NOT used as features if ``control_gap_label``
  is the training target.
- Reachability observations are NOT used as features if
  ``reachable_label`` is the training target.
- All labels record provenance (source observations, timestamps).
"""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.asset_models import (
    Asset,
    AssetSoftwareObs,
    ControlObs,
    ReachabilityObs,
    VexStatementObs,
)
from app.db.models import SignalObservation, Vulnerability
from app.features.actionability import _extract_vuln_products

log = get_logger(__name__)


# ── Label types and their circularity exclusion sets ─────────────────

LABEL_POLICIES: Dict[str, Dict[str, Any]] = {
    "affected_asset": {
        "description": "Is the asset running the affected software?",
        "excluded_features": frozenset({
            "affected_product_confirmed",
            "sbom_match_confidence",
            "vex_status_enum",
        }),
        "label_column": "affected_asset_label",
    },
    "reachable": {
        "description": "Is the vulnerable code path reachable on this asset?",
        "excluded_features": frozenset({
            "network_reachable_flag",
            "code_path_reachable",
            # internet_facing_flag is an asset property, not an observation → OK
        }),
        "label_column": "reachable_label",
    },
    "control_gap": {
        "description": "Are compensating controls insufficient for this vulnerability?",
        "excluded_features": frozenset({
            "has_waf",
            "has_edr",
            "has_ips",
            "has_network_segmentation",
            "control_coverage_score",
        }),
        "label_column": "control_gap_label",
    },
    "action_required": {
        "description": "Composite: should the defender take action?",
        "excluded_features": frozenset(),  # uses decision engine; no direct circularity
        "label_column": "action_required_label",
    },
}


def get_excluded_features_for_label(label_policy: str) -> frozenset:
    """Return features that must be excluded to prevent circularity."""
    policy = LABEL_POLICIES.get(label_policy)
    if policy is None:
        raise ValueError(f"Unknown label policy: {label_policy}. "
                         f"Available: {sorted(LABEL_POLICIES.keys())}")
    return policy["excluded_features"]


# ── Label builders ──────────────────────────────────────────────────

def build_affected_asset_label(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
) -> Dict[str, Any]:
    """Determine if asset is affected by the vulnerability.

    Returns
    -------
    dict
        Keys: label (0/1), confidence, provenance.
    """
    # Check VEX statements first (highest authority)
    vex_obs = (
        session.query(VexStatementObs)
        .filter(
            VexStatementObs.vulnerability_id == vuln.id,
            VexStatementObs.observed_at <= asof,
        )
        .order_by(VexStatementObs.observed_at.desc())
        .all()
    )

    # Asset-specific VEX takes precedence
    asset_vex = [v for v in vex_obs if v.asset_id == asset.id]
    if asset_vex:
        v = asset_vex[0]
        if v.status == "not_affected":
            return {"label": 0, "confidence": 0.95, "provenance": f"vex:{v.source}:not_affected"}
        elif v.status in ("affected", "under_investigation"):
            return {"label": 1, "confidence": 0.90, "provenance": f"vex:{v.source}:{v.status}"}

    # CVE-level VEX
    if vex_obs:
        v = vex_obs[0]
        if v.status == "not_affected":
            return {"label": 0, "confidence": 0.80, "provenance": f"vex_cve_level:{v.source}:not_affected"}
        elif v.status == "affected":
            return {"label": 1, "confidence": 0.80, "provenance": f"vex_cve_level:{v.source}:affected"}

    # Fall back to SBOM product matching
    vuln_products = _extract_vuln_products(vuln)
    if vuln_products:
        sw_obs = (
            session.query(AssetSoftwareObs)
            .filter(
                AssetSoftwareObs.asset_id == asset.id,
                AssetSoftwareObs.observed_at <= asof,
            )
            .all()
        )
        for sw in sw_obs:
            if (sw.vendor.lower(), sw.product.lower()) in vuln_products:
                conf = sw.confidence if sw.confidence is not None else 0.7
                return {"label": 1, "confidence": conf, "provenance": f"sbom:{sw.source}:{sw.vendor}/{sw.product}"}

    # No evidence → unknown (labeled as not-affected with low confidence)
    return {"label": 0, "confidence": 0.3, "provenance": "no_evidence"}


def build_reachable_label(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
) -> Dict[str, Any]:
    """Determine if the vulnerability is reachable on this asset."""
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

    if reach_obs:
        latest = reach_obs[0]
        label = 1 if latest.is_reachable else 0
        conf = latest.confidence if latest.confidence is not None else 0.8
        return {
            "label": label,
            "confidence": conf,
            "provenance": f"reachability:{latest.tool}:{latest.reachability_type}",
        }

    # No reachability data — infer from asset properties
    if asset.is_internet_facing:
        return {"label": 1, "confidence": 0.4, "provenance": "inferred:internet_facing"}

    return {"label": 0, "confidence": 0.3, "provenance": "no_evidence"}


def build_control_gap_label(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    *,
    full_threshold: float = 0.9,
) -> Dict[str, Any]:
    """Determine if compensating controls are insufficient.

    Returns label=1 if there's a gap (controls absent or ineffective),
    label=0 if controls fully mitigate the vulnerability.
    """
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
        return {"label": 1, "confidence": 0.5, "provenance": "no_controls"}

    active = [c for c in ctrl_obs if c.is_active]
    if not active:
        return {"label": 1, "confidence": 0.7, "provenance": "controls_inactive"}

    effectiveness_values = [c.effectiveness for c in active if c.effectiveness is not None]
    if effectiveness_values:
        best = max(effectiveness_values)
        if best >= full_threshold:
            return {"label": 0, "confidence": 0.85, "provenance": f"control_effective:{best:.2f}"}
        else:
            return {"label": 1, "confidence": 0.7, "provenance": f"control_insufficient:{best:.2f}"}

    # Controls exist but no effectiveness data
    return {"label": 0, "confidence": 0.4, "provenance": "controls_active_no_effectiveness"}


def build_action_required_label(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
) -> Dict[str, Any]:
    """Composite label: should the defender take action?

    Action required = affected AND (reachable OR no controls) AND
    (weaponization evidence exists).

    This intentionally mirrors the decision engine logic but in a
    simplified, binarized form suitable for ML evaluation.
    """
    affected = build_affected_asset_label(asset, vuln, session, asof)
    reachable = build_reachable_label(asset, vuln, session, asof)
    control_gap = build_control_gap_label(asset, vuln, session, asof)

    # Check weaponization from signals
    signals = (
        session.query(SignalObservation)
        .filter(
            SignalObservation.vulnerability_id == vuln.id,
            SignalObservation.observed_at <= asof,
        )
        .all()
    )
    has_weapon = any(
        (s.signal_type == "kev" and s.value_bool)
        or (s.signal_type == "poc_exploitdb" and s.value_bool)
        or (s.signal_type == "metasploit" and s.value_bool)
        or (s.signal_type == "epss" and s.value_num is not None and s.value_num >= 0.5)
        for s in signals
    )

    # Decision logic
    if affected["label"] == 0 and affected["confidence"] >= 0.8:
        # High-confidence not-affected → no action needed
        label = 0
        confidence = affected["confidence"] * 0.9
        provenance = "not_affected_high_conf"
    elif affected["label"] == 1 and has_weapon:
        if reachable["label"] == 1 or control_gap["label"] == 1:
            label = 1
            confidence = min(affected["confidence"], 0.85)
            provenance = f"affected+weaponized+{'reachable' if reachable['label'] else 'control_gap'}"
        else:
            label = 0
            confidence = 0.6
            provenance = "affected+weaponized_but_mitigated"
    elif affected["label"] == 1 and not has_weapon:
        label = 0
        confidence = 0.5
        provenance = "affected_no_weapon"
    else:
        label = 0
        confidence = 0.3
        provenance = "insufficient_evidence"

    return {
        "label": label,
        "confidence": confidence,
        "provenance": provenance,
        "sub_labels": {
            "affected": affected,
            "reachable": reachable,
            "control_gap": control_gap,
            "weaponized": has_weapon,
        },
    }


# ── Batch label builder ─────────────────────────────────────────────

LABEL_BUILDERS = {
    "affected_asset": build_affected_asset_label,
    "reachable": build_reachable_label,
    "control_gap": build_control_gap_label,
    "action_required": build_action_required_label,
}


def build_all_actionability_labels(
    session: Session,
    asof: date,
    *,
    asset_ids: Optional[List[Any]] = None,
    cve_ids: Optional[List[str]] = None,
    label_types: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Build actionability labels for all (asset, vulnerability) pairs.

    Parameters
    ----------
    session : Session
        Database session.
    asof : date
        Temporal cutoff for observation filtering.
    asset_ids : list, optional
        Filter to specific assets. If None, all assets.
    cve_ids : list, optional
        Filter to specific CVEs. If None, all CVEs.
    label_types : list, optional
        Which label types to build. Defaults to all 4.

    Returns
    -------
    DataFrame
        Columns: asset_id, cve_id, vuln_id, + one column per label type,
        + provenance columns.
    """
    if label_types is None:
        label_types = list(LABEL_BUILDERS.keys())

    for lt in label_types:
        if lt not in LABEL_BUILDERS:
            raise ValueError(f"Unknown label type: {lt}")

    # Load assets
    asset_q = session.query(Asset)
    if asset_ids:
        asset_q = asset_q.filter(Asset.id.in_(asset_ids))
    assets = asset_q.all()

    # Load vulns
    vuln_q = session.query(Vulnerability)
    if cve_ids:
        vuln_q = vuln_q.filter(Vulnerability.cve_id.in_(cve_ids))
    vulns = vuln_q.all()

    log.info("building_actionability_labels",
             n_assets=len(assets), n_vulns=len(vulns), label_types=label_types)

    rows: List[Dict[str, Any]] = []
    for asset in assets:
        for vuln in vulns:
            row: Dict[str, Any] = {
                "asset_id": str(asset.id),
                "asset_name": asset.name,
                "cve_id": vuln.cve_id,
                "vuln_id": str(vuln.id),
            }

            for lt in label_types:
                builder = LABEL_BUILDERS[lt]
                result = builder(asset, vuln, session, asof)
                col = LABEL_POLICIES[lt]["label_column"]
                row[col] = result["label"]
                row[f"{col}_confidence"] = result["confidence"]
                row[f"{col}_provenance"] = result["provenance"]

            rows.append(row)

    df = pd.DataFrame(rows)
    log.info("actionability_labels_built", total_pairs=len(df))

    # Log label distribution
    for lt in label_types:
        col = LABEL_POLICIES[lt]["label_column"]
        if col in df.columns:
            dist = Counter(df[col].values)
            log.info(f"label_distribution_{lt}", distribution=dict(dist))

    return df


def validate_actionability_labels(
    labels_df: pd.DataFrame,
    features_df: pd.DataFrame,
    label_type: str,
) -> Dict[str, Any]:
    """Validate that no circularity exists between features and labels.

    Parameters
    ----------
    labels_df : DataFrame
        Output from build_all_actionability_labels().
    features_df : DataFrame
        Output from build_all_actionability_features().
    label_type : str
        Which label type to validate against.

    Returns
    -------
    dict
        Validation report with pass/fail and details.
    """
    excluded = get_excluded_features_for_label(label_type)
    present_excluded = excluded & set(features_df.columns)

    return {
        "label_type": label_type,
        "excluded_features": sorted(excluded),
        "features_in_df_that_should_be_excluded": sorted(present_excluded),
        "is_valid": len(present_excluded) == 0,
        "recommendation": (
            "PASS — no circularity detected"
            if len(present_excluded) == 0
            else f"FAIL — remove {sorted(present_excluded)} before training"
        ),
    }
