"""Actionability feature builder – asset-level features for the 5-layer evidence hierarchy.

Computes 13+ asset-level features from observation tables, designed to
sit alongside the existing 37 CVE-level features produced by ``builder.py``.

Feature Groups
--------------
- **affectedness** (3): affected_product_confirmed, vex_status_enum, sbom_match_confidence
- **reachability** (3): network_reachable_flag, internet_facing_flag, code_path_reachable
- **controls** (5): has_waf, has_edr, has_ips, has_network_segmentation, control_coverage_score
- **decision_context** (2): asset_criticality_score, days_since_disclosure

All features respect temporal safety (as-of date enforcement).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.asset_models import (
    Asset,
    AssetSoftwareObs,
    ControlObs,
    ReachabilityObs,
    ValidationObs,
    VexStatementObs,
)
from app.db.models import Vulnerability

log = get_logger(__name__)


# ── VEX status → numeric encoding ────────────────────────────────────

VEX_STATUS_MAP: Dict[str, float] = {
    "not_affected": 0.0,
    "under_investigation": 0.25,
    "fixed": 0.5,
    "affected": 1.0,
}

# ── Asset criticality → numeric score ────────────────────────────────

CRITICALITY_SCORE_MAP: Dict[str, float] = {
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}

# ── Control type → canonical key ─────────────────────────────────────

CONTROL_TYPES: List[str] = ["waf", "edr", "ips", "network_segmentation"]


def _to_date(dt: Any) -> Optional[date]:
    """Coerce datetime/date/str to date, or return None."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.date()
    if isinstance(dt, date):
        return dt
    try:
        return pd.to_datetime(dt).date()
    except Exception:
        return None


# ── Single asset×CVE feature builder ────────────────────────────────

def build_actionability_features(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    *,
    prefetched: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compute actionability features for a single (asset, vulnerability) pair.

    Parameters
    ----------
    asset : Asset
        The organizational asset.
    vuln : Vulnerability
        The CVE record.
    session : Session
        DB session (only used if ``prefetched`` is None).
    asof : date
        Temporal cutoff — only observations with observed_at ≤ asof are used.
    prefetched : dict, optional
        Pre-loaded observation data to avoid N+1 queries in batch mode.
        Keys: ``software_obs``, ``vex_obs``, ``reachability_obs``,
        ``control_obs``, ``validation_obs``.

    Returns
    -------
    dict
        Feature name → float value, suitable for DataFrame construction.
    """
    features: Dict[str, float] = {}

    # ── Layer A: Affectedness ────────────────────────────────────────
    software_obs = _get_software_obs(asset, vuln, session, asof, prefetched)
    vex_obs = _get_vex_obs(asset, vuln, session, asof, prefetched)

    features["affected_product_confirmed"] = 1.0 if software_obs else 0.0
    features["sbom_match_confidence"] = _best_confidence(software_obs)
    features["vex_status_enum"] = _best_vex_status(vex_obs)

    # ── Layer B: Reachability ────────────────────────────────────────
    reach_obs = _get_reachability_obs(asset, vuln, session, asof, prefetched)

    net_reach = any(
        r.reachability_type == "network" and r.is_reachable
        for r in reach_obs
    )
    code_reach = any(
        r.reachability_type == "code_path" and r.is_reachable
        for r in reach_obs
    )

    features["network_reachable_flag"] = 1.0 if net_reach else 0.0
    features["internet_facing_flag"] = 1.0 if asset.is_internet_facing else 0.0
    features["code_path_reachable"] = 1.0 if code_reach else 0.0

    # ── Layer D: Controls ────────────────────────────────────────────
    control_obs = _get_control_obs(asset, vuln, session, asof, prefetched)

    active_controls: Set[str] = set()
    effectiveness_scores: List[float] = []
    for ctrl in control_obs:
        if ctrl.is_active:
            active_controls.add(ctrl.control_type)
            if ctrl.effectiveness is not None:
                effectiveness_scores.append(ctrl.effectiveness)

    features["has_waf"] = 1.0 if "waf" in active_controls else 0.0
    features["has_edr"] = 1.0 if "edr" in active_controls else 0.0
    features["has_ips"] = 1.0 if "ips" in active_controls else 0.0
    features["has_network_segmentation"] = 1.0 if "network_segmentation" in active_controls else 0.0

    # Coverage score: fraction of 4 control types present × avg effectiveness
    coverage_fraction = len(active_controls & set(CONTROL_TYPES)) / len(CONTROL_TYPES)
    avg_effectiveness = float(np.mean(effectiveness_scores)) if effectiveness_scores else 0.5
    features["control_coverage_score"] = round(coverage_fraction * avg_effectiveness, 4)

    # ── Decision context ─────────────────────────────────────────────
    features["asset_criticality_score"] = CRITICALITY_SCORE_MAP.get(
        (asset.criticality or "medium").lower(), 0.5
    )

    pub_date = _to_date(vuln.published_at)
    if pub_date and pub_date <= asof:
        features["days_since_disclosure"] = float((asof - pub_date).days)
    else:
        features["days_since_disclosure"] = 0.0

    return features


# ── Observation loaders (with as-of enforcement) ────────────────────

def _get_software_obs(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    prefetched: Optional[Dict[str, Any]],
) -> List[AssetSoftwareObs]:
    """Get SBOM observations for this asset that match vuln's affected products."""
    if prefetched and "software_obs" in prefetched:
        return [
            s for s in prefetched["software_obs"]
            if _to_date(s.observed_at) is not None and _to_date(s.observed_at) <= asof
        ]

    vuln_products = _extract_vuln_products(vuln)
    if not vuln_products:
        return []

    obs = (
        session.query(AssetSoftwareObs)
        .filter(
            AssetSoftwareObs.asset_id == asset.id,
            AssetSoftwareObs.observed_at <= asof,
        )
        .all()
    )
    # Filter to matching products
    return [
        s for s in obs
        if (s.vendor.lower(), s.product.lower()) in vuln_products
        or (s.cpe and _cpe_matches_vuln(s.cpe, vuln))
    ]


def _get_vex_obs(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    prefetched: Optional[Dict[str, Any]],
) -> List[VexStatementObs]:
    if prefetched and "vex_obs" in prefetched:
        return [
            v for v in prefetched["vex_obs"]
            if _to_date(v.observed_at) is not None and _to_date(v.observed_at) <= asof
        ]

    return (
        session.query(VexStatementObs)
        .filter(
            VexStatementObs.vulnerability_id == vuln.id,
            VexStatementObs.observed_at <= asof,
        )
        .all()
    )


def _get_reachability_obs(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    prefetched: Optional[Dict[str, Any]],
) -> List[ReachabilityObs]:
    if prefetched and "reachability_obs" in prefetched:
        return [
            r for r in prefetched["reachability_obs"]
            if _to_date(r.observed_at) is not None and _to_date(r.observed_at) <= asof
        ]

    return (
        session.query(ReachabilityObs)
        .filter(
            ReachabilityObs.asset_id == asset.id,
            ReachabilityObs.vulnerability_id == vuln.id,
            ReachabilityObs.observed_at <= asof,
        )
        .all()
    )


def _get_control_obs(
    asset: Asset,
    vuln: Vulnerability,
    session: Session,
    asof: date,
    prefetched: Optional[Dict[str, Any]],
) -> List[ControlObs]:
    if prefetched and "control_obs" in prefetched:
        return [
            c for c in prefetched["control_obs"]
            if _to_date(c.observed_at) is not None and _to_date(c.observed_at) <= asof
        ]

    # Controls can be asset-wide (vulnerability_id is NULL) or CVE-specific
    return (
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


# ── Helper functions ────────────────────────────────────────────────

def _extract_vuln_products(vuln: Vulnerability) -> Set[Tuple[str, str]]:
    """Extract (vendor, product) pairs from vulnerability's affected_products_json."""
    products = vuln.affected_products_json or []
    result: Set[Tuple[str, str]] = set()
    for p in products:
        if isinstance(p, dict):
            vendor = p.get("vendor", "").lower()
            product = p.get("product", "").lower()
            if vendor and product:
                result.add((vendor, product))
        elif isinstance(p, str) and ":" in p:
            # CPE format: cpe:2.3:a:vendor:product:version:...
            parts = p.split(":")
            if len(parts) >= 5:
                result.add((parts[3].lower(), parts[4].lower()))
    return result


def _cpe_matches_vuln(cpe: str, vuln: Vulnerability) -> bool:
    """Check if a CPE string matches any of the vulnerability's affected products."""
    vuln_products = _extract_vuln_products(vuln)
    if not vuln_products or not cpe:
        return False
    parts = cpe.split(":")
    if len(parts) >= 5:
        return (parts[3].lower(), parts[4].lower()) in vuln_products
    return False


def _best_confidence(software_obs: List[AssetSoftwareObs]) -> float:
    """Return the highest confidence from matching SBOM observations."""
    if not software_obs:
        return 0.0
    confs = [s.confidence for s in software_obs if s.confidence is not None]
    return max(confs) if confs else 0.8  # default 0.8 if present but no confidence


def _best_vex_status(vex_obs: List[VexStatementObs]) -> float:
    """Return the most severe VEX status as a numeric value."""
    if not vex_obs:
        return -1.0  # no VEX data available
    statuses = [VEX_STATUS_MAP.get(v.status, 0.5) for v in vex_obs]
    return max(statuses)  # worst-case (most affected)


# ── Batch feature builder ──────────────────────────────────────────

def build_all_actionability_features(
    session: Session,
    asof: date,
    *,
    asset_ids: Optional[List[Any]] = None,
    cve_ids: Optional[List[str]] = None,
) -> pd.DataFrame:
    """Build actionability features for all (asset, vulnerability) pairs.

    Parameters
    ----------
    session : Session
        Database session.
    asof : date
        As-of date for temporal safety.
    asset_ids : list, optional
        Filter to specific asset IDs.  If None, all assets.
    cve_ids : list, optional
        Filter to specific CVE IDs.  If None, uses all CVEs with matching
        SBOM observations.

    Returns
    -------
    DataFrame
        Rows = (asset_id, cve_id), columns = actionability features.
    """
    # ── Load assets ──────────────────────────────────────────────────
    asset_q = session.query(Asset)
    if asset_ids:
        asset_q = asset_q.filter(Asset.id.in_(asset_ids))
    assets = asset_q.all()
    if not assets:
        log.warning("no_assets_found", msg="No assets in DB")
        return pd.DataFrame()

    log.info("loading_assets", count=len(assets))

    # ── Prefetch all observations (batch) ────────────────────────────
    asset_id_set = {a.id for a in assets}

    # Software observations
    sw_q = session.query(AssetSoftwareObs).filter(
        AssetSoftwareObs.asset_id.in_(asset_id_set),
        AssetSoftwareObs.observed_at <= asof,
    )
    sw_by_asset: Dict[Any, List[AssetSoftwareObs]] = defaultdict(list)
    for sw in sw_q.all():
        sw_by_asset[sw.asset_id].append(sw)

    # Reachability
    reach_q = session.query(ReachabilityObs).filter(
        ReachabilityObs.asset_id.in_(asset_id_set),
        ReachabilityObs.observed_at <= asof,
    )
    reach_by_asset_vuln: Dict[Tuple, List[ReachabilityObs]] = defaultdict(list)
    for r in reach_q.all():
        reach_by_asset_vuln[(r.asset_id, r.vulnerability_id)].append(r)

    # Controls
    ctrl_q = session.query(ControlObs).filter(
        ControlObs.asset_id.in_(asset_id_set),
        ControlObs.observed_at <= asof,
    )
    ctrl_by_asset: Dict[Any, List[ControlObs]] = defaultdict(list)
    for c in ctrl_q.all():
        ctrl_by_asset[c.asset_id].append(c)

    # VEX statements
    vex_all = session.query(VexStatementObs).filter(
        VexStatementObs.observed_at <= asof,
    ).all()
    vex_by_vuln: Dict[Any, List[VexStatementObs]] = defaultdict(list)
    for v in vex_all:
        vex_by_vuln[v.vulnerability_id].append(v)

    # ── Determine which CVEs to score ────────────────────────────────
    if cve_ids:
        vulns = session.query(Vulnerability).filter(
            Vulnerability.cve_id.in_(cve_ids)
        ).all()
    else:
        # Score all CVEs that have SBOM matches on any asset
        all_vuln_ids = set()
        for asset in assets:
            sw_obs = sw_by_asset.get(asset.id, [])
            for vuln in session.query(Vulnerability).all():
                vuln_products = _extract_vuln_products(vuln)
                for sw in sw_obs:
                    if (sw.vendor.lower(), sw.product.lower()) in vuln_products:
                        all_vuln_ids.add(vuln.id)
                        break
        if all_vuln_ids:
            vulns = session.query(Vulnerability).filter(
                Vulnerability.id.in_(all_vuln_ids)
            ).all()
        else:
            vulns = session.query(Vulnerability).all()
            log.info("no_sbom_matches", msg="No SBOM matches; scoring all CVEs")

    log.info("scoring_pairs", n_assets=len(assets), n_vulns=len(vulns))

    # ── Build features ───────────────────────────────────────────────
    rows: List[Dict[str, Any]] = []
    for asset in assets:
        asset_sw = sw_by_asset.get(asset.id, [])
        asset_ctrl = ctrl_by_asset.get(asset.id, [])

        for vuln in vulns:
            prefetched = {
                "software_obs": [
                    s for s in asset_sw
                    if _product_matches(s, vuln)
                ],
                "vex_obs": vex_by_vuln.get(vuln.id, []),
                "reachability_obs": reach_by_asset_vuln.get((asset.id, vuln.id), []),
                "control_obs": [
                    c for c in asset_ctrl
                    if c.vulnerability_id is None or c.vulnerability_id == vuln.id
                ],
            }

            feat = build_actionability_features(
                asset, vuln, session, asof, prefetched=prefetched,
            )
            feat["asset_id"] = str(asset.id)
            feat["asset_name"] = asset.name
            feat["cve_id"] = vuln.cve_id
            feat["vuln_id"] = str(vuln.id)
            rows.append(feat)

    log.info("actionability_features_built", total_pairs=len(rows))
    return pd.DataFrame(rows)


def _product_matches(sw: AssetSoftwareObs, vuln: Vulnerability) -> bool:
    """Check if a software observation matches a vulnerability's products."""
    vuln_products = _extract_vuln_products(vuln)
    if (sw.vendor.lower(), sw.product.lower()) in vuln_products:
        return True
    if sw.cpe and _cpe_matches_vuln(sw.cpe, vuln):
        return True
    return False


# ── Feature column list (for downstream use) ────────────────────────

ACTIONABILITY_FEATURES: List[str] = [
    # Layer A: Affectedness
    "affected_product_confirmed",
    "vex_status_enum",
    "sbom_match_confidence",
    # Layer B: Reachability
    "network_reachable_flag",
    "internet_facing_flag",
    "code_path_reachable",
    # Layer D: Controls
    "has_waf",
    "has_edr",
    "has_ips",
    "has_network_segmentation",
    "control_coverage_score",
    # Decision context
    "asset_criticality_score",
    "days_since_disclosure",
]

META_COLUMNS: List[str] = ["asset_id", "asset_name", "cve_id", "vuln_id"]
