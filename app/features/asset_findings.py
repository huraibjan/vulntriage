"""Build the prioritised finding queue for an asset from its software inventory.

For every CVE whose affected products appear in the asset's SBOM, the installed
version is compared with the CVE's vulnerable ranges, and each confirmed or
unverified match is scored through the SSVC-inspired decision engine with the
asset's own context (criticality, exposure, VEX, controls). The same CVE is
also scored without asset context, so the effect of the asset evidence on the
recommended action is explicit for every finding.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.asset_models import Asset, AssetSoftwareObs, DecisionObs
from app.db.models import Vulnerability
from app.features.affectedness import (
    MATCH_NONE,
    MATCH_NOT_IN_RANGE,
    best_match,
    component_identity,
)
from app.core.settings import get_settings
from app.features.builder import build_features_for_vuln
from app.features.policy_engine import build_evidence_input, load_policy_config
from app.schemas.ssvc_cisa import derive_decision_points
from app.schemas.decision import (
    SLA_HOURS,
    Action,
    Affectedness,
    ControlStatus,
    Criticality,
    EvidenceInput,
    Exploitation,
    Reachability,
    decide,
)

log = get_logger(__name__)

POLICY_NAME = "ssvc_v1"
ACTION_ORDER = ["patch_now", "mitigate_now", "patch_window", "monitor", "accept"]
URGENT_ACTIONS = {"patch_now", "mitigate_now"}


def _val(x: Any) -> Any:
    return getattr(x, "value", x)


def decide_global(vuln: Vulnerability, features: Dict[str, Any], ml_prob: float):
    """Decision with no asset context (the assetless baseline)."""
    kev = bool(features.get("kev_flag"))
    poc = bool(features.get("poc_exploitdb_flag")) or bool(features.get("metasploit_flag"))
    exploitation = (
        Exploitation.ACTIVE if kev else Exploitation.POC_PUBLIC if poc else Exploitation.THEORETICAL
    )
    evidence = EvidenceInput(
        affectedness=Affectedness.UNKNOWN,
        reachability=Reachability.UNKNOWN,
        is_internet_facing=False,
        exploitation=exploitation,
        epss_score=float(features.get("epss_score", 0.0) or 0.0),
        ml_exploit_prob=ml_prob,
        days_since_published=int(features.get("days_since_published", 0) or 0),
        control_status=ControlStatus.UNKNOWN,
        asset_criticality=Criticality.MEDIUM,
        cvss_base_score=float(vuln.cvss_base_score or 0.0),
    )
    return decide(evidence), exploitation


def _candidate_cves(
    components: List[AssetSoftwareObs], session: Session
) -> Dict[Any, Tuple[Vulnerability, List[AssetSoftwareObs]]]:
    """CVEs whose affected products include a product installed on the asset."""
    by_identity: Dict[Tuple[str, str], List[AssetSoftwareObs]] = {}
    for sw in components:
        vendor, product, _ = component_identity(sw)
        if vendor and product and vendor != "unknown":
            by_identity.setdefault((vendor, product), []).append(sw)

    candidates: Dict[Any, Tuple[Vulnerability, List[AssetSoftwareObs]]] = {}
    for (vendor, product), comps in by_identity.items():
        # affected_products_json stores CPE tokens with underscores as spaces.
        needle = [{"vendor": vendor.replace("_", " "), "product": product.replace("_", " ")}]
        rows = (
            session.query(Vulnerability)
            .filter(Vulnerability.affected_products_json.contains(needle))
            .all()
        )
        for vuln in rows:
            if vuln.id in candidates:
                candidates[vuln.id][1].extend(comps)
            else:
                candidates[vuln.id] = (vuln, list(comps))
    return candidates


def evaluate_asset(
    asset: Asset,
    session: Session,
    asof: Optional[date] = None,
    *,
    max_scored: int = 3000,
) -> Dict[str, Any]:
    """Recompute and persist the finding queue for one asset."""
    from app.ml.tabular.train import load_model

    asof = asof or datetime.utcnow().date()  # observations are stamped in UTC
    components = session.query(AssetSoftwareObs).filter_by(asset_id=asset.id).all()
    candidates = _candidate_cves(components, session)

    matched: List[Tuple[Vulnerability, Dict[str, Any]]] = []
    for vuln, comps in candidates.values():
        match = best_match(comps, vuln)
        if match["level"] != MATCH_NONE:
            matched.append((vuln, match))

    # Highest-severity matches are scored first if the cap applies.
    matched.sort(key=lambda vm: -(vm[0].cvss_base_score or 0.0))
    truncated = max(0, len(matched) - max_scored)
    matched = matched[:max_scored]

    model = load_model()
    feat_cols = list(model.get_booster().feature_names)
    config = load_policy_config()

    # Optional: ask the distribution's own tracker (via OSV) whether the
    # installed package revision already carries the fix. Any failure leaves
    # the upstream-range verdict in place.
    osv_result, osv_keys = None, {}
    if get_settings().osv_backport_check:
        from app.features.osv_backports import distro_package, osv_vulnerable_cves
        for vuln, match in matched:
            if match["level"] != MATCH_NOT_IN_RANGE:
                key = distro_package(match.get("purl"))
                if key:
                    osv_keys[vuln.id] = key
        if osv_keys:
            osv_result = osv_vulnerable_cves(set(osv_keys.values()))
    fixed_by_distro = 0

    session.query(DecisionObs).filter(
        DecisionObs.asset_id == asset.id, DecisionObs.policy_name == POLICY_NAME
    ).delete(synchronize_session=False)

    now = datetime.utcnow()
    counts = {a: 0 for a in ACTION_ORDER}
    global_counts = {a: 0 for a in ACTION_ORDER}
    changed = 0

    for vuln, match in matched:
        features = build_features_for_vuln(vuln, session, asof)
        X = pd.DataFrame([{c: features.get(c, 0.0) for c in feat_cols}])[feat_cols]
        ml_prob = float(model.predict_proba(X.fillna(0).astype(float))[:, 1][0])

        global_decision, exploitation = decide_global(vuln, features, ml_prob)
        global_action = _val(global_decision.action)

        distro_verdict = None
        if osv_result is not None and vuln.id in osv_keys:
            from app.features.osv_backports import backport_verdict
            distro_verdict = backport_verdict(vuln.cve_id, osv_keys[vuln.id], osv_result)

        if match["level"] == MATCH_NOT_IN_RANGE:
            # Installed version is outside every vulnerable range: no further
            # evidence can make this actionable, so the engine is not consulted.
            action, confidence, sla_hours = "accept", 0.9, SLA_HOURS[Action.ACCEPT]
            rationale = [f"SBOM: {match['detail']}"]
            summary: Dict[str, Any] = {"affectedness": {"status": "not_affected",
                                                        "vex": "sbom_version_not_in_range"}}
        elif distro_verdict == "fixed_by_distro":
            # The distribution tracks this CVE for the package and the installed
            # revision is outside its affected set (a backported fix).
            fixed_by_distro += 1
            eco, pkg, rev = osv_keys[vuln.id]
            action, confidence, sla_hours = "accept", 0.9, SLA_HOURS[Action.ACCEPT]
            rationale = [f"Distribution tracker ({eco}, via OSV): {pkg} {rev} is not affected "
                         f"by {vuln.cve_id}, although the upstream version is in NVD's range"]
            summary = {"affectedness": {"status": "not_affected", "vex": "fixed_by_distro"}}
            match = {**match, "level": "fixed_by_distro"}
        else:
            evidence = build_evidence_input(
                asset, vuln, session, asof, ml_exploit_prob=ml_prob, config=config
            )
            decision = decide(evidence)
            action, confidence, sla_hours = _val(decision.action), decision.confidence, decision.sla_hours
            rationale = list(decision.rationale)
            summary = decision.evidence_summary
            if distro_verdict == "confirmed_by_distro":
                rationale.append("Distribution tracker (via OSV) also lists this revision as affected")

        cisa = derive_decision_points(
            in_kev=bool(features.get("kev_flag")),
            has_public_poc=bool(features.get("poc_exploitdb_flag")) or bool(features.get("metasploit_flag")),
            cvss_vector=vuln.cvss_vector,
            asset_criticality=asset.criticality,
        ).to_dict()

        counts[action] += 1
        global_counts[global_action] += 1
        if action != global_action:
            changed += 1

        session.add(DecisionObs(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            action=action,
            confidence=confidence,
            evidence_chain_json={
                "rationale": rationale,
                "match": match,
                "sla_hours": sla_hours,
                "global_action": global_action,
                "exploitation": _val(exploitation),
                "epss": float(features.get("epss_score", 0.0) or 0.0),
                "tabular_model_output": round(ml_prob, 4),
                "ssvc_cisa": cisa,
                "distro_verdict": distro_verdict,
                "summary": _jsonable(summary),
            },
            policy_name=POLICY_NAME,
            policy_version="1.0",
            decided_at=now,
            sla_deadline=now + timedelta(hours=sla_hours) if sla_hours else None,
        ))

    session.commit()

    urgent = sum(counts[a] for a in URGENT_ACTIONS)
    urgent_global = sum(global_counts[a] for a in URGENT_ACTIONS)
    result = {
        "asset_id": str(asset.id),
        "asof": str(asof),
        "components": len(components),
        "components_with_identity": sum(
            1 for sw in components if (sw.confidence or 0) >= 0.6
        ),
        "candidate_cves": len(candidates),
        "findings": len(matched),
        "not_scored_over_cap": truncated,
        "by_action": counts,
        "without_asset_context": global_counts,
        "decisions_changed_by_asset_context": changed,
        "urgent": urgent,
        "urgent_without_asset_context": urgent_global,
        "distro_backport_check": bool(osv_result is not None),
        "fixed_by_distro": fixed_by_distro,
    }
    log.info("asset_evaluated", **{k: v for k, v in result.items() if not isinstance(v, dict)})
    return result


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    return _val(obj)


def list_findings(
    asset: Asset,
    session: Session,
    *,
    action: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
) -> Dict[str, Any]:
    """Persisted findings for an asset, most urgent first."""
    q = (
        session.query(DecisionObs, Vulnerability)
        .join(Vulnerability, Vulnerability.id == DecisionObs.vulnerability_id)
        .filter(DecisionObs.asset_id == asset.id, DecisionObs.policy_name == POLICY_NAME)
    )
    if action:
        q = q.filter(DecisionObs.action == action)
    rows = q.all()

    def sort_key(row: Tuple[DecisionObs, Vulnerability]):
        d, v = row
        chain = d.evidence_chain_json or {}
        return (
            ACTION_ORDER.index(d.action) if d.action in ACTION_ORDER else len(ACTION_ORDER),
            0 if chain.get("exploitation") == "active" else 1,
            -(chain.get("epss") or 0.0),
            -(v.cvss_base_score or 0.0),
        )

    rows.sort(key=sort_key)
    items = []
    for d, v in rows[offset:offset + limit]:
        chain = d.evidence_chain_json or {}
        match = chain.get("match") or {}
        items.append({
            "cve_id": v.cve_id,
            "title": v.title,
            "cvss_base_score": v.cvss_base_score,
            "published_at": v.published_at.isoformat() if v.published_at else None,
            "action": d.action,
            "sla_hours": chain.get("sla_hours"),
            "sla_deadline": d.sla_deadline.isoformat() if d.sla_deadline else None,
            "confidence": d.confidence,
            "exploitation": chain.get("exploitation"),
            "epss": chain.get("epss"),
            "component": {
                "vendor": match.get("vendor"),
                "product": match.get("product"),
                "installed_version": match.get("installed_version"),
                "match_level": match.get("level"),
                "vulnerable_range": match.get("vulnerable_range"),
            },
            "rationale": chain.get("rationale", []),
            "ssvc_cisa": (chain.get("ssvc_cisa") or {}).get("outcome"),
            "distro_verdict": chain.get("distro_verdict"),
            "action_without_asset_context": chain.get("global_action"),
            "changed_by_asset_context": chain.get("global_action") not in (None, d.action),
        })
    return {"total": len(rows), "offset": offset, "limit": limit, "items": items}
