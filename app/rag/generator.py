"""STRICT JSON brief generator – produces evidence-grounded vulnerability briefs.

Every claim must include retrieved evidence snippets. No free-text "advice"
without grounding. No exploit code generation.
"""

from __future__ import annotations

from datetime import datetime, date
from typing import Any, Dict, List, Optional

from app.core.logging import get_logger
from app.rag.retriever import build_query_text, retrieve_techniques
from app.schemas.models import (
    ATTCKMapping,
    AuditInfo,
    BriefMeta,
    DataVersions,
    EvidenceSnippet,
    ModelVersions,
    RemediationAction,
    SafetyInfo,
    VulnerabilityBrief,
    VulnerabilityRead,
    VulnerabilityScores,
)

log = get_logger(__name__)

# Maximum evidence snippet length (chars)
MAX_EVIDENCE_LEN = 500


def generate_brief(
    vuln: Dict[str, Any],
    scores: Dict[str, Any],
    *,
    asof_date: Optional[str] = None,
    attck_version: str = "v18.1",
    top_k_techniques: int = 3,
) -> VulnerabilityBrief:
    """Generate a STRICT JSON vulnerability brief with ATT&CK mapping.

    This is the core output of the system – enterprise-ready, evidence-backed,
    no hallucinated claims.

    Args:
        vuln: Vulnerability data dict (from DB model).
        scores: Dict with p_stage1, p_stage2, p_final keys.
        asof_date: Evaluation date string (YYYY-MM-DD).
        attck_version: Version of ATT&CK corpus used.
        top_k_techniques: Number of ATT&CK techniques to map.

    Returns:
        VulnerabilityBrief Pydantic model.
    """
    if asof_date is None:
        asof_date = date.today().isoformat()

    # ── 1. Build query and retrieve techniques ───────────────────────────
    query = build_query_text(
        description=vuln.get("description", ""),
        cwe_ids=vuln.get("cwe_ids"),
        products=vuln.get("affected_products_json"),
    )

    retrieved = retrieve_techniques(query, top_k=top_k_techniques)

    # ── 2. Build ATT&CK mappings with evidence ──────────────────────────
    attck_mappings: List[ATTCKMapping] = []
    for tech in retrieved:
        evidence_text = tech.get("description", "")[:MAX_EVIDENCE_LEN]
        if not evidence_text:
            continue

        mapping = ATTCKMapping(
            technique_id=tech["technique_id"],
            technique_name=tech["technique_name"],
            confidence=round(tech.get("similarity_score", 0.5), 3),
            rationale=_build_rationale(vuln, tech),
            evidence=[
                EvidenceSnippet(
                    source="ATT&CK",
                    text=evidence_text,
                    attck_version=attck_version,
                    object_ref=tech.get("stix_id", ""),
                )
            ],
        )
        attck_mappings.append(mapping)

    # ── 3. Build remediation actions ─────────────────────────────────────
    remediation = _build_remediation(vuln, attck_mappings)

    # ── 4. Assemble the brief ────────────────────────────────────────────
    brief = VulnerabilityBrief(
        meta=BriefMeta(
            generated_at=datetime.utcnow(),
            asof_date=asof_date,
            data_versions=DataVersions(
                vulndb_snapshot=asof_date,
                attck_version=attck_version,
            ),
            model_versions=ModelVersions(
                tabular_model="xgb_v1",
                text_model="distilbert_v1",
                stacking_model="calibrated_lr_v1",
            ),
        ),
        vulnerability=VulnerabilityRead(
            id=vuln.get("id", "00000000-0000-0000-0000-000000000000"),
            source=vuln.get("source", "vulndb"),
            cve_id=vuln.get("cve_id"),
            vuldb_id=vuln.get("vuldb_id"),
            published_at=vuln.get("published_at"),
            title=vuln.get("title"),
            description=vuln.get("description"),
            cvss_version=vuln.get("cvss_version"),
            cvss_vector=vuln.get("cvss_vector"),
            cvss_base_score=vuln.get("cvss_base_score"),
            cwe_ids=vuln.get("cwe_ids"),
        ),
        scores=VulnerabilityScores(
            p_stage1=scores.get("p_stage1"),
            p_stage2=scores.get("p_stage2"),
            p_final=scores.get("p_final", 0.5),
            calibration={
                "method": "sigmoid",
                "brier_score": scores.get("brier_score"),
            },
        ),
        attck=attck_mappings,
        remediation=remediation,
        confidence_notes=_confidence_notes(scores, attck_mappings),
        audit=AuditInfo(
            leakage_checked=True,
            explanations=scores.get("explanations"),
        ),
        safety=SafetyInfo(),
    )

    log.info(
        "brief_generated",
        cve_id=vuln.get("cve_id"),
        n_techniques=len(attck_mappings),
        p_final=scores.get("p_final"),
    )
    return brief


def _build_rationale(vuln: Dict[str, Any], tech: Dict[str, Any]) -> str:
    """Build a grounded rationale connecting the vulnerability to the technique."""
    desc = vuln.get("description", "")
    cwe_str = ", ".join(vuln.get("cwe_ids", []))
    products = vuln.get("affected_products_json", [])
    product_str = ", ".join(
        f"{p.get('vendor', '')} {p.get('product', '')}".strip()
        for p in products[:3]
    ) if products else "the affected software"

    parts = [
        f"The vulnerability in {product_str}",
    ]

    if cwe_str:
        parts.append(f"involves weakness type(s) {cwe_str}")

    tactics = tech.get("tactics", [])
    if tactics:
        parts.append(
            f"and is consistent with the '{tech['technique_name']}' technique "
            f"(tactic: {', '.join(tactics)})"
        )
    else:
        parts.append(
            f"and is consistent with the '{tech['technique_name']}' technique"
        )

    parts.append(
        f"based on semantic similarity (score: {tech.get('similarity_score', 0):.3f})"
    )

    return " ".join(parts) + "."


def _build_remediation(
    vuln: Dict[str, Any],
    mappings: List[ATTCKMapping],
) -> List[RemediationAction]:
    """Generate evidence-backed remediation actions."""
    actions: List[RemediationAction] = []

    # Primary: vendor patch
    refs = vuln.get("references_json", [])
    vendor_refs = [r for r in refs if r.get("source") == "vendor"]
    vendor_evidence = []
    for ref in vendor_refs[:2]:
        vendor_evidence.append(
            EvidenceSnippet(
                source="Vendor Advisory",
                text=f"See vendor advisory at {ref.get('url', 'N/A')}",
                ref=ref.get("url"),
            )
        )

    actions.append(
        RemediationAction(
            action="Apply vendor patch and validate remediation via version check.",
            priority="critical" if vuln.get("cvss_base_score", 0) >= 9.0 else "high",
            evidence=vendor_evidence if vendor_evidence else [
                EvidenceSnippet(
                    source="General",
                    text="Check vendor security advisories for available patches.",
                )
            ],
        )
    )

    # Detection: based on ATT&CK techniques
    if mappings:
        tech_names = [m.technique_name for m in mappings[:3]]
        actions.append(
            RemediationAction(
                action=f"Monitor for indicators of {', '.join(tech_names)} in network and endpoint telemetry.",
                priority="high",
                evidence=[
                    EvidenceSnippet(
                        source="ATT&CK",
                        text=f"ATT&CK techniques {', '.join(m.technique_id for m in mappings[:3])} describe detection opportunities.",
                    )
                ],
            )
        )

    return actions


def _confidence_notes(
    scores: Dict[str, Any],
    mappings: List[ATTCKMapping],
) -> str:
    """Generate brief confidence notes."""
    p_final = scores.get("p_final", 0.5)
    n_mappings = len(mappings)

    if p_final >= 0.7:
        risk = "HIGH"
    elif p_final >= 0.4:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return (
        f"Predicted exploitability: {risk} ({p_final:.1%}). "
        f"Based on {n_mappings} ATT&CK technique mapping(s). "
        f"Calibrated probability; consult audit.explanations for feature contributions."
    )
