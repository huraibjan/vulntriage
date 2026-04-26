"""LLM-powered RAG brief generator using OpenAI GPT-4o-mini.

Replaces the template-based generator with actual LLM reasoning while
keeping the existing retriever (Qdrant semantic search) and verifier
(safety checker + technique validation) as guardrails.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any, Dict, List, Optional

from openai import OpenAI

from app.core.logging import get_logger
from app.core.settings import get_settings
from app.rag.retriever import build_query_text, retrieve_techniques
from app.rag.verifier import verify_brief
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

_client: Optional[OpenAI] = None


def _get_client() -> OpenAI:
    """Lazy-init singleton OpenAI client."""
    global _client
    if _client is None:
        settings = get_settings()
        if not settings.openai_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set in .env — cannot generate LLM briefs."
            )
        _client = OpenAI(api_key=settings.openai_api_key)
    return _client


# ── System prompt ────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are VulnTriage AI, a cybersecurity vulnerability analyst. You produce
concise, evidence-grounded vulnerability intelligence briefs.

RULES:
1. Every claim MUST reference the provided ATT&CK techniques or CVE data.
2. NEVER fabricate technique IDs, CVE details, or exploit code.
3. NEVER include working exploit code, shellcode, or attack scripts.
4. Use professional security analyst language.
5. Be specific about impact, affected software, and recommended actions.
6. Output ONLY valid JSON matching the requested schema.
"""


def _build_user_prompt(
    vuln: Dict[str, Any],
    scores: Dict[str, Any],
    techniques: List[Dict[str, Any]],
) -> str:
    """Build the user prompt with all context for the LLM."""
    tech_context = "\n".join(
        f"  - {t['technique_id']} ({t['technique_name']}): {t['description'][:300]}..."
        f" [similarity: {t['similarity_score']:.3f}, tactics: {', '.join(t.get('tactics', []))}]"
        for t in techniques
    )

    products = vuln.get("affected_products_json", [])
    product_str = ", ".join(
        f"{p.get('vendor', '')} {p.get('product', '')}".strip()
        for p in products[:5]
    ) if products else "Unknown"

    refs = vuln.get("references_json", [])
    ref_str = "\n".join(f"  - {r.get('url', 'N/A')}" for r in refs[:5]) if refs else "  None"

    return f"""\
Analyze this vulnerability and generate an intelligence brief.

CVE: {vuln.get('cve_id', 'N/A')}
Title: {vuln.get('title', 'N/A')}
Description: {vuln.get('description', 'N/A')}
CVSS: {vuln.get('cvss_base_score', 'N/A')} ({vuln.get('cvss_vector', 'N/A')})
CWE: {', '.join(vuln.get('cwe_ids', []) or ['N/A'])}
Affected Products: {product_str}
References:
{ref_str}

ML Prediction: {scores.get('p_final', 0.5):.1%} exploitation probability
EPSS Score: {scores.get('epss_score', 'N/A')}

Retrieved ATT&CK Techniques:
{tech_context}

Generate a JSON response with this exact structure:
{{
  "executive_summary": "2-3 sentence summary of the vulnerability, its risk, and recommended action",
  "risk_assessment": "Detailed analysis of exploitation likelihood and potential impact",
  "attck_analysis": [
    {{
      "technique_id": "Txxxx",
      "technique_name": "Name",
      "relevance": "Why this technique is relevant to this CVE",
      "detection_guidance": "How to detect exploitation via this technique"
    }}
  ],
  "remediation_steps": [
    {{
      "action": "Specific action to take",
      "priority": "critical|high|medium|low",
      "rationale": "Why this action matters"
    }}
  ],
  "ioc_suggestions": ["indicators of compromise to look for"],
  "confidence_notes": "Assessment of prediction confidence and data quality"
}}

IMPORTANT: Only reference the ATT&CK techniques provided above. Do not invent technique IDs."""


def generate_llm_brief(
    vuln: Dict[str, Any],
    scores: Dict[str, Any],
    *,
    asof_date: Optional[str] = None,
    attck_version: str = "v18.1",
    top_k_techniques: int = 3,
) -> Dict[str, Any]:
    """Generate an LLM-powered vulnerability brief.

    Pipeline:
      1. Retrieve ATT&CK techniques via Qdrant (existing retriever)
      2. Build prompt with CVE data + retrieved context
      3. Call GPT-4o-mini for analysis
      4. Parse response and build VulnerabilityBrief
      5. Run safety verification (existing verifier)

    Returns:
        Dict with the full brief + LLM analysis.
    """
    settings = get_settings()
    client = _get_client()

    if asof_date is None:
        asof_date = date.today().isoformat()

    # ── 1. Retrieve ATT&CK techniques ───────────────────────────────────
    query = build_query_text(
        description=vuln.get("description", ""),
        cwe_ids=vuln.get("cwe_ids"),
        products=vuln.get("affected_products_json"),
    )
    techniques = retrieve_techniques(query, top_k=top_k_techniques)

    # ── 2. Call LLM ─────────────────────────────────────────────────────
    user_prompt = _build_user_prompt(vuln, scores, techniques)

    log.info("llm_brief_request", cve_id=vuln.get("cve_id"), model=settings.openai_model)

    response = client.chat.completions.create(
        model=settings.openai_model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.3,
        max_tokens=2000,
        response_format={"type": "json_object"},
    )

    raw_content = response.choices[0].message.content
    usage = response.usage

    try:
        llm_analysis = json.loads(raw_content)
    except json.JSONDecodeError:
        log.error("llm_json_parse_failed", raw=raw_content[:200])
        llm_analysis = {"executive_summary": raw_content, "error": "JSON parse failed"}

    # ── 3. Build structured brief (for verifier compatibility) ──────────
    attck_mappings: List[ATTCKMapping] = []
    for tech in techniques:
        llm_match = next(
            (a for a in llm_analysis.get("attck_analysis", [])
             if a.get("technique_id") == tech["technique_id"]),
            None,
        )
        rationale = (
            llm_match.get("relevance", "") if llm_match
            else f"Semantically similar to vulnerability description (score: {tech['similarity_score']:.3f})"
        )
        detection = llm_match.get("detection_guidance", "") if llm_match else ""

        attck_mappings.append(ATTCKMapping(
            technique_id=tech["technique_id"],
            technique_name=tech["technique_name"],
            confidence=round(tech.get("similarity_score", 0.5), 3),
            rationale=rationale,
            evidence=[
                EvidenceSnippet(
                    source="ATT&CK",
                    text=tech.get("description", "")[:500],
                    attck_version=attck_version,
                    object_ref=tech.get("stix_id", ""),
                )
            ],
        ))

    remediation: List[RemediationAction] = []
    for step in llm_analysis.get("remediation_steps", []):
        remediation.append(RemediationAction(
            action=step.get("action", "Review and patch."),
            priority=step.get("priority", "high"),
            evidence=[EvidenceSnippet(
                source="LLM Analysis",
                text=step.get("rationale", "AI-generated recommendation."),
            )],
        ))

    if not remediation:
        remediation.append(RemediationAction(
            action="Apply vendor patch and validate remediation.",
            priority="high",
            evidence=[EvidenceSnippet(source="General", text="Standard remediation.")],
        ))

    brief = VulnerabilityBrief(
        meta=BriefMeta(
            generated_at=datetime.utcnow(),
            asof_date=asof_date,
            data_versions=DataVersions(
                vulndb_snapshot=asof_date,
                attck_version=attck_version,
            ),
            model_versions=ModelVersions(
                tabular_model="xgb_v2_rrf",
                text_model="all-MiniLM-L6-v2",
                stacking_model="rrf_ensemble_v2",
            ),
        ),
        vulnerability=VulnerabilityRead(
            id=vuln.get("id", "00000000-0000-0000-0000-000000000000"),
            source=vuln.get("source", "nvd"),
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
            calibration={"method": "rrf_ensemble", "brier_score": scores.get("brier_score")},
        ),
        attck=attck_mappings,
        remediation=remediation,
        confidence_notes=llm_analysis.get("confidence_notes", ""),
        audit=AuditInfo(leakage_checked=True),
        safety=SafetyInfo(),
    )

    # ── 4. Safety verification ──────────────────────────────────────────
    is_valid, errors = verify_brief(brief)

    log.info(
        "llm_brief_generated",
        cve_id=vuln.get("cve_id"),
        model=settings.openai_model,
        tokens_prompt=usage.prompt_tokens if usage else 0,
        tokens_completion=usage.completion_tokens if usage else 0,
        verified=is_valid,
        n_errors=len(errors),
    )

    return {
        "brief": brief.model_dump(mode="json"),
        "llm_analysis": llm_analysis,
        "verification": {"valid": is_valid, "errors": errors},
        "usage": {
            "model": settings.openai_model,
            "prompt_tokens": usage.prompt_tokens if usage else 0,
            "completion_tokens": usage.completion_tokens if usage else 0,
            "total_tokens": usage.total_tokens if usage else 0,
        },
    }
