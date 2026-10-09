"""RAGAS-style faithfulness scoring for generated vulnerability briefs.

Faithfulness (a.k.a. groundedness) is the fraction of factual claims in a
generated answer that are supported by the retrieved context. It is the RAGAS
metric that most directly captures hallucination / over-rationalisation:
``faithfulness = supported_claims / total_claims`` (Es et al., "RAGAS: Automated
Evaluation of Retrieval Augmented Generation", arXiv:2309.15217).

Unlike the deterministic STIX/URL checks — which only confirm that cited
identifiers *exist* — faithfulness checks whether the brief's *statements* are
actually entailed by the ATT&CK evidence and CVE record it was given. It is
computed natively with the same OpenAI client the generator uses, so it needs no
extra dependency (the ``ragas`` package is not required).

The scoring is a two-step LLM chain, exactly as RAGAS specifies:
  1. decompose the answer into atomic, self-contained claims;
  2. label each claim supported / not-supported given the context.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from openai import OpenAI

from app.core.logging import get_logger

log = get_logger(__name__)

_DECOMPOSE_SYS = (
    "You break an analytical text into atomic, self-contained factual claims. "
    "Each claim must stand alone (resolve pronouns) and assert one fact. "
    'Reply only as JSON: {"claims": ["...", "..."]}.'
)

_JUDGE_SYS = (
    "You verify whether each claim is supported by the provided CONTEXT. A claim "
    "is supported only if it can be directly inferred from the context; generic "
    "security best-practice advice that the context does not contradict counts as "
    "supported. Reply only as JSON: "
    '{"verdicts": [{"claim": "...", "supported": true/false}, ...]}.'
)


def _chat_json(client: OpenAI, model: str, system: str, user: str,
               max_tokens: int = 900) -> Dict[str, Any]:
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role": "system", "content": system},
                  {"role": "user", "content": user}],
        temperature=0.0,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
    )
    return json.loads(resp.choices[0].message.content)


def score_faithfulness(
    client: OpenAI,
    model: str,
    answer_text: str,
    context_text: str,
) -> Dict[str, Any]:
    """Compute the RAGAS faithfulness score for one brief.

    Args:
        client: An initialised OpenAI client.
        model: Model name to use as the judge (e.g. ``gpt-4o``).
        answer_text: The generated brief text to evaluate.
        context_text: The retrieved evidence the brief was grounded on
            (ATT&CK technique descriptions + CVE record).

    Returns:
        Dict with ``faithfulness`` in [0,1], ``n_claims``, ``n_supported``, and
        the per-claim ``verdicts``. On any failure returns ``faithfulness=None``
        so the caller can skip rather than record a wrong 0.
    """
    try:
        claims = _chat_json(
            client, model, _DECOMPOSE_SYS,
            f"TEXT:\n{answer_text[:4000]}",
        ).get("claims", [])
    except Exception as e:  # noqa: BLE001
        log.warning("faithfulness_decompose_failed", error=str(e))
        return {"faithfulness": None, "n_claims": 0, "n_supported": 0, "verdicts": []}

    if not claims:
        return {"faithfulness": None, "n_claims": 0, "n_supported": 0, "verdicts": []}

    try:
        claim_list = "\n".join(f"- {c}" for c in claims)
        verdicts = _chat_json(
            client, model, _JUDGE_SYS,
            f"CONTEXT:\n{context_text[:6000]}\n\nCLAIMS:\n{claim_list}",
        ).get("verdicts", [])
    except Exception as e:  # noqa: BLE001
        log.warning("faithfulness_judge_failed", error=str(e))
        return {"faithfulness": None, "n_claims": len(claims), "n_supported": 0,
                "verdicts": []}

    n_supported = sum(1 for v in verdicts if v.get("supported") is True)
    n_total = len(verdicts) or len(claims)
    faithfulness = round(n_supported / n_total, 4) if n_total else None

    log.info("faithfulness_scored", n_claims=n_total, n_supported=n_supported,
             faithfulness=faithfulness)
    return {
        "faithfulness": faithfulness,
        "n_claims": n_total,
        "n_supported": n_supported,
        "verdicts": verdicts,
    }


def build_context_text(vuln: Dict[str, Any], techniques: List[Dict[str, Any]]) -> str:
    """Assemble the grounding context a brief should be faithful to."""
    parts = [
        f"CVE: {vuln.get('cve_id', '')}",
        f"Description: {vuln.get('description', '')}",
    ]
    if vuln.get("cvss_vector"):
        parts.append(f"CVSS: {vuln.get('cvss_base_score')} {vuln.get('cvss_vector')}")
    for t in techniques:
        parts.append(
            f"ATT&CK {t.get('technique_id')} ({t.get('technique_name')}): "
            f"{t.get('description', '')[:400]}"
        )
    for r in (vuln.get("references_json") or [])[:8]:
        if r.get("url"):
            parts.append(f"Reference: {r['url']}")
    return "\n".join(parts)
