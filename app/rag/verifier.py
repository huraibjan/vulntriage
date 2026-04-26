"""RAG output verifier – validates STRICT JSON brief compliance.

Checks:
  1. All technique IDs exist in the loaded ATT&CK corpus.
  2. Every ATT&CK mapping rationale has ≥1 evidence snippet.
  3. Output validates against the Pydantic schema.
  4. No exploit code patterns detected.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from app.core.logging import get_logger
from app.rag.attck_loader import technique_exists
from app.schemas.models import VulnerabilityBrief

log = get_logger(__name__)

# Patterns that might indicate exploit code (safety check)
EXPLOIT_CODE_PATTERNS = [
    r"import\s+socket",
    r"subprocess\.call",
    r"os\.system\(",
    r"exec\(",
    r"eval\(",
    r"\\x[0-9a-f]{2}",       # shellcode hex
    r"\\u0000",               # null bytes
    r"powershell\s+-enc",     # encoded powershell
    r"curl\s+.*\|\s*sh",      # pipe to shell
    r"wget\s+.*\|\s*bash",    # pipe to bash
]


def verify_brief(brief: VulnerabilityBrief) -> Tuple[bool, List[str]]:
    """Verify a vulnerability brief meets all safety and quality requirements.

    Args:
        brief: The VulnerabilityBrief to verify.

    Returns:
        Tuple of (is_valid, list_of_errors).
    """
    errors: List[str] = []

    # ── 1. Technique ID existence ────────────────────────────────────────
    for mapping in brief.attck:
        if not technique_exists(mapping.technique_id):
            errors.append(
                f"Technique ID '{mapping.technique_id}' not found in ATT&CK corpus"
            )

    # ── 2. Evidence requirement ──────────────────────────────────────────
    for i, mapping in enumerate(brief.attck):
        if not mapping.evidence or len(mapping.evidence) < 1:
            errors.append(
                f"ATT&CK mapping [{i}] ('{mapping.technique_id}') has no evidence snippets"
            )
        for j, ev in enumerate(mapping.evidence):
            if not ev.text or len(ev.text.strip()) == 0:
                errors.append(
                    f"ATT&CK mapping [{i}] evidence [{j}] has empty text"
                )

    # ── 3. Rationale quality ─────────────────────────────────────────────
    for i, mapping in enumerate(brief.attck):
        if not mapping.rationale or len(mapping.rationale) < 20:
            errors.append(
                f"ATT&CK mapping [{i}] rationale is too short or empty"
            )

    # ── 4. Safety – no exploit code ──────────────────────────────────────
    brief_text = brief.model_dump_json()
    for pattern in EXPLOIT_CODE_PATTERNS:
        if re.search(pattern, brief_text, re.IGNORECASE):
            errors.append(
                f"Safety violation: exploit code pattern detected: {pattern}"
            )

    # ── 5. Schema validation (Pydantic handles this, but double-check) ──
    try:
        _ = brief.model_dump_json()
    except Exception as e:
        errors.append(f"JSON serialization failed: {e}")

    # ── 6. Required fields ───────────────────────────────────────────────
    if not brief.vulnerability.description:
        errors.append("Vulnerability description is missing")

    if brief.scores.p_final is None:
        errors.append("Final probability score is missing")

    is_valid = len(errors) == 0

    if not is_valid:
        log.warning(
            "brief_verification_failed",
            n_errors=len(errors),
            errors=errors[:5],
        )
    else:
        log.info("brief_verified", cve_id=brief.vulnerability.cve_id)

    return is_valid, errors
