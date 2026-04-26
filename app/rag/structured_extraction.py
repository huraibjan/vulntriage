"""Structured extraction — extract affectedness and exploitability signals from text.

Uses rule-based heuristics to extract structured evidence from NVD
descriptions and advisory text.  An optional LLM path can be added
later for higher accuracy.

The extracted evidence is returned as Pydantic models defined in
``app.schemas.llm_structures``.

Usage
-----
::

    from app.rag.structured_extraction import extract_from_description
    evidence = extract_from_description(cve_id, description)
"""

from __future__ import annotations

import re
from typing import List, Optional

from app.core.logging import get_logger
from app.schemas.llm_structures import (
    AffectednessEvidence,
    AffectednessStatus,
    AttackPrerequisite,
    ExploitabilityEvidence,
    ExtractedVulnEvidence,
    RemediationEvidence,
    VersionRange,
)

log = get_logger(__name__)


# ── Regex patterns for extraction ───────────────────────────────────

_VERSION_PATTERN = re.compile(
    r"(?:before|prior to|up to|through|<=?)\s*([\d]+(?:\.[\d]+)+)",
    re.IGNORECASE,
)
_FIXED_VERSION_PATTERN = re.compile(
    r"(?:fixed in|patched in|resolved in|upgrade to)\s*([\d]+(?:\.[\d]+)+)",
    re.IGNORECASE,
)
_PRODUCT_PATTERN = re.compile(
    r"(?:in|affects?|vulnerability in)\s+([A-Z][\w\s-]{2,30}?)\s+(?:before|version|through|prior)",
    re.IGNORECASE,
)
_NOT_AFFECTED_PATTERNS = [
    re.compile(r"does not affect", re.IGNORECASE),
    re.compile(r"not affected", re.IGNORECASE),
    re.compile(r"not vulnerable", re.IGNORECASE),
    re.compile(r"not exploitable", re.IGNORECASE),
]

_EXPLOIT_TYPE_PATTERNS = {
    "rce": re.compile(r"remote code execution|arbitrary code|command execution", re.IGNORECASE),
    "dos": re.compile(r"denial of service|crash|resource consumption", re.IGNORECASE),
    "info_disclosure": re.compile(r"information disclosure|information leak|data exposure|sensitive data", re.IGNORECASE),
    "privilege_escalation": re.compile(r"privilege escalation|elevat(?:e|ion)", re.IGNORECASE),
    "sqli": re.compile(r"sql injection", re.IGNORECASE),
    "xss": re.compile(r"cross-site scripting|xss", re.IGNORECASE),
    "ssrf": re.compile(r"server-side request forgery|ssrf", re.IGNORECASE),
    "auth_bypass": re.compile(r"authentication bypass|authorization bypass|bypass auth", re.IGNORECASE),
}

_PREREQ_PATTERNS = {
    AttackPrerequisite.NETWORK_ACCESS: re.compile(
        r"remote|network|via HTTP|over the network", re.IGNORECASE
    ),
    AttackPrerequisite.LOCAL_ACCESS: re.compile(
        r"local\s+(?:attacker|access|user)", re.IGNORECASE
    ),
    AttackPrerequisite.AUTHENTICATION: re.compile(
        r"authenticated|requires? (?:valid )?credentials|login", re.IGNORECASE
    ),
    AttackPrerequisite.USER_INTERACTION: re.compile(
        r"user interaction|click|visit|open(?:s|ing)?\s+a", re.IGNORECASE
    ),
    AttackPrerequisite.SPECIFIC_CONFIGURATION: re.compile(
        r"non-default|specific config|when configured|if enabled", re.IGNORECASE
    ),
}


def extract_from_description(
    cve_id: str,
    description: str,
    *,
    extraction_model: str = "heuristic_v1",
) -> ExtractedVulnEvidence:
    """Extract structured evidence from a CVE description using heuristics.

    Parameters
    ----------
    cve_id : str
        CVE identifier.
    description : str
        NVD or advisory description text.
    extraction_model : str
        Name of the extraction method.

    Returns
    -------
    ExtractedVulnEvidence
        Structured evidence with affectedness, exploitability, remediation.
    """
    if not description:
        return ExtractedVulnEvidence(
            cve_id=cve_id,
            extraction_model=extraction_model,
            raw_description=description,
        )

    # ── Affectedness extraction ──────────────────────────────────────
    affectedness = _extract_affectedness(description)

    # ── Exploitability extraction ────────────────────────────────────
    exploitability = _extract_exploitability(description)

    # ── Remediation extraction ───────────────────────────────────────
    remediation = _extract_remediation(description)

    return ExtractedVulnEvidence(
        cve_id=cve_id,
        affectedness=affectedness,
        exploitability=exploitability,
        remediation=remediation,
        extraction_model=extraction_model,
        raw_description=description[:500],  # truncate for storage
    )


def _extract_affectedness(text: str) -> AffectednessEvidence:
    """Extract affectedness evidence from text."""
    # Check for not-affected signals
    for pattern in _NOT_AFFECTED_PATTERNS:
        match = pattern.search(text)
        if match:
            return AffectednessEvidence(
                status=AffectednessStatus.NOT_AFFECTED,
                confidence=0.6,
                justification="Text contains not-affected language",
                source_text=text[max(0, match.start() - 20):match.end() + 20],
            )

    # Extract product + version ranges
    products: List[VersionRange] = []

    product_matches = _PRODUCT_PATTERN.findall(text)
    version_matches = _VERSION_PATTERN.findall(text)
    fixed_matches = _FIXED_VERSION_PATTERN.findall(text)

    for prod_name in product_matches[:3]:  # limit to 3
        vr = VersionRange(
            product=prod_name.strip(),
            version_end=version_matches[0] if version_matches else None,
            fixed_version=fixed_matches[0] if fixed_matches else None,
        )
        products.append(vr)

    if products:
        return AffectednessEvidence(
            status=AffectednessStatus.AFFECTED,
            products=products,
            confidence=0.7,
            justification=f"Extracted {len(products)} affected product(s)",
        )

    return AffectednessEvidence(
        status=AffectednessStatus.UNKNOWN,
        confidence=0.3,
        justification="Could not determine affectedness from description",
    )


def _extract_exploitability(text: str) -> ExploitabilityEvidence:
    """Extract exploitability evidence from text."""
    # Determine exploit type
    exploit_type = None
    for etype, pattern in _EXPLOIT_TYPE_PATTERNS.items():
        if pattern.search(text):
            exploit_type = etype
            break

    # Determine prerequisites
    prereqs: List[AttackPrerequisite] = []
    for prereq, pattern in _PREREQ_PATTERNS.items():
        if pattern.search(text):
            prereqs.append(prereq)

    requires_network = AttackPrerequisite.NETWORK_ACCESS in prereqs
    requires_auth = AttackPrerequisite.AUTHENTICATION in prereqs
    requires_ui = AttackPrerequisite.USER_INTERACTION in prereqs

    # If no network/local specified, default to network (most common)
    if not requires_network and AttackPrerequisite.LOCAL_ACCESS not in prereqs:
        requires_network = True

    # Confidence based on how much we extracted
    confidence = 0.3 + 0.1 * len(prereqs) + (0.2 if exploit_type else 0.0)
    confidence = min(confidence, 0.85)

    return ExploitabilityEvidence(
        requires_network=requires_network,
        requires_auth=requires_auth,
        requires_user_interaction=requires_ui,
        prerequisites=prereqs,
        exploit_type=exploit_type,
        confidence=round(confidence, 2),
    )


def _extract_remediation(text: str) -> RemediationEvidence:
    """Extract remediation evidence from text."""
    fixed_versions = _FIXED_VERSION_PATTERN.findall(text)
    patch_available = len(fixed_versions) > 0

    workaround_pattern = re.compile(
        r"workaround|mitigation|disable|turn off|restrict", re.IGNORECASE
    )
    workaround_available = bool(workaround_pattern.search(text))

    return RemediationEvidence(
        patch_available=patch_available,
        workaround_available=workaround_available,
        confidence=0.6 if (patch_available or workaround_available) else 0.3,
    )


def extract_batch(
    descriptions: List[dict],
    *,
    extraction_model: str = "heuristic_v1",
) -> List[ExtractedVulnEvidence]:
    """Extract evidence from a batch of CVE descriptions.

    Parameters
    ----------
    descriptions : list[dict]
        Each dict has ``cve_id`` and ``description`` keys.

    Returns
    -------
    list[ExtractedVulnEvidence]
    """
    results = []
    for item in descriptions:
        evidence = extract_from_description(
            cve_id=item["cve_id"],
            description=item.get("description", ""),
            extraction_model=extraction_model,
        )
        results.append(evidence)

    log.info("batch_extraction_complete", total=len(results))
    return results
