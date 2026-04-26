"""Pydantic models for LLM-extracted evidence structures.

These models define the schema for evidence extracted from NVD
descriptions, advisories, and other unstructured text sources
using LLM-based structured extraction.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class AffectednessStatus(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNDER_INVESTIGATION = "under_investigation"
    UNKNOWN = "unknown"


class VersionRange(BaseModel):
    """A version range affected by a vulnerability."""
    product: str = Field(..., description="Software product name")
    vendor: Optional[str] = Field(None, description="Vendor name")
    version_start: Optional[str] = Field(None, description="Start of affected version range")
    version_end: Optional[str] = Field(None, description="End of affected version range (exclusive)")
    fixed_version: Optional[str] = Field(None, description="First fixed version")


class AttackPrerequisite(str, Enum):
    NETWORK_ACCESS = "network_access"
    LOCAL_ACCESS = "local_access"
    AUTHENTICATION = "authentication"
    USER_INTERACTION = "user_interaction"
    SPECIFIC_CONFIGURATION = "specific_configuration"
    NONE = "none"


class AffectednessEvidence(BaseModel):
    """Evidence about whether specific software is affected."""
    status: AffectednessStatus = AffectednessStatus.UNKNOWN
    products: List[VersionRange] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    justification: Optional[str] = Field(None, description="Why this status was assigned")
    source_text: Optional[str] = Field(None, description="Quoted text supporting this assessment")


class ExploitabilityEvidence(BaseModel):
    """Evidence about the exploitability of a vulnerability."""
    requires_network: bool = Field(default=True, description="Attack requires network access")
    requires_auth: bool = Field(default=False, description="Attack requires authentication")
    requires_user_interaction: bool = Field(default=False, description="Attack requires user interaction")
    prerequisites: List[AttackPrerequisite] = Field(default_factory=list)
    attack_complexity: Optional[str] = Field(None, description="low, medium, high")
    exploit_type: Optional[str] = Field(None, description="e.g., RCE, DoS, info_disclosure, privilege_escalation")
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    source_text: Optional[str] = None


class RemediationEvidence(BaseModel):
    """Evidence about available remediation."""
    patch_available: bool = False
    workaround_available: bool = False
    patch_url: Optional[str] = None
    workaround_description: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    source_text: Optional[str] = None


class ExtractedVulnEvidence(BaseModel):
    """Complete structured evidence extracted from vulnerability description."""
    cve_id: str
    affectedness: AffectednessEvidence = Field(default_factory=AffectednessEvidence)
    exploitability: ExploitabilityEvidence = Field(default_factory=ExploitabilityEvidence)
    remediation: RemediationEvidence = Field(default_factory=RemediationEvidence)
    extraction_model: str = Field(default="manual", description="Model used for extraction")
    raw_description: Optional[str] = None
