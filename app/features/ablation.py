"""Ablation framework – defines feature group configurations for experiments.

Each ablation configuration specifies which feature columns to INCLUDE
(or equivalently, which to exclude).  This integrates with the label
builder's ``get_excluded_features()`` to ensure circularity prevention
is enforced at the experiment level.

Usage
-----
::

    from app.features.ablation import get_ablation_config, apply_ablation
    from app.ingest.label_builder import get_excluded_features

    config = get_ablation_config("no_circular")
    excluded = get_excluded_features("kev_strict")

    # Apply both ablation and circularity exclusions
    df_train = apply_ablation(df, config, extra_exclude=excluded)

Ablation Configurations
-----------------------
1. **full** – All 37 features (baseline).
2. **no_circular** – Remove features derived from exploit signals
   (kev_flag, poc_exploitdb_flag, metasploit_flag, exploit_signal_count,
   days_since_poc).  Shows what the model can predict *without* knowing
   the answer.
3. **cve_only** – Only CVSS + CWE + text features. No enrichment.
   Tests "how much can we predict from the CVE alone?"
4. **temporal_only** – Only temporal features (days_since_published,
   epss_score).  Tests time-decay hypothesis.
5. **network_enriched** – CVE-only + product/reference features.
   Tests vendor ecosystem signal.
6. **text_only** – description_length + description_word_count only.
   Sanity check (should be weakest).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set

import pandas as pd

from app.core.logging import get_logger

log = get_logger(__name__)


# ── Feature groups ──────────────────────────────────────────────────────

# Every feature produced by builder.py, organized into semantic groups
FEATURE_GROUPS: Dict[str, List[str]] = {
    "cvss_core": [
        "cvss_base_score",
        "cvss_version_31",
    ],
    "cvss_vector": [
        "cvss_attack_vector",
        "cvss_attack_complexity",
        "cvss_privileges_required",
        "cvss_user_interaction",
        "cvss_scope",
        "cvss_confidentiality_impact",
        "cvss_integrity_impact",
        "cvss_availability_impact",
        "cvss_is_network",
        "cvss_no_privs",
        "cvss_no_interaction",
        "cvss_scope_changed",
        "cvss_cia_total",
    ],
    "temporal": [
        "days_since_published",
    ],
    "enrichment_safe": [
        # EPSS is safe to use as feature when label is NOT epss_derived
        "epss_score",
    ],
    "exploit_signals": [
        # These are the CIRCULAR features when labels come from
        # kev/poc/metasploit signals
        "kev_flag",
        "poc_exploitdb_flag",
        "metasploit_flag",
        "exploit_signal_count",
        "days_since_poc",
    ],
    "cwe": [
        "cwe_injection",
        "cwe_input_validation",
        "cwe_path_traversal",
        "cwe_information_disclosure",
        "cwe_auth_bypass",
        "cwe_race_condition",
        "cwe_file_upload",
        "cwe_deserialization",
        "cwe_memory_safety",
        "cwe_ssrf",
        "cwe_other",
        "cwe_count",
    ],
    "text": [
        "description_length",
        "description_word_count",
    ],
    "network": [
        "product_count",
        "reference_count",
    ],
    "composite": [
        # Derived from other features — include for legacy compat only
        "composite_exploit_score",
    ],
    # ── Actionability feature groups (asset-level) ──────────────────
    "affectedness": [
        "affected_product_confirmed",
        "vex_status_enum",
        "sbom_match_confidence",
    ],
    "reachability": [
        "network_reachable_flag",
        "internet_facing_flag",
        "code_path_reachable",
    ],
    "controls": [
        "has_waf",
        "has_edr",
        "has_ips",
        "has_network_segmentation",
        "control_coverage_score",
    ],
    "decision_context": [
        "asset_criticality_score",
        "days_since_disclosure",
    ],
}

# Flatten for easy lookup
ALL_FEATURES: Set[str] = set()
for _group_features in FEATURE_GROUPS.values():
    ALL_FEATURES.update(_group_features)


# ── Ablation configurations ────────────────────────────────────────────

@dataclass(frozen=True)
class AblationConfig:
    """Describes which feature groups are included in an experiment."""

    name: str
    description: str
    included_groups: FrozenSet[str]
    # Extra features to always exclude (on top of group-level exclusion)
    always_exclude: FrozenSet[str] = frozenset()

    @property
    def included_features(self) -> Set[str]:
        """Compute the full set of included feature names."""
        features: Set[str] = set()
        for group in self.included_groups:
            features.update(FEATURE_GROUPS.get(group, []))
        features -= self.always_exclude
        return features

    @property
    def excluded_features(self) -> Set[str]:
        """Features NOT included in this configuration."""
        return ALL_FEATURES - self.included_features


ABLATION_CONFIGS: Dict[str, AblationConfig] = {
    "full": AblationConfig(
        name="full",
        description="All 37 features — baseline experiment",
        included_groups=frozenset(FEATURE_GROUPS.keys()),
    ),
    "no_circular": AblationConfig(
        name="no_circular",
        description=(
            "Remove exploit signal features (kev_flag, poc, msf, etc.). "
            "Tests prediction without circularity."
        ),
        included_groups=frozenset(
            FEATURE_GROUPS.keys() - {"exploit_signals", "composite"}
        ),
    ),
    "cve_only": AblationConfig(
        name="cve_only",
        description=(
            "Only CVSS + CWE + text features. No enrichment signals. "
            "Tests: how much can we predict from the CVE record alone?"
        ),
        included_groups=frozenset({"cvss_core", "cvss_vector", "cwe", "text"}),
    ),
    "temporal_only": AblationConfig(
        name="temporal_only",
        description=(
            "Only temporal features (days_since_published, epss_score). "
            "Tests time-decay and EPSS signal strength in isolation."
        ),
        included_groups=frozenset({"temporal", "enrichment_safe"}),
    ),
    "network_enriched": AblationConfig(
        name="network_enriched",
        description=(
            "CVE-only + product/reference counts. "
            "Tests vendor ecosystem and reference network signal."
        ),
        included_groups=frozenset({
            "cvss_core", "cvss_vector", "cwe", "text", "network",
        }),
    ),
    "text_only": AblationConfig(
        name="text_only",
        description=(
            "Only description length and word count. "
            "Sanity check — should be the weakest model."
        ),
        included_groups=frozenset({"text"}),
    ),
    # ── Actionability-aware configurations ──────────────────────────
    "actionability_full": AblationConfig(
        name="actionability_full",
        description=(
            "All CVE-level features + all 13 actionability features. "
            "Full asset-aware experiment."
        ),
        included_groups=frozenset(FEATURE_GROUPS.keys()),
    ),
    "no_controls": AblationConfig(
        name="no_controls",
        description=(
            "Actionability full minus control features. "
            "Tests: how much do compensating controls change decisions?"
        ),
        included_groups=frozenset(FEATURE_GROUPS.keys() - {"controls"}),
    ),
    "no_reachability": AblationConfig(
        name="no_reachability",
        description=(
            "Actionability full minus reachability features. "
            "Tests: how much does reachability evidence change decisions?"
        ),
        included_groups=frozenset(FEATURE_GROUPS.keys() - {"reachability"}),
    ),
    "asset_context_only": AblationConfig(
        name="asset_context_only",
        description=(
            "Only actionability features (no CVE-level features). "
            "Tests: can asset context alone predict the right action?"
        ),
        included_groups=frozenset({
            "affectedness", "reachability", "controls", "decision_context",
        }),
    ),
}


# ── Application logic ──────────────────────────────────────────────────

def get_ablation_config(name: str) -> AblationConfig:
    """Get an ablation configuration by name.

    Raises ValueError if not found.
    """
    if name not in ABLATION_CONFIGS:
        raise ValueError(
            f"Unknown ablation config '{name}'. "
            f"Available: {sorted(ABLATION_CONFIGS.keys())}"
        )
    return ABLATION_CONFIGS[name]


def apply_ablation(
    df: pd.DataFrame,
    config: AblationConfig,
    *,
    extra_exclude: Optional[FrozenSet[str]] = None,
    keep_meta_columns: bool = True,
) -> pd.DataFrame:
    """Filter a feature DataFrame to only the columns allowed by the
    ablation configuration.

    Parameters
    ----------
    df : DataFrame
        Feature DataFrame (rows = vulns, columns = features + meta).
    config : AblationConfig
        Which feature groups to include.
    extra_exclude : frozenset[str], optional
        Additional features to exclude (e.g., from label circularity).
    keep_meta_columns : bool
        If True, always keep ``vuln_id``, ``cve_id``, ``published_at``
        columns if present.

    Returns
    -------
    DataFrame
        Filtered DataFrame with only allowed feature columns.
    """
    included = config.included_features
    if extra_exclude:
        included = included - extra_exclude

    # Meta columns to preserve
    meta_cols = {"vuln_id", "cve_id", "published_at"}

    kept_cols = []
    for col in df.columns:
        if col in included:
            kept_cols.append(col)
        elif keep_meta_columns and col in meta_cols:
            kept_cols.append(col)

    dropped = set(df.columns) - set(kept_cols)
    feature_dropped = dropped - meta_cols
    if feature_dropped:
        log.info(
            "ablation_applied",
            config=config.name,
            kept=len(kept_cols),
            dropped_features=len(feature_dropped),
        )

    return df[kept_cols].copy()


def get_feature_columns(
    config_name: str,
    policy_name: Optional[str] = None,
) -> List[str]:
    """Get the ordered list of feature column names for a given
    ablation + policy combination.

    This is used by the training pipeline to know which columns
    to select from the feature DataFrame.

    Parameters
    ----------
    config_name : str
        Ablation configuration name.
    policy_name : str, optional
        Label policy name.  If provided, also excludes circularity
        features.

    Returns
    -------
    list[str]
        Sorted list of feature column names.
    """
    config = get_ablation_config(config_name)
    included = config.included_features

    if policy_name:
        from app.ingest.label_builder import get_excluded_features
        excluded = get_excluded_features(policy_name)
        included = included - excluded

    return sorted(included)


def list_ablation_configs() -> List[Dict[str, Any]]:
    """Return human-readable list of all ablation configurations."""
    return [
        {
            "name": c.name,
            "description": c.description,
            "num_features": len(c.included_features),
            "included_groups": sorted(c.included_groups),
            "included_features": sorted(c.included_features),
        }
        for c in ABLATION_CONFIGS.values()
    ]


def ablation_comparison_table() -> pd.DataFrame:
    """Generate a comparison table of all ablation configs.

    Returns a DataFrame where rows = features and columns = configs,
    with ✓/✗ indicating inclusion.
    """
    all_feats = sorted(ALL_FEATURES)
    configs = sorted(ABLATION_CONFIGS.keys())

    data: Dict[str, List[str]] = {"feature": all_feats}
    for cfg_name in configs:
        cfg = ABLATION_CONFIGS[cfg_name]
        included = cfg.included_features
        data[cfg_name] = ["✓" if f in included else "✗" for f in all_feats]

    # Add group column
    feat_to_group = {}
    for group, feats in FEATURE_GROUPS.items():
        for f in feats:
            feat_to_group[f] = group
    data["group"] = [feat_to_group.get(f, "?") for f in all_feats]

    df = pd.DataFrame(data)
    # Reorder columns: group, feature, then configs
    cols = ["group", "feature"] + configs
    return df[cols]
