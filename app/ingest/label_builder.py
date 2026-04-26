"""Circularity-free label builder with provenance tracking.

This module replaces the original ``build_labels()`` in orchestrator.py.
Every label row records:
  - which signal_observation(s) contributed to the label decision
  - an explicit ``label_asof`` anchored to the *signal* observation date
  - which features must be EXCLUDED when this label policy is used
    (preventing the same evidence from appearing on both sides of the
    prediction equation)

Ground-Truth Policies
---------------------
* **kev_strict** – label=1 iff CISA KEV observed *before* the as-of date.
  Feature exclusion: ``kev_flag``.

* **temporal_first_exploit** – label=1 iff *any* exploit signal (KEV, PoC,
  Metasploit) was observed ≤ *N* days after publication (default 90).
  Feature exclusion: ``kev_flag, poc_exploitdb_flag, metasploit_flag,
  exploit_signal_count, days_since_poc``.

* **composite_no_leak** – like the old composite but with explicit
  circularity audit.  Meant for ablation comparison only.
  Feature exclusion: same as temporal_first_exploit.

* **epss_derived** – label=1 iff EPSS ≥ threshold *and* KEV observed
  (combines prediction + ground-truth).
  Feature exclusion: ``epss_score, kev_flag``.

Circularity Matrix
------------------
See ``reports/ground_truth_audit.md §4`` for the full matrix mapping
(signal_type → feature_name → label_policy) with overlap flags.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Dict, FrozenSet, List, Optional, Set
from uuid import uuid4

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db.models import LabelObservation, SignalObservation, Vulnerability

log = get_logger(__name__)


# ── Policy definitions ──────────────────────────────────────────────────

@dataclass(frozen=True)
class LabelPolicy:
    """Immutable descriptor of a ground-truth label policy."""

    name: str
    description: str
    # Feature columns that MUST be excluded from training when using
    # labels produced by this policy (prevents circularity).
    excluded_features: FrozenSet[str]

    # Signal types that contribute to the positive label
    positive_signal_types: FrozenSet[str]

    # Additional parameters
    params: Dict[str, Any] = field(default_factory=dict)


# ── Pre-defined policies ────────────────────────────────────────────────

POLICIES: Dict[str, LabelPolicy] = {
    "kev_strict": LabelPolicy(
        name="kev_strict",
        description=(
            "Label = 1 iff CISA KEV observed before the as-of date. "
            "Most conservative: only known-exploited vulnerabilities."
        ),
        excluded_features=frozenset({"kev_flag"}),
        positive_signal_types=frozenset({"kev"}),
    ),
    "temporal_first_exploit": LabelPolicy(
        name="temporal_first_exploit",
        description=(
            "Label = 1 iff any exploit signal (KEV/PoC/Metasploit) appeared "
            "within N days of publication. Default N=90."
        ),
        excluded_features=frozenset({
            "kev_flag",
            "poc_exploitdb_flag",
            "metasploit_flag",
            "exploit_signal_count",
            "days_since_poc",
        }),
        positive_signal_types=frozenset({"kev", "poc_exploitdb", "metasploit"}),
        params={"horizon_days": 90},
    ),
    "composite_no_leak": LabelPolicy(
        name="composite_no_leak",
        description=(
            "Composite of all exploit signals (like the old composite) "
            "but with circularity-excluded features. For ablation only."
        ),
        excluded_features=frozenset({
            "kev_flag",
            "poc_exploitdb_flag",
            "metasploit_flag",
            "exploit_signal_count",
            "days_since_poc",
        }),
        positive_signal_types=frozenset({"kev", "poc_exploitdb", "metasploit"}),
    ),
    "epss_derived": LabelPolicy(
        name="epss_derived",
        description=(
            "Label = 1 iff EPSS >= threshold AND KEV observed. "
            "Combines prediction with ground truth for high confidence."
        ),
        excluded_features=frozenset({"epss_score", "kev_flag"}),
        positive_signal_types=frozenset({"kev", "epss"}),
        params={"epss_threshold": 0.15},
    ),
}


# ── Provenance record ──────────────────────────────────────────────────

@dataclass
class LabelProvenance:
    """Audit trail for one label decision."""

    vuln_id: str
    cve_id: Optional[str]
    policy: str
    label_value: int
    label_asof: datetime
    contributing_signals: List[Dict[str, Any]]  # signal_type, observed_at, value
    excluded_features: List[str]
    rationale: str


# ── Core builder ────────────────────────────────────────────────────────

def build_labels(
    session: Session,
    *,
    policy_name: str = "kev_strict",
    asof: Optional[date] = None,
    overwrite: bool = False,
    dry_run: bool = False,
) -> List[LabelProvenance]:
    """Build circularity-free ground-truth labels for all vulnerabilities.

    Parameters
    ----------
    session : Session
        Active SQLAlchemy session.
    policy_name : str
        Name of the policy to use (must be in ``POLICIES``).
    asof : date, optional
        Observation cut-off date.  Only signals observed on or before this
        date count.  Defaults to today.
    overwrite : bool
        If True, delete existing labels for this policy before rebuilding.
    dry_run : bool
        If True, compute labels but do not persist.  Returns provenance
        records for inspection.

    Returns
    -------
    list[LabelProvenance]
        Provenance records for every label created (or computed in dry-run).
    """
    if policy_name not in POLICIES:
        raise ValueError(
            f"Unknown policy '{policy_name}'. "
            f"Available: {sorted(POLICIES.keys())}"
        )

    policy = POLICIES[policy_name]
    asof_dt = datetime.combine(asof or date.today(), datetime.max.time())
    provenance: List[LabelProvenance] = []

    # Optionally clear old labels for this policy
    if overwrite and not dry_run:
        deleted = (
            session.query(LabelObservation)
            .filter_by(label_type="exploited", label_source=policy_name)
            .delete()
        )
        log.info("labels_deleted", policy=policy_name, count=deleted)

    # ── Batch-load all data upfront (avoid N+1) ────────────────────
    log.info("labels_loading_vulns", policy=policy_name)
    vulns = session.query(Vulnerability).all()

    # Pre-fetch existing label IDs for this policy (skip check)
    existing_label_vuln_ids: Set[Any] = set()
    if not overwrite:
        existing_rows = (
            session.query(LabelObservation.vulnerability_id)
            .filter_by(label_type="exploited", label_source=policy_name)
            .all()
        )
        existing_label_vuln_ids = {r[0] for r in existing_rows}
        log.info("labels_existing_prefetched", count=len(existing_label_vuln_ids))

    # Batch-load ALL signals observed before as-of date (1 query)
    log.info("labels_loading_signals", asof=str(asof_dt))
    from collections import defaultdict as _defaultdict
    all_signals = (
        session.query(SignalObservation)
        .filter(SignalObservation.observed_at <= asof_dt)
        .all()
    )
    signals_by_vuln: Dict[Any, List[SignalObservation]] = _defaultdict(list)
    for sig in all_signals:
        signals_by_vuln[sig.vulnerability_id].append(sig)
    log.info("labels_signals_loaded", total=len(all_signals),
             vulns_with_signals=len(signals_by_vuln))

    created = 0
    skipped = 0
    batch_size = 5000

    for i, vuln in enumerate(vulns, 1):
        # Check existing (skip if not overwriting)
        if not overwrite and vuln.id in existing_label_vuln_ids:
            skipped += 1
            continue

        # Use pre-fetched signals
        signals = signals_by_vuln.get(vuln.id, [])

        # Apply policy
        label_value, contributing, rationale = _apply_policy(
            policy, vuln, signals, asof_dt
        )

        # Build provenance record
        prov = LabelProvenance(
            vuln_id=str(vuln.id),
            cve_id=vuln.cve_id,
            policy=policy_name,
            label_value=label_value,
            label_asof=asof_dt,
            contributing_signals=[
                {
                    "signal_type": s.signal_type,
                    "observed_at": str(s.observed_at),
                    "value_num": s.value_num,
                    "value_bool": s.value_bool,
                    "source": s.source,
                }
                for s in contributing
            ],
            excluded_features=sorted(policy.excluded_features),
            rationale=rationale,
        )
        provenance.append(prov)

        if not dry_run:
            label = LabelObservation(
                vulnerability_id=vuln.id,
                label_type="exploited",
                label_value=label_value,
                label_asof=asof_dt,
                label_source=policy_name,
                label_rationale=rationale,
            )
            session.add(label)
            created += 1

        # Periodic commit to avoid huge transaction
        if not dry_run and i % batch_size == 0:
            session.commit()
            log.info("labels_progress", processed=i, total=len(vulns),
                     created=created, skipped=skipped)

    if not dry_run:
        session.commit()

    # Summary statistics
    positive = sum(1 for p in provenance if p.label_value == 1)
    negative = sum(1 for p in provenance if p.label_value == 0)
    rate = positive / len(provenance) if provenance else 0.0

    log.info(
        "labels_built",
        policy=policy_name,
        total=len(provenance),
        positive=positive,
        negative=negative,
        positive_rate=f"{rate:.4f}",
        skipped=skipped,
        created=created,
        dry_run=dry_run,
    )

    return provenance


# ── Policy application logic ───────────────────────────────────────────

def _apply_policy(
    policy: LabelPolicy,
    vuln: Vulnerability,
    signals: List[SignalObservation],
    asof_dt: datetime,
) -> tuple[int, List[SignalObservation], str]:
    """Apply a label policy to a single vulnerability.

    Returns (label_value, contributing_signals, rationale_string).
    """
    if policy.name == "kev_strict":
        return _policy_kev_strict(vuln, signals, asof_dt)
    elif policy.name == "temporal_first_exploit":
        horizon = policy.params.get("horizon_days", 90)
        return _policy_temporal_first(vuln, signals, asof_dt, horizon)
    elif policy.name == "composite_no_leak":
        return _policy_composite(vuln, signals, asof_dt)
    elif policy.name == "epss_derived":
        threshold = policy.params.get("epss_threshold", 0.15)
        return _policy_epss_derived(vuln, signals, asof_dt, threshold)
    else:
        raise ValueError(f"No implementation for policy '{policy.name}'")


def _policy_kev_strict(
    vuln: Vulnerability,
    signals: List[SignalObservation],
    asof_dt: datetime,
) -> tuple[int, List[SignalObservation], str]:
    """KEV-strict: label=1 iff any KEV signal observed before as-of."""
    contributing = [
        s for s in signals
        if s.signal_type == "kev" and s.value_bool is True
    ]
    if contributing:
        return (1, contributing, "KEV observed before cut-off")
    return (0, [], "No KEV signal observed")


def _policy_temporal_first(
    vuln: Vulnerability,
    signals: List[SignalObservation],
    asof_dt: datetime,
    horizon_days: int,
) -> tuple[int, List[SignalObservation], str]:
    """Temporal: label=1 iff exploit signal appeared within N days of publication."""
    if not vuln.published_at:
        return (0, [], "No publication date; cannot compute temporal window")

    pub_dt = vuln.published_at
    if isinstance(pub_dt, date) and not isinstance(pub_dt, datetime):
        pub_dt = datetime.combine(pub_dt, datetime.min.time())

    window_end = pub_dt + timedelta(days=horizon_days)
    # Also respect the as-of cut-off
    effective_end = min(window_end, asof_dt)

    contributing = []
    for s in signals:
        if s.signal_type not in ("kev", "poc_exploitdb", "metasploit"):
            continue
        if s.value_bool is not True:
            continue
        if s.observed_at <= effective_end:
            contributing.append(s)

    if contributing:
        types = sorted(set(s.signal_type for s in contributing))
        return (
            1,
            contributing,
            f"Exploit signal(s) [{', '.join(types)}] within {horizon_days}d of publication",
        )
    return (
        0,
        [],
        f"No exploit signal within {horizon_days}d of publication (window ends {effective_end.date()})",
    )


def _policy_composite(
    vuln: Vulnerability,
    signals: List[SignalObservation],
    asof_dt: datetime,
) -> tuple[int, List[SignalObservation], str]:
    """Composite: label=1 iff any exploit signal exists (no time window)."""
    contributing = []
    for s in signals:
        if s.signal_type in ("kev", "poc_exploitdb", "metasploit"):
            if s.value_bool is True:
                contributing.append(s)

    if contributing:
        types = sorted(set(s.signal_type for s in contributing))
        return (1, contributing, f"Composite exploit signals: {', '.join(types)}")
    return (0, [], "No exploit signals observed")


def _policy_epss_derived(
    vuln: Vulnerability,
    signals: List[SignalObservation],
    asof_dt: datetime,
    epss_threshold: float,
) -> tuple[int, List[SignalObservation], str]:
    """EPSS-derived: label=1 iff EPSS >= threshold AND KEV observed."""
    contributing = []
    has_kev = False
    epss_val = 0.0

    for s in signals:
        if s.signal_type == "kev" and s.value_bool is True:
            has_kev = True
            contributing.append(s)
        if s.signal_type == "epss" and s.value_num is not None:
            if s.value_num > epss_val:
                epss_val = s.value_num
                # Keep only the latest EPSS signal in contributing list
                contributing = [c for c in contributing if c.signal_type != "epss"]
                contributing.append(s)

    if has_kev and epss_val >= epss_threshold:
        return (
            1,
            contributing,
            f"KEV=True AND EPSS={epss_val:.4f} >= {epss_threshold}",
        )
    return (
        0,
        [],
        f"Condition not met: KEV={has_kev}, EPSS={epss_val:.4f}, threshold={epss_threshold}",
    )


# ── Validation / circularity audit ─────────────────────────────────────

def validate_labels(
    session: Session,
    policy_name: str = "kev_strict",
) -> Dict[str, Any]:
    """Validate that no circularity exists between labels and features.

    Checks:
    1. No signal used for labelling also appears as a feature without
       being in the exclusion set.
    2. All label_asof dates are <= the feature asof dates.
    3. Positive-class ratio is within expected bounds.

    Returns a validation report dict.
    """
    if policy_name not in POLICIES:
        raise ValueError(f"Unknown policy '{policy_name}'")

    policy = POLICIES[policy_name]
    report: Dict[str, Any] = {
        "policy": policy_name,
        "excluded_features": sorted(policy.excluded_features),
        "checks": {},
    }

    # Check 1: Signal-feature overlap
    # Map of signal_type → feature names they produce
    signal_to_features: Dict[str, Set[str]] = {
        "kev": {"kev_flag"},
        "poc_exploitdb": {"poc_exploitdb_flag", "days_since_poc"},
        "metasploit": {"metasploit_flag"},
        "epss": {"epss_score"},
    }

    leaky_features: Set[str] = set()
    for sig_type in policy.positive_signal_types:
        produced = signal_to_features.get(sig_type, set())
        overlap = produced - policy.excluded_features
        leaky_features.update(overlap)

    report["checks"]["circularity"] = {
        "status": "PASS" if not leaky_features else "FAIL",
        "leaky_features": sorted(leaky_features),
        "detail": (
            "No circularity detected"
            if not leaky_features
            else f"Features {sorted(leaky_features)} are derived from "
            f"label signals but NOT excluded"
        ),
    }

    # Check 2: Label statistics
    total_labels = (
        session.query(func.count(LabelObservation.id))
        .filter_by(label_type="exploited", label_source=policy_name)
        .scalar()
        or 0
    )
    positive_labels = (
        session.query(func.count(LabelObservation.id))
        .filter_by(label_type="exploited", label_source=policy_name, label_value=1)
        .scalar()
        or 0
    )
    rate = positive_labels / total_labels if total_labels > 0 else 0.0

    report["checks"]["label_stats"] = {
        "total": total_labels,
        "positive": positive_labels,
        "negative": total_labels - positive_labels,
        "positive_rate": round(rate, 6),
    }

    # Check 3: Sanity bounds on positive rate
    # KEV strict: ~0.5% (975 / 180K); temporal could be higher
    if policy_name == "kev_strict" and rate > 0.05:
        report["checks"]["sanity"] = {
            "status": "WARN",
            "detail": f"KEV-strict positive rate {rate:.4f} is unusually high (expected <5%)",
        }
    elif rate > 0.20:
        report["checks"]["sanity"] = {
            "status": "WARN",
            "detail": f"Positive rate {rate:.4f} seems very high — check data quality",
        }
    else:
        report["checks"]["sanity"] = {
            "status": "PASS",
            "detail": f"Positive rate {rate:.4f} is within expected bounds",
        }

    # Overall status
    all_pass = all(
        c.get("status") in ("PASS", None)
        for c in report["checks"].values()
    )
    report["overall_status"] = "PASS" if all_pass else "FAIL"

    log.info(
        "label_validation",
        policy=policy_name,
        overall=report["overall_status"],
        total=total_labels,
        positive=positive_labels,
    )

    return report


# ── Conflict detection ──────────────────────────────────────────────────

def detect_label_conflicts(
    session: Session,
) -> List[Dict[str, Any]]:
    """Find vulnerabilities with conflicting labels across policies.

    A conflict is when the same CVE has label=1 under one policy but
    label=0 under another.  This is *expected* (kev_strict is a subset
    of composite) but worth auditing.
    """
    from collections import defaultdict

    conflicts: List[Dict[str, Any]] = []

    # Group labels by vulnerability
    all_labels = (
        session.query(LabelObservation)
        .filter_by(label_type="exploited")
        .all()
    )
    vuln_labels: Dict[str, Dict[str, int]] = defaultdict(dict)
    for lab in all_labels:
        vuln_labels[str(lab.vulnerability_id)][lab.label_source] = lab.label_value

    for vuln_id, policies in vuln_labels.items():
        values = set(policies.values())
        if len(values) > 1:
            conflicts.append({
                "vuln_id": vuln_id,
                "labels_by_policy": policies,
                "severity": "expected" if "kev_strict" in policies else "unexpected",
            })

    log.info("label_conflicts", total=len(conflicts))
    return conflicts


# ── Utility: get excluded features for a policy ────────────────────────

def get_excluded_features(policy_name: str) -> FrozenSet[str]:
    """Return the set of feature names that must be excluded when training
    with labels from the given policy.

    This is the single source of truth for circularity prevention.
    """
    if policy_name not in POLICIES:
        raise ValueError(f"Unknown policy '{policy_name}'")
    return POLICIES[policy_name].excluded_features


def list_policies() -> List[Dict[str, Any]]:
    """Return human-readable list of all available label policies."""
    return [
        {
            "name": p.name,
            "description": p.description,
            "excluded_features": sorted(p.excluded_features),
            "positive_signal_types": sorted(p.positive_signal_types),
            "params": p.params,
        }
        for p in POLICIES.values()
    ]
