"""Tests for the assetless (global) SSVC decision the /v1/predict endpoint
returns. Mirrors the evidence the API builds so backend and UI share one logic
and representative decision paths are covered.
"""

from __future__ import annotations

from app.schemas.decision import (
    Affectedness,
    ControlStatus,
    Criticality,
    EvidenceInput,
    Exploitation,
    Reachability,
    decide,
)

URGENT = {"patch_now", "mitigate_now"}


def _global_evidence(*, kev=False, poc=False, epss=0.0, ml=0.0, cvss=0.0, days=0):
    """Replicates the API's assetless evidence construction."""
    exploitation = (Exploitation.ACTIVE if kev else
                    Exploitation.POC_PUBLIC if poc else Exploitation.THEORETICAL)
    return EvidenceInput(
        affectedness=Affectedness.UNKNOWN,
        reachability=Reachability.UNKNOWN,
        is_internet_facing=False,
        exploitation=exploitation,
        epss_score=epss,
        ml_exploit_prob=ml,
        days_since_published=days,
        control_status=ControlStatus.UNKNOWN,
        asset_criticality=Criticality.MEDIUM,
        cvss_base_score=cvss,
    )


def _action(ev):
    d = decide(ev)
    return getattr(d.action, "value", d.action), d


def test_kev_active_exploitation_is_urgent():
    action, d = _action(_global_evidence(kev=True, epss=0.9, ml=0.95, cvss=9.8))
    assert action in URGENT
    assert d.sla_hours <= 24
    assert d.rationale  # non-empty factor list


def test_low_signal_cve_is_not_urgent():
    action, d = _action(_global_evidence(epss=0.01, ml=0.01, cvss=5.0, days=400))
    assert action not in URGENT
    assert action in {"accept", "monitor", "patch_window"}


def test_high_ml_poc_escalates_above_low_signal():
    """A public-PoC, high-risk CVE should rank at least as urgent as a dormant one."""
    hot, _ = _action(_global_evidence(poc=True, epss=0.8, ml=0.85, cvss=9.0))
    cold, _ = _action(_global_evidence(epss=0.02, ml=0.02, cvss=4.0))
    order = ["accept", "monitor", "patch_window", "mitigate_now", "patch_now"]
    assert order.index(hot) >= order.index(cold)


def test_decision_is_deterministic():
    ev = _global_evidence(kev=True, epss=0.9, ml=0.9, cvss=9.8)
    assert _action(ev)[0] == _action(ev)[0]
