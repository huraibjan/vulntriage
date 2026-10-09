#!/usr/bin/env python3
"""Experiment 4: Asset-Aware Triage Ablation.

IEEE Reviewer Revision — addresses Reviewer 2 comment #5.

The paper's SSVC decision engine was evaluated with global CVE evidence only.
This experiment quantifies what asset-level context (SBOM affectedness, VEX
statements, reachability observations, compensating controls, asset
criticality) changes about triage decisions.

DESIGN
------
1. Simulated enterprise fleet (seeded, reproducible): the 4 curated assets
   from data/sample_assets.json plus 46 generated assets whose software
   inventory is drawn from the most frequent (vendor, product) pairs actually
   present in the CVE corpus.  Criticality / internet-facing / control
   distributions follow common enterprise proportions.
2. Asset-CVE pairs are formed by (vendor, product) matching against
   affected_products_json for CVEs published in the paper's TEST window
   (>= 2024-06-01), the same period used for model evaluation.  KEV-positive
   test CVEs are always included; the remainder is a seeded random sample.
3. VEX statements are synthesised for a fraction of matched pairs
   (15% not_affected, 5% affected) and reachability observations for
   internet-facing assets (40% of their pairs), mimicking the coverage an
   organisation obtains from vendor CSAF/VEX feeds and network scanning.
4. Every pair is scored twice through the SAME decision tree (decide()):
     Mode A — global-only: CVE-level evidence (exploitation, EPSS, CVSS,
              ML probability) with UNKNOWN asset layers and default
              criticality — the paper's original configuration.
     Mode B — asset-aware: full 5-layer evidence via build_evidence_input.
   The ML probability is the paper's tabular v2 model output for that CVE.
5. Metrics: decision distribution shift, per-pair change matrix,
   urgent-workload reduction, VEX suppression count, reachability-driven
   escalations, and KEV alignment (share of KEV pairs receiving
   patch_now/mitigate_now) under each mode.

All synthetic rows are tagged (source='sim_r2_5') and deleted at the end
unless --keep is passed, leaving the research DB unchanged.

Usage (from project root):
    python experiments/asset_aware_triage.py [--keep]

Results are saved to results/asset_aware_triage.json.
"""

from __future__ import annotations

import json
import random
import sys
import time
from collections import Counter
from datetime import date, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text as sa_text

from app.db.asset_models import (
    Asset,
    AssetSoftwareObs,
    ControlObs,
    ReachabilityObs,
    VexStatementObs,
)
from app.db.models import FeatureSnapshot, Vulnerability
from app.db.session import get_session
from app.features.ablation import get_feature_columns
from app.features.builder import build_labels_df, time_aware_split
from app.features.policy_engine import build_evidence_input, load_policy_config
from app.features.policy_engine import _resolve_weaponization
from app.schemas.decision import (
    Affectedness,
    ControlStatus,
    Criticality,
    EvidenceInput,
    Reachability,
    decide,
)

MODELS_DIR = Path("models")
RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)

ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY = "kev_strict"
ABLATION = "no_circular"
SEED = 42
SIM_SOURCE = "sim_r2_5"

N_GENERATED_ASSETS = 46
MAX_SAMPLED_TEST_CVES = 2500   # + all KEV positives in the test window

# Software catalogue: common enterprise products confirmed present in the
# corpus (top affected_products_json entries for the test window).
SOFTWARE_CATALOGUE = [
    ("linux", "linux kernel"),
    ("microsoft", "windows server 2019"),
    ("microsoft", "windows server 2012"),
    ("microsoft", "windows 10 1809"),
    ("cisco", "ios"),
    ("cisco", "ios xe"),
    ("cisco", "adaptive security appliance software"),
    ("juniper", "junos"),
    ("adobe", "commerce"),
    ("adobe", "coldfusion"),
    ("adobe", "experience manager"),
    ("google", "android"),
    ("qnap", "qts"),
    ("checkmk", "checkmk"),
    ("liferay", "digital experience platform"),
]

CRITICALITY_DIST = [("critical", 0.10), ("high", 0.25), ("medium", 0.45), ("low", 0.20)]
CONTROL_TYPES = [
    ("waf", 0.75), ("ips", 0.60), ("edr", 0.85), ("network_segmentation", 0.90),
]


def pick_weighted(rng: random.Random, dist):
    r = rng.random()
    acc = 0.0
    for value, p in dist:
        acc += p
        if r <= acc:
            return value
    return dist[-1][0]


# ── Fleet construction ─────────────────────────────────────────────────────

def load_curated_assets() -> list[dict]:
    with open("data/sample_assets.json") as f:
        return json.load(f)


def generate_fleet(rng: random.Random) -> list[dict]:
    fleet = []
    for i in range(N_GENERATED_ASSETS):
        crit = pick_weighted(rng, CRITICALITY_DIST)
        internet_facing = rng.random() < 0.30
        n_sw = rng.randint(2, 6)
        software = [
            {"vendor": v, "product": p, "version": None, "source": "sbom_scan"}
            for v, p in rng.sample(SOFTWARE_CATALOGUE, n_sw)
        ]
        n_controls = rng.randint(0, 3)
        controls = [
            {"control_type": ct, "control_name": ct.upper(), "is_active": True,
             "effectiveness": eff, "source": "api_query"}
            for ct, eff in rng.sample(CONTROL_TYPES, n_controls)
        ]
        fleet.append({
            "name": f"sim-asset-{i:03d}",
            "asset_type": rng.choice(["server", "container", "endpoint", "application"]),
            "environment": rng.choice(["production", "production", "staging", "development"]),
            "criticality": crit,
            "owner": "sim-fleet",
            "is_internet_facing": internet_facing,
            "network_zone": "dmz" if internet_facing else "internal",
            "tags": {"sim": SIM_SOURCE},
            "software": software,
            "reachability": [],
            "controls": controls,
            "vex_statements": [],
        })
    return fleet


def insert_fleet(session, fleet: list[dict]) -> list[Asset]:
    now = datetime(2026, 3, 1)
    assets = []
    for spec in fleet:
        asset = Asset(
            name=spec["name"],
            asset_type=spec.get("asset_type", "server"),
            environment=spec.get("environment"),
            criticality=spec.get("criticality", "medium"),
            owner=spec.get("owner"),
            tags_json={**(spec.get("tags") or {}), "sim": SIM_SOURCE},
            is_internet_facing=spec.get("is_internet_facing", False),
            network_zone=spec.get("network_zone"),
        )
        session.add(asset)
        session.flush()
        for sw in spec.get("software", []):
            session.add(AssetSoftwareObs(
                asset_id=asset.id, vendor=sw["vendor"], product=sw["product"],
                version=sw.get("version"), cpe=sw.get("cpe"),
                observed_at=now, confidence=0.9, source=SIM_SOURCE,
            ))
        for ctl in spec.get("controls", []):
            session.add(ControlObs(
                asset_id=asset.id, control_type=ctl["control_type"],
                control_name=ctl.get("control_name"), is_active=ctl.get("is_active", True),
                effectiveness=ctl.get("effectiveness"), observed_at=now, source=SIM_SOURCE,
            ))
        assets.append(asset)
    session.commit()
    return assets


# ── Pair construction ──────────────────────────────────────────────────────

def build_pairs(session, assets, rng: random.Random):
    """Match asset software to test-window CVEs by (vendor, product)."""
    # Software per asset
    sw_by_asset = {}
    for a in assets:
        rows = session.query(AssetSoftwareObs).filter_by(asset_id=a.id).all()
        sw_by_asset[a.id] = {(r.vendor.lower(), r.product.lower()) for r in rows}

    all_products = set().union(*sw_by_asset.values())

    # Test-window CVEs: all KEV positives + seeded sample of the rest
    labels = build_labels_df(session, policy_name=POLICY)
    snaps = session.query(FeatureSnapshot).filter_by(
        asof=ASOF_DATE, feature_version="v1").all()
    feat_rows = [dict(s.features_json, vuln_id=str(s.vulnerability_id)) for s in snaps]
    fdf = pd.DataFrame(feat_rows).merge(labels, on="vuln_id", how="inner")
    _, test_df = time_aware_split(fdf, CUTOFF_DATE)

    pos_ids = set(test_df.loc[test_df["exploited"] == 1, "vuln_id"])
    neg_ids = list(test_df.loc[test_df["exploited"] == 0, "vuln_id"])
    rng.shuffle(neg_ids)
    chosen = pos_ids | set(neg_ids[:MAX_SAMPLED_TEST_CVES])

    # Pull those vulns and match products
    import uuid as uuid_mod
    vulns = session.query(Vulnerability).filter(
        Vulnerability.id.in_([uuid_mod.UUID(v) for v in chosen])
    ).all()

    pairs = []
    for v in vulns:
        vp = {(str(p.get("vendor", "")).lower(), str(p.get("product", "")).lower())
              for p in (v.affected_products_json or [])}
        matched_products = vp & all_products
        if not matched_products:
            continue
        for a in assets:
            if sw_by_asset[a.id] & matched_products:
                pairs.append((a, v))
    return pairs, test_df


def synthesise_vex_and_reachability(session, pairs, rng: random.Random):
    """Add VEX statements and reachability observations for a pair subset."""
    now = datetime(2026, 3, 1)
    n_vex_na = n_vex_aff = n_reach = 0
    for a, v in pairs:
        r = rng.random()
        if r < 0.15:
            session.add(VexStatementObs(
                vulnerability_id=v.id, asset_id=a.id,
                vendor="vendor", product="product", status="not_affected",
                justification="vulnerable_code_not_present",
                observed_at=now, source=SIM_SOURCE,
            ))
            n_vex_na += 1
        elif r < 0.20:
            session.add(VexStatementObs(
                vulnerability_id=v.id, asset_id=a.id,
                vendor="vendor", product="product", status="affected",
                observed_at=now, source=SIM_SOURCE,
            ))
            n_vex_aff += 1
        if a.is_internet_facing and rng.random() < 0.40:
            session.add(ReachabilityObs(
                asset_id=a.id, vulnerability_id=v.id,
                reachability_type="network", is_reachable=True, confidence=0.9,
                tool="nmap", observed_at=now,
            ))
            n_reach += 1
    session.commit()
    return n_vex_na, n_vex_aff, n_reach


# ── ML probabilities (paper's tabular v2 model) ───────────────────────────

def ml_probs_for(test_df: pd.DataFrame) -> dict[str, float]:
    feat_cols = get_feature_columns(ABLATION, policy_name=POLICY)
    available = [c for c in feat_cols if c in test_df.columns]
    X = test_df[available].fillna(0).astype(float)
    model = joblib.load(MODELS_DIR / "xgb_tuned_tabular_v2.joblib")
    p = model.predict_proba(X)[:, 1]
    return dict(zip(test_df["vuln_id"], p.astype(float)))


# ── Scoring modes ─────────────────────────────────────────────────────────

def decide_global_only(vuln, session, asof, ml_prob, config):
    """Mode A: CVE-level evidence only (paper's original configuration)."""
    exploitation, epss_score = _resolve_weaponization(vuln, session, asof)
    days_since = 0
    if vuln.published_at:
        pub = vuln.published_at.date() if isinstance(vuln.published_at, datetime) \
            else vuln.published_at
        if pub <= asof:
            days_since = (asof - pub).days
    evidence = EvidenceInput(
        affectedness=Affectedness.UNKNOWN,
        reachability=Reachability.UNKNOWN,
        is_internet_facing=False,
        exploitation=exploitation,
        epss_score=epss_score,
        ml_exploit_prob=ml_prob,
        days_since_published=days_since,
        control_status=ControlStatus.UNKNOWN,
        asset_criticality=Criticality.MEDIUM,
        cvss_base_score=vuln.cvss_base_score or 0.0,
    )
    return decide(evidence)


# ── Cleanup ────────────────────────────────────────────────────────────────

def cleanup(session):
    ids = [r[0] for r in session.query(Asset.id).filter(
        Asset.tags_json["sim"].astext == SIM_SOURCE).all()]
    if ids:
        session.query(VexStatementObs).filter(
            VexStatementObs.asset_id.in_(ids)).delete(synchronize_session=False)
        session.query(ReachabilityObs).filter(
            ReachabilityObs.asset_id.in_(ids)).delete(synchronize_session=False)
        session.query(ControlObs).filter(
            ControlObs.asset_id.in_(ids)).delete(synchronize_session=False)
        session.query(AssetSoftwareObs).filter(
            AssetSoftwareObs.asset_id.in_(ids)).delete(synchronize_session=False)
        session.query(Asset).filter(Asset.id.in_(ids)).delete(synchronize_session=False)
        session.commit()
    return len(ids)


# ── Main ───────────────────────────────────────────────────────────────────

URGENT = {"patch_now", "mitigate_now"}


def run(keep: bool = False) -> dict:
    t0 = time.time()
    rng = random.Random(SEED)
    print("=" * 72)
    print("  Experiment 4: Asset-Aware Triage Ablation (R2 #5)")
    print("=" * 72)

    with get_session() as session:
        # Fresh start: remove any prior simulated fleet
        removed = cleanup(session)
        if removed:
            print(f"  (removed {removed} stale simulated assets)")

        # ── 1. Fleet ─────────────────────────────────────────────────────
        print("\n[1/5] Building simulated fleet …")
        fleet = load_curated_assets() + generate_fleet(rng)
        assets = insert_fleet(session, fleet)
        crit_dist = Counter(a.criticality for a in assets)
        print(f"  Assets: {len(assets)}  criticality={dict(crit_dist)}  "
              f"internet-facing={sum(1 for a in assets if a.is_internet_facing)}")

        # ── 2. Pairs ─────────────────────────────────────────────────────
        print("\n[2/5] Matching software inventory to test-window CVEs …")
        pairs, test_df = build_pairs(session, assets, rng)
        uniq_cves = len({v.id for _, v in pairs})
        print(f"  Matched pairs: {len(pairs):,} ({uniq_cves} unique CVEs, "
              f"{len(assets)} assets)")

        # ── 3. Synthesise VEX + reachability ────────────────────────────
        print("\n[3/5] Synthesising VEX and reachability observations …")
        n_vex_na, n_vex_aff, n_reach = synthesise_vex_and_reachability(session, pairs, rng)
        print(f"  VEX not_affected: {n_vex_na}  |  VEX affected: {n_vex_aff}  "
              f"|  reachability obs: {n_reach}")

        # ── 4. Score both modes ─────────────────────────────────────────
        print("\n[4/5] Scoring pairs in both modes …")
        ml_probs = ml_probs_for(test_df)
        vuln_id_str = {v.id: str(v.id) for _, v in pairs}
        kev_ids = set(test_df.loc[test_df["exploited"] == 1, "vuln_id"])
        config = load_policy_config()

        records = []
        global_cache: dict = {}
        for a, v in pairs:
            ml_p = ml_probs.get(vuln_id_str[v.id])
            if v.id not in global_cache:
                global_cache[v.id] = decide_global_only(
                    v, session, ASOF_DATE, ml_p, config)
            d_global = global_cache[v.id]
            evidence = build_evidence_input(
                a, v, session, ASOF_DATE, ml_exploit_prob=ml_p, config=config)
            d_asset = decide(evidence)
            records.append({
                "asset": a.name,
                "criticality": a.criticality,
                "internet_facing": bool(a.is_internet_facing),
                "cve_uuid": str(v.id),
                "is_kev": vuln_id_str[v.id] in kev_ids,
                "action_global": getattr(d_global.action, "value", d_global.action),
                "action_asset": getattr(d_asset.action, "value", d_asset.action),
                "sla_global": d_global.sla_hours,
                "sla_asset": d_asset.sla_hours,
            })
        df = pd.DataFrame(records)
        print(f"  Scored {len(df):,} pairs x 2 modes")

        # ── 5. Metrics ──────────────────────────────────────────────────
        print("\n[5/5] Computing ablation metrics …")
        dist_global = df["action_global"].value_counts().to_dict()
        dist_asset = df["action_asset"].value_counts().to_dict()
        changed = df[df["action_global"] != df["action_asset"]]
        change_rate = len(changed) / len(df)

        urgent_global = int(df["action_global"].isin(URGENT).sum())
        urgent_asset = int(df["action_asset"].isin(URGENT).sum())
        accepted_via_vex = int(((df["action_asset"] == "accept")
                                & (df["action_global"] != "accept")).sum())
        escalated = int((df["action_asset"].isin(URGENT)
                         & ~df["action_global"].isin(URGENT)).sum())
        downgraded = int((~df["action_asset"].isin(URGENT)
                          & df["action_global"].isin(URGENT)).sum())

        kev_df = df[df["is_kev"]]
        kev_urgent_global = float(kev_df["action_global"].isin(URGENT).mean()) if len(kev_df) else None
        kev_urgent_asset = float(kev_df["action_asset"].isin(URGENT).mean()) if len(kev_df) else None

        # Change matrix
        matrix = (df.groupby(["action_global", "action_asset"]).size()
                    .unstack(fill_value=0))
        print("\n  Action distribution (global -> asset-aware):")
        order = ["patch_now", "mitigate_now", "patch_window", "monitor", "accept"]
        for act in order:
            print(f"    {act:<14} {dist_global.get(act, 0):>7,} -> {dist_asset.get(act, 0):>7,}")
        print(f"\n  Pairs with changed decision : {len(changed):,} ({change_rate:.1%})")
        print(f"  Urgent workload (P/M now)   : {urgent_global:,} -> {urgent_asset:,} "
              f"({(urgent_asset-urgent_global)/max(urgent_global,1):+.1%})")
        print(f"  Suppressed via VEX/controls : {downgraded:,} de-escalations "
              f"({accepted_via_vex:,} to accept)")
        print(f"  Escalations (reach+crit)    : {escalated:,}")
        if kev_urgent_global is not None:
            print(f"  KEV pairs urgent-action rate: {kev_urgent_global:.1%} -> {kev_urgent_asset:.1%} "
                  f"(n={len(kev_df)})")
        print(f"  Mean SLA hours              : {df['sla_global'].mean():.0f} -> "
              f"{df['sla_asset'].mean():.0f}")

        result = {
            "experiment": "asset_aware_triage",
            "reviewer_item": "R2-#5",
            "seed": SEED,
            "n_assets": len(assets),
            "n_pairs": len(df),
            "n_unique_cves": uniq_cves,
            "n_kev_pairs": int(df["is_kev"].sum()),
            "synthetic_evidence": {
                "vex_not_affected": n_vex_na,
                "vex_affected": n_vex_aff,
                "reachability_obs": n_reach,
            },
            "action_distribution": {
                "global_only": dist_global,
                "asset_aware": dist_asset,
            },
            "decision_change_rate": round(change_rate, 4),
            "urgent_actions": {"global_only": urgent_global, "asset_aware": urgent_asset},
            "de_escalations": downgraded,
            "accepted_via_vex_or_controls": accepted_via_vex,
            "escalations": escalated,
            "kev_urgent_rate": {
                "global_only": round(kev_urgent_global, 4) if kev_urgent_global is not None else None,
                "asset_aware": round(kev_urgent_asset, 4) if kev_urgent_asset is not None else None,
            },
            "mean_sla_hours": {
                "global_only": round(float(df["sla_global"].mean()), 1),
                "asset_aware": round(float(df["sla_asset"].mean()), 1),
            },
            "change_matrix": {g: row.to_dict() for g, row in matrix.iterrows()},
            "elapsed_seconds": round(time.time() - t0, 1),
        }

        # ── Cleanup ─────────────────────────────────────────────────────
        if keep:
            print("\n  --keep passed: simulated fleet left in DB")
        else:
            n = cleanup(session)
            print(f"\n  Cleaned up {n} simulated assets (+ cascaded observations)")

    (RESULTS_DIR / "asset_aware_triage.json").write_text(json.dumps(result, indent=2))
    print(f"  Saved -> results/asset_aware_triage.json  "
          f"({result['elapsed_seconds']}s)")
    return result


if __name__ == "__main__":
    run(keep="--keep" in sys.argv)
