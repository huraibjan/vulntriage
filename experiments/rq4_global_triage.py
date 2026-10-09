#!/usr/bin/env python3
"""RQ4 refresh: decision-engine triage accuracy on the CURRENT test split.

The original RQ4 numbers (127 KEV / 31,987 non-KEV) came from an earlier
32k-row test split.  This script recomputes the same evaluation on the
paper's authoritative split (70,831 test CVEs, 277 KEV positives) so all
sections report on one consistent partition.

For every test CVE the SSVC tree is evaluated in global-evidence mode
(asset layers UNKNOWN, criticality MEDIUM):
  exploitation = ACTIVE if kev_flag else POC_PUBLIC if poc flag else
                 THEORETICAL/NONE  (from the feature snapshot)
  epss / cvss  = snapshot values
  ml prob      = paper tabular v2 model output

Reported: % of KEV CVEs in PATCH_NOW/MITIGATE_NOW, action distribution,
and false-escalation rate among non-KEV CVEs.

Usage:  python experiments/rq4_global_triage.py
Saves:  results/rq4_global_triage.json
"""

from __future__ import annotations

import json
import sys
import time
from datetime import date
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.models import FeatureSnapshot
from app.db.session import get_session
from app.features.ablation import get_feature_columns
from app.features.builder import build_labels_df, time_aware_split
from app.schemas.decision import (
    Affectedness,
    ControlStatus,
    Criticality,
    EvidenceInput,
    Exploitation,
    Reachability,
    decide,
)

ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY = "kev_strict"
URGENT = {"patch_now", "mitigate_now"}

RESULTS_DIR = Path("results")
MODELS_DIR = Path("models")


def run() -> dict:
    t0 = time.time()
    print("=" * 72)
    print("  RQ4 refresh: global-mode triage on the authoritative test split")
    print("=" * 72)

    with get_session() as session:
        snaps = session.query(FeatureSnapshot).filter_by(
            asof=ASOF_DATE, feature_version="v1").all()
        rows = [dict(s.features_json, vuln_id=str(s.vulnerability_id)) for s in snaps]
        fdf = pd.DataFrame(rows)
        labels = build_labels_df(session, policy_name=POLICY)
    merged = fdf.merge(labels, on="vuln_id", how="inner")
    _, test_df = time_aware_split(merged, CUTOFF_DATE)
    test_df = test_df.reset_index(drop=True)
    y = test_df["exploited"].astype(int).values
    print(f"  Test: {len(test_df):,} CVEs, {int(y.sum())} KEV positives")

    # ML probabilities from the paper model
    feat_cols = get_feature_columns("no_circular", policy_name=POLICY)
    avail = [c for c in feat_cols if c in test_df.columns]
    model = joblib.load(MODELS_DIR / "xgb_tuned_tabular_v2.joblib")
    ml_p = model.predict_proba(test_df[avail].fillna(0).astype(float))[:, 1]

    kev = test_df.get("kev_flag", pd.Series(0, index=test_df.index)).fillna(0).astype(int).values
    poc = test_df.get("poc_exploitdb_flag", pd.Series(0, index=test_df.index)).fillna(0).astype(int).values
    msf = test_df.get("metasploit_flag", pd.Series(0, index=test_df.index)).fillna(0).astype(int).values
    epss = test_df["epss_score"].fillna(0).values
    cvss = test_df["cvss_base_score"].fillna(0).values
    days = test_df.get("days_since_published", pd.Series(0, index=test_df.index)).fillna(0).values

    actions = []
    for i in range(len(test_df)):
        if kev[i]:
            expl = Exploitation.ACTIVE
        elif poc[i] or msf[i]:
            expl = Exploitation.POC_PUBLIC
        else:
            expl = Exploitation.THEORETICAL
        ev = EvidenceInput(
            affectedness=Affectedness.UNKNOWN,
            reachability=Reachability.UNKNOWN,
            is_internet_facing=False,
            exploitation=expl,
            epss_score=float(epss[i]),
            ml_exploit_prob=float(ml_p[i]),
            days_since_published=int(days[i]),
            control_status=ControlStatus.UNKNOWN,
            asset_criticality=Criticality.MEDIUM,
            cvss_base_score=float(cvss[i]),
        )
        d = decide(ev)
        actions.append(getattr(d.action, "value", d.action))
    actions = np.array(actions)

    kev_mask = y == 1
    n_kev = int(kev_mask.sum())
    kev_urgent = int(np.isin(actions[kev_mask], list(URGENT)).sum())
    nonkev = ~kev_mask
    n_nonkev = int(nonkev.sum())
    nonkev_urgent = int(np.isin(actions[nonkev], list(URGENT)).sum())

    dist_all = pd.Series(actions).value_counts().to_dict()
    dist_kev = pd.Series(actions[kev_mask]).value_counts().to_dict()

    print(f"\n  KEV CVEs in urgent tier      : {kev_urgent}/{n_kev} "
          f"({100*kev_urgent/n_kev:.1f}%)")
    print(f"  KEV action distribution      : {dist_kev}")
    print(f"  Non-KEV false escalations    : {nonkev_urgent}/{n_nonkev:,} "
          f"({100*nonkev_urgent/n_nonkev:.2f}%)")
    print(f"  Overall action distribution  : {dist_all}")

    result = {
        "experiment": "rq4_global_triage_refresh",
        "n_test": len(test_df),
        "n_kev": n_kev,
        "kev_urgent": kev_urgent,
        "kev_urgent_rate": round(kev_urgent / n_kev, 4),
        "kev_action_distribution": dist_kev,
        "n_nonkev": n_nonkev,
        "nonkev_urgent": nonkev_urgent,
        "false_escalation_rate": round(nonkev_urgent / n_nonkev, 4),
        "overall_action_distribution": dist_all,
        "elapsed_seconds": round(time.time() - t0, 1),
    }
    (RESULTS_DIR / "rq4_global_triage.json").write_text(json.dumps(result, indent=2))
    print(f"\n  Saved -> results/rq4_global_triage.json")
    return result


if __name__ == "__main__":
    run()
