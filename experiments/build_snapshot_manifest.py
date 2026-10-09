#!/usr/bin/env python3
"""Write a versioned manifest of the evaluated snapshot.

Records what the reported results were computed from: database row counts and
date ranges, the label policy, model and reference files with their hashes, and
the result artifacts. The paper lists releasing such a manifest as a requirement
for external validity.

Usage (from project root):
    python experiments/build_snapshot_manifest.py
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text

from app.db.session import get_session
from app.ml import fusion

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "snapshot_manifest.json"

MODEL_FILES = [
    fusion.TABULAR_MODEL, fusion.TABEMB_MODEL, fusion.EMBEDDING_PIPELINE,
    fusion.REFERENCE_FILE, fusion.REFERENCE_META,
]
RESULT_FILES = [
    "ensemble_v2_comparison.csv", "ensemble_fusion_baselines.json", "rrf_k_ablation.json",
    "rolling_window_cv.json", "point_in_time_epss.json", "strict_pit_bound.json",
    "circularity_reconciled.json", "feature_group_ablation.json", "shap_v2.json",
    "statistical_significance.json", "asset_aware_triage.json",
    "asset_aware_triage_corrected_vex_scope.json", "rq4_global_triage.json",
    "rag_eval/rag_eval_summary.json", "rag_eval/rerank_ab_summary.json", "rag_eval/kappa.json",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def files(base: Path, names: list[str]) -> list[dict]:
    out = []
    for name in names:
        path = base / name
        if path.exists():
            out.append({"path": str(path.relative_to(ROOT)), "bytes": path.stat().st_size,
                        "sha256": sha256(path)})
        else:
            out.append({"path": str(path.relative_to(ROOT)), "missing": True})
    return out


def main() -> None:
    with get_session() as session:
        def one(sql: str):
            return session.execute(text(sql)).one()

        n_vuln, first_pub, last_pub = one(
            "SELECT count(*), min(published_at)::date, max(published_at)::date FROM vulnerability")
        signals = {
            row[0]: {"rows": row[1], "first_observed": str(row[2]), "last_observed": str(row[3])}
            for row in session.execute(text(
                "SELECT signal_type, count(*), min(observed_at)::date, max(observed_at)::date "
                "FROM signal_observation GROUP BY signal_type ORDER BY signal_type"))
        }
        n_snap, = one(
            f"SELECT count(*) FROM feature_snapshot WHERE asof = '{fusion.ASOF_DATE}' "
            "AND feature_version = 'v1'")
        kev_cves, = one(
            "SELECT count(DISTINCT vulnerability_id) FROM signal_observation "
            "WHERE signal_type = 'kev' AND value_bool")
        raw_cfg, = one(
            "SELECT count(*) FROM vulnerability WHERE raw_source_json ? 'configurations'")

    reference = json.loads((ROOT / "models" / fusion.REFERENCE_META).read_text())
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "evaluated_configuration": {
            "feature_snapshot_asof": str(fusion.ASOF_DATE),
            "train_test_cutoff": fusion.CUTOFF_DATE,
            "label_policy": fusion.POLICY,
            "feature_policy": fusion.ABLATION,
            "rrf_k": fusion.RRF_K,
            "rank_sources": list(fusion.SOURCES),
            "seed": fusion.SEED,
            "validation_fraction": fusion.VAL_FRACTION,
        },
        "database": {
            "vulnerabilities": n_vuln,
            "published_range": [str(first_pub), str(last_pub)],
            "feature_snapshot_rows": n_snap,
            "kev_listed_cves": kev_cves,
            "cves_with_nvd_configurations": raw_cfg,
            "signals": signals,
        },
        "reference_population": reference,
        "attck_corpus": {"version": "v18.1", "file": "data/attck/enterprise-attack-full.json",
                         **({"sha256": sha256(ROOT / "data/attck/enterprise-attack-full.json")}
                            if (ROOT / "data/attck/enterprise-attack-full.json").exists() else {})},
        "models": files(ROOT / "models", MODEL_FILES),
        "results": files(ROOT / "results", RESULT_FILES),
        "known_evaluation_limits": [
            "Features and KEV labels are a single 2026-03 snapshot; only EPSS is replaced "
            "historically in the sensitivity analysis.",
            "EPSS is stored for one observation date in the database.",
            "The asset experiment uses a synthetic fleet; asset_aware_triage.json predates the "
            "VEX-scope correction and is kept as the published artifact.",
        ],
    }
    OUT.write_text(json.dumps(manifest, indent=2))
    print(f"Wrote {OUT.relative_to(ROOT)}")
    print(json.dumps({k: manifest[k] for k in ("evaluated_configuration", "database")}, indent=1)[:1400])


if __name__ == "__main__":
    main()
