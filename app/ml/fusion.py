"""Reciprocal Rank Fusion (RRF) serving path.

The evaluated ensemble fuses three rank sources — the leakage-safe tabular
XGBoost model, the tabular+SBERT-embedding XGBoost model, and the EPSS score:

    RRF(d) = sum_r 1 / (k + rank_r(d)),  k = 60

A rank is a position inside a population, so a single CVE cannot be fused in
isolation. For serving, each source score is ranked against a persisted
*reference population*: the held-out test partition of the evaluated split
(CVEs published on or after the 2024-06-01 cutoff). Its scores are
out-of-sample for both models, so the reference distribution is not distorted
by training-set fit.

The fused value orders CVEs. It is NOT a calibrated exploitation probability
and is reported as a rank and percentile within the reference population.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

import joblib
import numpy as np
import pandas as pd

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)

# ── Evaluated configuration (mirrors run_ensemble_v2.py) ───────────────────
ASOF_DATE = date(2026, 3, 3)
CUTOFF_DATE = "2024-06-01"
POLICY = "kev_strict"
ABLATION = "no_circular"
PCA_COMPONENTS = 64
SEED = 42
VAL_FRACTION = 0.15
RRF_K = 60

TABULAR_MODEL = "xgb_tuned_tabular_v2.joblib"
TABEMB_MODEL = "xgb_tuned_tabemb_v2.joblib"
EMBEDDING_PIPELINE = "text_embedding_pipeline_v2.joblib"
REFERENCE_FILE = "rrf_reference_v2.npz"
REFERENCE_META = "rrf_reference_v2.json"

SOURCES = ("xgb_tabular", "xgb_tabemb", "epss")

# Published anchors (results/ensemble_v2_comparison.csv). Building the
# reference fails loudly if the reconstruction does not reproduce them.
ANCHORS = {"xgb_tabular": 0.25069, "xgb_tabemb": 0.30864, "epss": 0.27105, "rrf": 0.36714}
ANCHOR_TOLERANCE = 5e-5


def rrf_fuse(sources: Dict[str, np.ndarray], k: int = RRF_K) -> np.ndarray:
    """Reciprocal Rank Fusion over a population (rank 0 = highest score)."""
    n = len(next(iter(sources.values())))
    scores = np.zeros(n)
    for p in sources.values():
        ranks = np.argsort(np.argsort(-p))
        scores += 1.0 / (k + ranks)
    return scores


def _rank_in(sorted_asc: np.ndarray, value: float) -> int:
    """0-based rank of ``value`` in a population: count of strictly greater scores."""
    return int(len(sorted_asc) - np.searchsorted(sorted_asc, value, side="right"))


def _description_text(description: Optional[str]) -> str:
    return description if description and len(description) > 10 else "No description available."


# ── Reference construction ─────────────────────────────────────────────────

def build_reference(models_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Recompute the three source scores on the held-out partition and persist them.

    Reproduces the evaluated split from the stored feature snapshot, verifies the
    published anchors, and writes the sorted per-source score arrays that the
    serving path ranks against.
    """
    from sklearn.metrics import average_precision_score

    from app.db.models import FeatureSnapshot, Vulnerability
    from app.db.session import get_session
    from app.features.ablation import get_feature_columns
    from app.features.builder import build_labels_df, time_aware_split
    from app.ml.text.embeddings import TextEmbeddingPipeline

    models_dir = Path(models_dir or get_settings().models_dir)

    with get_session() as session:
        snaps = session.query(FeatureSnapshot).filter_by(
            asof=ASOF_DATE, feature_version="v1"
        ).all()
        rows = []
        for s in snaps:
            feat = dict(s.features_json)
            feat["vuln_id"] = str(s.vulnerability_id)
            rows.append(feat)
        features_df = pd.DataFrame(rows)
        labels_df = build_labels_df(session, policy_name=POLICY)
        merged = features_df.merge(labels_df, on="vuln_id", how="inner")
        _, test_df = time_aware_split(merged, CUTOFF_DATE)
        test_df = test_df.reset_index(drop=True)

        ids = test_df["vuln_id"].tolist()
        desc_map: Dict[str, str] = {}
        cve_map: Dict[str, str] = {}
        for i in range(0, len(ids), 10000):
            for vid, cve, desc in session.query(
                Vulnerability.id, Vulnerability.cve_id, Vulnerability.description
            ).filter(Vulnerability.id.in_(ids[i:i + 10000])).all():
                desc_map[str(vid)] = desc or ""
                cve_map[str(vid)] = cve or ""

    texts = [_description_text(desc_map.get(v)) for v in ids]
    y = test_df["exploited"].astype(int).values

    feat_cols = [c for c in get_feature_columns(ABLATION, policy_name=POLICY) if c in test_df.columns]
    X = test_df[feat_cols].fillna(0).astype(float)

    tab = joblib.load(models_dir / TABULAR_MODEL)
    tabemb = joblib.load(models_dir / TABEMB_MODEL)
    pipe = TextEmbeddingPipeline(model_name="all-MiniLM-L6-v2", n_components=PCA_COMPONENTS)
    pipe.load(models_dir / EMBEDDING_PIPELINE)

    emb = pipe.transform_raw(pipe.encode_raw(texts, cache_key="v2_test"))
    emb_cols = [f"emb_{i}" for i in range(emb.shape[1])]
    X_emb = pd.concat([X.reset_index(drop=True), pd.DataFrame(emb, columns=emb_cols)], axis=1)

    sources = {
        "xgb_tabular": tab.predict_proba(X)[:, 1],
        "xgb_tabemb": tabemb.predict_proba(X_emb)[:, 1],
        "epss": test_df["epss_score"].fillna(0).values.astype(float),
    }
    fused = rrf_fuse(sources)

    measured = {name: float(average_precision_score(y, p)) for name, p in sources.items()}
    measured["rrf"] = float(average_precision_score(y, fused))
    mismatches = {
        name: (round(measured[name], 5), anchor)
        for name, anchor in ANCHORS.items()
        if abs(measured[name] - anchor) > ANCHOR_TOLERANCE
    }
    if mismatches:
        raise RuntimeError(
            f"RRF reference does not reproduce the published anchors: {mismatches}. "
            "Refusing to write a reference built from a different pipeline."
        )

    np.savez_compressed(
        models_dir / REFERENCE_FILE,
        xgb_tabular=np.sort(sources["xgb_tabular"]),
        xgb_tabemb=np.sort(sources["xgb_tabemb"]),
        epss=np.sort(sources["epss"]),
        rrf=np.sort(fused),
    )
    meta = {
        "population": "held-out test partition (published on or after cutoff)",
        "n_reference": int(len(y)),
        "n_positives": int(y.sum()),
        "cutoff": CUTOFF_DATE,
        "feature_snapshot_asof": str(ASOF_DATE),
        "label_policy": POLICY,
        "feature_policy": ABLATION,
        "rrf_k": RRF_K,
        "sources": list(SOURCES),
        "pr_auc": {k: round(v, 5) for k, v in measured.items()},
        "anchors_verified": True,
    }
    (models_dir / REFERENCE_META).write_text(json.dumps(meta, indent=2))
    log.info("rrf_reference_built", **{k: v for k, v in meta.items() if k != "pr_auc"})
    return meta


# ── Serving ────────────────────────────────────────────────────────────────

class RRFScorer:
    """Scores one CVE with the three evaluated rank sources and fuses them."""

    def __init__(self, models_dir: Optional[Path] = None):
        from app.ml.text.embeddings import TextEmbeddingPipeline

        models_dir = Path(models_dir or get_settings().models_dir)
        ref_path = models_dir / REFERENCE_FILE
        if not ref_path.exists():
            raise FileNotFoundError(
                f"{ref_path} is missing. Run `vulntriage build-rrf-reference` first."
            )
        ref = np.load(ref_path)
        self.reference = {name: ref[name] for name in (*SOURCES, "rrf")}
        self.meta = json.loads((models_dir / REFERENCE_META).read_text())
        self.n = int(self.meta["n_reference"])

        self.tab = joblib.load(models_dir / TABULAR_MODEL)
        self.tabemb = joblib.load(models_dir / TABEMB_MODEL)
        self.tab_cols = list(self.tab.get_booster().feature_names)
        self.tabemb_cols = list(self.tabemb.get_booster().feature_names)
        self.pipe = TextEmbeddingPipeline(
            model_name="all-MiniLM-L6-v2", n_components=PCA_COMPONENTS
        )
        self.pipe.load(models_dir / EMBEDDING_PIPELINE)
        self._encode_lock = Lock()

    def source_scores(self, features: Dict[str, Any], description: Optional[str]) -> Dict[str, float]:
        row = {c: features.get(c, 0.0) for c in self.tab_cols}
        X = pd.DataFrame([row])[self.tab_cols].fillna(0).astype(float)
        p_tab = float(self.tab.predict_proba(X)[:, 1][0])

        with self._encode_lock:
            raw = self.pipe.encode_raw([_description_text(description)], show_progress=False)
        emb = self.pipe.transform_raw(raw)[0]
        row_emb = dict(row)
        row_emb.update({f"emb_{i}": float(v) for i, v in enumerate(emb)})
        X_emb = pd.DataFrame([row_emb])[self.tabemb_cols].fillna(0).astype(float)
        p_tabemb = float(self.tabemb.predict_proba(X_emb)[:, 1][0])

        epss = float(features.get("epss_score") or 0.0)
        return {"xgb_tabular": p_tab, "xgb_tabemb": p_tabemb, "epss": epss}

    def score(self, features: Dict[str, Any], description: Optional[str]) -> Dict[str, Any]:
        scores = self.source_scores(features, description)
        ranks = {name: _rank_in(self.reference[name], scores[name]) for name in SOURCES}
        fused = float(sum(1.0 / (RRF_K + r) for r in ranks.values()))
        fused_rank = _rank_in(self.reference["rrf"], fused)
        return {
            "rrf_score": fused,
            "rank": fused_rank + 1,
            "n_reference": self.n,
            "percentile": round(100.0 * (1.0 - fused_rank / self.n), 2),
            "k": RRF_K,
            "sources": {
                name: {
                    "score": round(scores[name], 6),
                    "rank": ranks[name] + 1,
                    "percentile": round(100.0 * (1.0 - ranks[name] / self.n), 2),
                }
                for name in SOURCES
            },
            "reference_population": self.meta["population"],
            "calibrated_probability": False,
        }


_scorer: Optional[RRFScorer] = None
_scorer_lock = Lock()


def get_scorer() -> RRFScorer:
    """Process-wide lazily initialised scorer."""
    global _scorer
    if _scorer is None:
        with _scorer_lock:
            if _scorer is None:
                _scorer = RRFScorer()
    return _scorer
