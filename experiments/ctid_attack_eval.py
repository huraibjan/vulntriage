#!/usr/bin/env python3
"""ATT&CK retrieval evaluated against human-curated CTID KEV mappings.

The RQ3 technique-relevance figures in the paper are judged by LLMs, and the
paper names human validation as outstanding. The MITRE Center for
Threat-Informed Defense (CTID) publishes analyst-curated mappings from CISA KEV
CVEs to ATT&CK techniques ("Mappings Explorer"). This script scores the
production retriever against that ground truth, with no LLM in the loop.

For every CVE present in both the CTID file and the VulnTriage database the
query is built and executed exactly as ``generate_llm_brief`` does it
(``build_query_text`` over description, CWE identifiers and affected products,
then ``retrieve_techniques(query, top_k=3)`` with re-ranking disabled).

Reported per slice: hit@1, hit@3, precision@3, recall@3 and MRR, on (i) exact
technique identifiers and (ii) sub-techniques collapsed to their parent on both
sides. ATT&CK version drift is handled explicitly: the CTID file targets an
older ATT&CK release than the corpus indexed in Qdrant, so ground-truth
identifiers absent from the corpus are counted, and every metric is reported
both including and excluding CVEs whose ground truth is entirely absent.

The database is only read (the transaction is declared READ ONLY).

Usage (from project root):
    python experiments/ctid_attack_eval.py download   # fetch + checksum the CTID file
    python experiments/ctid_attack_eval.py run        # evaluate, write results JSON
    python experiments/ctid_attack_eval.py report     # re-print the table
    python experiments/ctid_attack_eval.py selftest   # offline checks of the pure logic

Output:
    results/ctid_attack_eval.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── Provenance of the ground truth ────────────────────────────────────────

CTID_REPO = "center-for-threat-informed-defense/mappings-explorer"
CTID_REPO_PATH = (
    "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/"
    "kev-07.28.2025_attack-16.1-enterprise.json"
)
CTID_URL = f"https://raw.githubusercontent.com/{CTID_REPO}/main/{CTID_REPO_PATH}"
CTID_FILE = ROOT / "data" / "ctid" / "kev-07.28.2025_attack-16.1-enterprise.json"
# Checksum of the file retrieved on 2026-10-08; `run` refuses any other content
# so the reported figures remain tied to one specific ground-truth release.
CTID_SHA256 = "b57b3d382809d9159fdda6701d21f0e67a2d655444d89301caab2c39ad54bdc7"

ATTCK_BUNDLE = ROOT / "data" / "attck" / "enterprise-attack-full.json"
OUT_PATH = ROOT / "results" / "ctid_attack_eval.json"

TOP_K = 3  # generate_llm_brief default (top_k_techniques)
TEST_WINDOW_START = "2024-06-01"  # paper cutoff (app.ml.fusion)
MIN_SLICE_N = 20
METRIC_KEYS = (
    "hit_at_1", "hit_at_3", "precision_at_3", "precision_returned",
    "recall_at_3", "mrr",
)


# ── Pure logic (no I/O; exercised by `selftest`) ──────────────────────────

def parent_technique(technique_id: str) -> str:
    """Collapse a sub-technique identifier (T1059.001) to its parent (T1059)."""
    return technique_id.split(".", 1)[0]


def dedupe(items: Iterable[str]) -> List[str]:
    """Remove duplicates while preserving rank order."""
    seen: set = set()
    out: List[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def parse_ctid(doc: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """Group CTID mapping objects by CVE.

    Rows without an ATT&CK identifier (CTID marks non-mappable capabilities
    this way) are dropped, because they carry no ground truth to score against.
    """
    by_cve: Dict[str, List[Dict[str, str]]] = {}
    for obj in doc.get("mapping_objects", []):
        cve = (obj.get("capability_id") or "").strip().upper()
        tid = (obj.get("attack_object_id") or "").strip().upper()
        if not cve.startswith("CVE-") or not tid.startswith("T"):
            continue
        by_cve.setdefault(cve, []).append(
            {"technique_id": tid, "mapping_type": obj.get("mapping_type") or "uncategorized"}
        )
    return by_cve


def ground_truth(
    mappings: Sequence[Dict[str, str]], mapping_type: Optional[str] = None
) -> List[str]:
    """Distinct ground-truth technique identifiers, optionally for one mapping type."""
    return dedupe(
        m["technique_id"] for m in mappings
        if mapping_type is None or m["mapping_type"] == mapping_type
    )


def score_one(
    retrieved: Sequence[str], truth: Sequence[str], *, k: int = TOP_K, collapse: bool = False
) -> Dict[str, float]:
    """Rank metrics for a single CVE.

    ``precision_at_3`` uses the fixed denominator k, so a query that returns
    fewer than k techniques (similarity floor) or several sub-techniques of one
    parent (collapsed mode) is not rewarded for the shortfall;
    ``precision_returned`` uses the number of distinct identifiers actually
    returned. The reciprocal rank is zero when no relevant technique appears in
    the top k, since the product never surfaces deeper ranks.
    """
    ranked = list(retrieved)
    gold = list(truth)
    if collapse:
        ranked = [parent_technique(t) for t in ranked]
        gold = [parent_technique(t) for t in gold]
    ranked = dedupe(ranked)[:k]
    gold_set = set(gold)
    if not gold_set:
        raise ValueError("score_one requires non-empty ground truth")

    hits = [t in gold_set for t in ranked]
    n_hit = sum(hits)
    rr = 0.0
    for rank, is_hit in enumerate(hits, start=1):
        if is_hit:
            rr = 1.0 / rank
            break
    return {
        "hit_at_1": float(bool(hits) and hits[0]),
        "hit_at_3": float(n_hit > 0),
        "precision_at_3": n_hit / k,
        "precision_returned": n_hit / len(ranked) if ranked else 0.0,
        "recall_at_3": n_hit / len(gold_set),
        "mrr": rr,
    }


def aggregate(rows: Sequence[Dict[str, float]]) -> Dict[str, Any]:
    """Macro-average per-CVE metrics; ``n`` is the number of CVEs averaged."""
    n = len(rows)
    out: Dict[str, Any] = {"n": n}
    for key in METRIC_KEYS:
        out[key] = round(sum(r[key] for r in rows) / n, 5) if n else None
    return out


def evaluate_slice(
    records: Sequence[Dict[str, Any]],
    corpus_ids: set,
    *,
    mapping_type: Optional[str] = None,
    retrieved_key: str = "retrieved",
) -> Dict[str, Any]:
    """Score one slice of CVEs under both matching rules and both drift policies.

    ``all_cves`` keeps every CVE with ground truth of the requested type, so
    identifiers that the corpus cannot return count against the retriever.
    ``excluding_gt_absent_from_corpus`` drops CVEs for which no ground-truth
    identifier exists in the corpus (in collapsed mode: no ground-truth parent).
    """
    corpus_parents = {parent_technique(t) for t in corpus_ids}
    out: Dict[str, Any] = {}
    for mode, collapse in (("exact", False), ("parent_collapsed", True)):
        rows_all: List[Dict[str, float]] = []
        rows_reachable: List[Dict[str, float]] = []
        n_fully_absent = 0
        for rec in records:
            truth = ground_truth(rec["mappings"], mapping_type)
            if not truth:
                continue
            row = score_one(rec[retrieved_key], truth, collapse=collapse)
            rows_all.append(row)
            if collapse:
                reachable = any(parent_technique(t) in corpus_parents for t in truth)
            else:
                reachable = any(t in corpus_ids for t in truth)
            if reachable:
                rows_reachable.append(row)
            else:
                n_fully_absent += 1
        out[mode] = {
            "all_cves": aggregate(rows_all),
            "excluding_gt_absent_from_corpus": aggregate(rows_reachable),
            "n_cves_gt_entirely_absent": n_fully_absent,
        }
    return out


def popularity_baseline(records: Sequence[Dict[str, Any]], k: int = TOP_K) -> List[str]:
    """The k techniques most often mapped across the evaluated CVEs.

    A constant prediction of these identifiers is the reference point a
    content-aware retriever has to exceed. It is fitted on the same CVEs it is
    scored on, which favours the baseline.
    """
    counts: Counter = Counter()
    for rec in records:
        counts.update(ground_truth(rec["mappings"]))
    return [t for t, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:k]]


def corpus_technique_ids(bundle: Dict[str, Any]) -> set:
    """Active Enterprise technique identifiers in a STIX bundle.

    Revoked and deprecated attack-patterns are excluded, matching what the
    Qdrant loader indexes; `run` verifies the equality against the live
    collection.
    """
    ids: set = set()
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                ids.add(ref["external_id"])
    return ids


def sha256_of(path: Path) -> str:
    """Hex SHA-256 of a file."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── I/O ────────────────────────────────────────────────────────────────────

def download() -> None:
    """Fetch the CTID KEV mapping file and print its checksum."""
    import urllib.request

    CTID_FILE.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(CTID_URL, timeout=60) as resp:  # noqa: S310 (fixed https URL)
        data = resp.read()
    CTID_FILE.write_bytes(data)
    digest = sha256_of(CTID_FILE)
    print(f"saved {CTID_FILE} ({len(data)} bytes)\nsha256 {digest}")
    if digest != CTID_SHA256:
        print(f"WARNING: checksum differs from the pinned release {CTID_SHA256}")


def _load_vulnerabilities(cve_ids: Sequence[str]) -> tuple[Dict[str, Dict[str, Any]], int]:
    """Read the retrieval inputs for the given CVEs inside a read-only transaction."""
    from sqlalchemy import text

    from app.db.session import engine

    sql = text(
        "SELECT cve_id, description, cwe_ids, affected_products_json, published_at "
        "FROM vulnerability WHERE cve_id = ANY(:ids) ORDER BY cve_id, created_at, id"
    )
    out: Dict[str, Dict[str, Any]] = {}
    n_duplicate_rows = 0
    with engine.connect() as conn:
        conn.execute(text("SET TRANSACTION READ ONLY"))
        for row in conn.execute(sql, {"ids": list(cve_ids)}).mappings():
            if row["cve_id"] in out:
                n_duplicate_rows += 1  # keep the earliest row, deterministically
                continue
            out[row["cve_id"]] = dict(row)
        conn.rollback()
    return out, n_duplicate_rows


def _qdrant_technique_ids() -> set:
    """Technique identifiers actually indexed in the live ATT&CK collection."""
    from app.ingest.qdrant_loader import ATTCK_COLLECTION, get_qdrant_client

    client = get_qdrant_client()
    ids: set = set()
    offset = None
    while True:
        points, offset = client.scroll(
            collection_name=ATTCK_COLLECTION, limit=512, offset=offset,
            with_payload=["technique_id"], with_vectors=False,
        )
        ids.update(p.payload.get("technique_id") for p in points if p.payload)
        if offset is None:
            break
    ids.discard(None)
    return ids


def run() -> None:
    """Retrieve for every CTID CVE held in the database and write the metrics."""
    from app.core.logging import get_logger
    from app.rag.retriever import build_query_text, retrieve_techniques

    log = get_logger(__name__)

    if not CTID_FILE.exists():
        sys.exit(f"{CTID_FILE} is missing; run the `download` command first.")
    digest = sha256_of(CTID_FILE)
    if digest != CTID_SHA256:
        sys.exit(f"CTID file checksum {digest} differs from pinned {CTID_SHA256}.")

    doc = json.loads(CTID_FILE.read_text())
    by_cve = parse_ctid(doc)

    bundle_ids = corpus_technique_ids(json.loads(ATTCK_BUNDLE.read_text()))
    qdrant_ids = _qdrant_technique_ids()
    # The live collection is what the retriever can return, so it defines the corpus.
    corpus_ids = qdrant_ids

    vulns, n_duplicate_rows = _load_vulnerabilities(sorted(by_cve))
    log.info("ctid_eval_inputs", ctid_cves=len(by_cve), in_db=len(vulns))

    records: List[Dict[str, Any]] = []
    n_empty_description = 0
    for i, cve in enumerate(sorted(vulns), start=1):
        v = vulns[cve]
        if not (v.get("description") or "").strip():
            n_empty_description += 1
        # Mirrors generate_llm_brief step 1 (vuln.get("description", "") etc.).
        query = build_query_text(
            description=v.get("description") or "",
            cwe_ids=v.get("cwe_ids"),
            products=v.get("affected_products_json"),
        )
        techniques = retrieve_techniques(query, top_k=TOP_K, rerank=False)
        published = v.get("published_at")
        records.append({
            "cve_id": cve,
            "published_at": published.date().isoformat() if published else None,
            "mappings": by_cve[cve],
            "retrieved": [t["technique_id"] for t in techniques],
            "similarity": [round(float(t["similarity_score"]), 5) for t in techniques],
        })
        if i % 100 == 0:
            print(f"  retrieved {i}/{len(vulns)}", flush=True)

    baseline_ids = popularity_baseline(records)
    for rec in records:
        rec["baseline"] = baseline_ids

    window = [r for r in records if r["published_at"] and r["published_at"] >= TEST_WINDOW_START]
    mapping_types = sorted({m["mapping_type"] for r in records for m in r["mappings"]})

    def block(recs: Sequence[Dict[str, Any]], key: str) -> Dict[str, Any]:
        res = {"all_mapping_types": evaluate_slice(recs, corpus_ids, retrieved_key=key)}
        for mt in mapping_types:
            res[mt] = evaluate_slice(recs, corpus_ids, mapping_type=mt, retrieved_key=key)
        return res

    gt_all = [m["technique_id"] for r in records for m in r["mappings"]]
    gt_distinct = sorted(set(gt_all))
    absent_distinct = [t for t in gt_distinct if t not in corpus_ids]
    absent_parent_distinct = sorted(
        {parent_technique(t) for t in gt_distinct}
        - {parent_technique(t) for t in corpus_ids}
    )

    result: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ground_truth": {
            "source": "MITRE CTID Mappings Explorer, CISA KEV to ATT&CK",
            "url": CTID_URL,
            "repository": CTID_REPO,
            "repository_path": CTID_REPO_PATH,
            "local_file": str(CTID_FILE.relative_to(ROOT)),
            "sha256": digest,
            "attack_version": doc["metadata"].get("attack_version"),
            "kev_catalog_version": doc["metadata"].get("mapping_framework_version"),
            "creation_date": doc["metadata"].get("creation_date"),
            "last_update": doc["metadata"].get("last_update"),
            "n_mapping_objects": len(doc.get("mapping_objects", [])),
            "n_cves": len(by_cve),
            "mapping_type_counts": dict(Counter(
                m["mapping_type"] for ms in by_cve.values() for m in ms)),
        },
        "retriever": {
            "function": "app.rag.retriever.retrieve_techniques",
            "query": "app.rag.retriever.build_query_text(description, cwe_ids, affected_products_json)",
            "top_k": TOP_K, "rerank": False, "min_score": 0.3,
            "llm_calls": 0,
            "returned_count_distribution": dict(sorted(Counter(
                str(len(r["retrieved"])) for r in records).items())),
        },
        "corpus": {
            "qdrant_collection_techniques": len(qdrant_ids),
            "bundle_file": str(ATTCK_BUNDLE.relative_to(ROOT)),
            "bundle_active_techniques": len(bundle_ids),
            "qdrant_equals_bundle_active": qdrant_ids == bundle_ids,
            "qdrant_minus_bundle": sorted(qdrant_ids - bundle_ids),
            "bundle_minus_qdrant": sorted(bundle_ids - qdrant_ids),
        },
        "coverage": {
            "ctid_cves": len(by_cve),
            "ctid_cves_in_database": len(vulns),
            "ctid_cves_not_in_database": sorted(set(by_cve) - set(vulns)),
            "duplicate_database_rows_ignored": n_duplicate_rows,
            "evaluated_cves_with_empty_description": n_empty_description,
            "evaluated_cves_in_test_window": len(window),
            "test_window_start": TEST_WINDOW_START,
        },
        "version_drift": {
            "distinct_gt_ids": len(gt_distinct),
            "distinct_gt_ids_absent_from_corpus": absent_distinct,
            "n_distinct_gt_ids_absent_from_corpus": len(absent_distinct),
            "gt_mapping_rows": len(gt_all),
            "gt_mapping_rows_absent_from_corpus": sum(t not in corpus_ids for t in gt_all),
            "distinct_gt_parents_absent_from_corpus": absent_parent_distinct,
            "n_cves_with_any_absent_gt_id": sum(
                any(m["technique_id"] not in corpus_ids for m in r["mappings"])
                for r in records),
        },
        "metric_definitions": {
            "averaging": "macro average over CVEs; n is the number of CVEs averaged",
            "hit_at_k": "1 if any of the top-k retrieved identifiers is in the ground truth",
            "precision_at_3": "relevant retrieved / 3 (fixed denominator)",
            "precision_returned": "relevant retrieved / distinct identifiers returned",
            "recall_at_3": "relevant retrieved / distinct ground-truth identifiers",
            "mrr": "reciprocal rank of the first relevant identifier within the top 3, else 0",
            "exact": "identifier equality, sub-techniques distinct from parents",
            "parent_collapsed": "both sides truncated to the parent technique, then de-duplicated",
            "all_cves": "ground-truth identifiers absent from the corpus count as misses",
            "excluding_gt_absent_from_corpus":
                "CVEs whose ground truth has no identifier in the corpus are removed",
        },
        "retriever_metrics": block(records, "retrieved"),
        "retriever_metrics_test_window": (
            block(window, "retrieved") if len(window) >= MIN_SLICE_N else None),
        "popularity_baseline": {
            "description": (
                "Constant prediction of the three most frequently mapped techniques "
                "among the evaluated CVEs; fitted on the evaluated CVEs themselves, "
                "which favours the baseline."),
            "techniques": baseline_ids,
            "metrics": block(records, "baseline"),
            "metrics_test_window": (
                block(window, "baseline") if len(window) >= MIN_SLICE_N else None),
        },
        "per_cve": [
            {k: r[k] for k in ("cve_id", "published_at", "retrieved", "similarity", "mappings")}
            for r in records
        ],
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {OUT_PATH}")
    report()


def _fmt(v: Optional[float]) -> str:
    return "   n/a" if v is None else f"{v:6.3f}"


def _print_block(title: str, blk: Optional[Dict[str, Any]]) -> None:
    print(f"\n{title}")
    if blk is None:
        print(f"  (fewer than {MIN_SLICE_N} CVEs; not reported)")
        return
    head = f"  {'mapping type':<24}{'match':<18}{'drift policy':<14}{'n':>5}"
    head += "".join(f"{h:>8}" for h in ("hit@1", "hit@3", "P@3", "R@3", "MRR"))
    print(head)
    for mt, by_mode in blk.items():
        for mode in ("exact", "parent_collapsed"):
            for policy, label in (("all_cves", "all"),
                                  ("excluding_gt_absent_from_corpus", "excl. absent")):
                m = by_mode[mode][policy]
                print(f"  {mt:<24}{mode:<18}{label:<14}{m['n']:>5}" + "".join(
                    f"  {_fmt(m[k])}" for k in
                    ("hit_at_1", "hit_at_3", "precision_at_3", "recall_at_3", "mrr")))


def report() -> None:
    """Print a compact table from the stored results."""
    if not OUT_PATH.exists():
        sys.exit(f"{OUT_PATH} is missing; run the `run` command first.")
    r = json.loads(OUT_PATH.read_text())
    gt, cov, drift = r["ground_truth"], r["coverage"], r["version_drift"]
    print(f"\nCTID KEV mappings: ATT&CK v{gt['attack_version']}, KEV {gt['kev_catalog_version']}, "
          f"{gt['n_cves']} CVEs, sha256 {gt['sha256'][:12]}...")
    print(f"Evaluated (in CTID and in database): {cov['ctid_cves_in_database']} CVEs; "
          f"{cov['evaluated_cves_in_test_window']} published on or after {cov['test_window_start']}")
    print(f"Corpus: {r['corpus']['qdrant_collection_techniques']} techniques; ground-truth "
          f"identifiers absent from corpus: {drift['n_distinct_gt_ids_absent_from_corpus']} of "
          f"{drift['distinct_gt_ids']} distinct "
          f"({drift['gt_mapping_rows_absent_from_corpus']} of {drift['gt_mapping_rows']} rows)")
    _print_block("Retriever, all evaluated CVEs", r["retriever_metrics"])
    _print_block(f"Retriever, test window (published >= {cov['test_window_start']})",
                 r["retriever_metrics_test_window"])
    _print_block(f"Popularity baseline {r['popularity_baseline']['techniques']}, all evaluated CVEs",
                 r["popularity_baseline"]["metrics"])


def selftest() -> None:
    """Offline assertions over the pure logic (no database, network or model)."""
    assert parent_technique("T1059.001") == "T1059" and parent_technique("T1190") == "T1190"
    assert dedupe(["a", "b", "a"]) == ["a", "b"]

    doc = {"mapping_objects": [
        {"capability_id": "CVE-2024-1", "attack_object_id": "T1190",
         "mapping_type": "exploitation_technique"},
        {"capability_id": "CVE-2024-1", "attack_object_id": "T1059.001",
         "mapping_type": "primary_impact"},
        {"capability_id": "CVE-2024-1", "attack_object_id": "T1190",
         "mapping_type": "primary_impact"},
        {"capability_id": "CVE-2024-2", "attack_object_id": None, "mapping_type": "x"},
        {"capability_id": "CVE-2024-3", "attack_object_id": "T9999",
         "mapping_type": "exploitation_technique"},
    ]}
    by_cve = parse_ctid(doc)
    assert set(by_cve) == {"CVE-2024-1", "CVE-2024-3"}
    assert ground_truth(by_cve["CVE-2024-1"]) == ["T1190", "T1059.001"]
    assert ground_truth(by_cve["CVE-2024-1"], "exploitation_technique") == ["T1190"]

    s = score_one(["T1203", "T1190", "T1059.003"], ["T1190", "T1059.001"])
    assert s == {"hit_at_1": 0.0, "hit_at_3": 1.0, "precision_at_3": 1 / 3,
                 "precision_returned": 1 / 3, "recall_at_3": 0.5, "mrr": 0.5}
    s = score_one(["T1203", "T1190", "T1059.003"], ["T1190", "T1059.001"], collapse=True)
    assert s["precision_at_3"] == 2 / 3 and s["recall_at_3"] == 1.0 and s["mrr"] == 0.5
    # Two sub-techniques of one parent collapse to a single returned identifier.
    s = score_one(["T1059.001", "T1059.003", "T1190"], ["T1059"], collapse=True)
    assert s["hit_at_1"] == 1.0 and s["precision_at_3"] == 1 / 3
    assert s["precision_returned"] == 0.5 and s["mrr"] == 1.0
    s = score_one([], ["T1190"])
    assert all(v == 0.0 for v in s.values())
    # Only the top k ranks are scored.
    assert score_one(["a", "b", "c", "T1190"], ["T1190"])["hit_at_3"] == 0.0
    try:
        score_one(["T1190"], [])
    except ValueError:
        pass
    else:
        raise AssertionError("empty ground truth must be rejected")

    assert aggregate([]) == {"n": 0, **{k: None for k in METRIC_KEYS}}
    records = [
        {"mappings": by_cve["CVE-2024-1"], "retrieved": ["T1190"]},
        {"mappings": by_cve["CVE-2024-3"], "retrieved": ["T1190"]},
    ]
    ev = evaluate_slice(records, {"T1190", "T1059.001"})
    assert ev["exact"]["all_cves"]["n"] == 2 and ev["exact"]["all_cves"]["hit_at_1"] == 0.5
    assert ev["exact"]["excluding_gt_absent_from_corpus"]["n"] == 1
    assert ev["exact"]["excluding_gt_absent_from_corpus"]["hit_at_1"] == 1.0
    assert ev["exact"]["n_cves_gt_entirely_absent"] == 1
    ev = evaluate_slice(records, {"T1190"}, mapping_type="primary_impact")
    assert ev["exact"]["all_cves"]["n"] == 1  # CVE-2024-3 has no primary_impact mapping
    # T1190 is mapped for two CVEs once CVE-2024-1 is counted twice; ties break by identifier.
    assert popularity_baseline(records + records[:1], k=1) == ["T1059.001"]
    assert popularity_baseline(records + [{"mappings": by_cve["CVE-2024-1"][:1]}], k=1) == ["T1190"]

    bundle = {"objects": [
        {"type": "attack-pattern",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]},
        {"type": "attack-pattern", "revoked": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}]},
        {"type": "attack-pattern", "x_mitre_deprecated": True,
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1001"}]},
        {"type": "malware",
         "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}]},
    ]}
    assert corpus_technique_ids(bundle) == {"T1190"}
    print("selftest passed")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    commands = {"download": download, "run": run, "report": report, "selftest": selftest}
    if cmd not in commands:
        sys.exit(__doc__)
    commands[cmd]()
