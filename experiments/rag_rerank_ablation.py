#!/usr/bin/env python3
"""RAG quality A/B: bi-encoder baseline vs cross-encoder rerank + gate + CoVe.

Measures whether the retrieval-quality improvements actually raise brief quality
on the SAME top-N test CVEs used in the RQ3 evaluation. Two arms:

  baseline : bi-encoder retrieval only (the paper's current pipeline)
  improved : cross-encoder re-ranking + CRAG relevance gate + Chain-of-
             Verification relevance pass

For every brief in each arm it records:
  - techniques cited / abstention (gate declined all candidates)
  - LLM-judge technique relevance and over-rationalisation (same rubric as
    rag_eval_expansion, GPT-4o judge)
  - RAGAS-style faithfulness (fraction of brief claims supported by context)
  - deterministic STIX / advisory checks (should stay perfect)

The metric aggregation (`summarize`) is pure and unit-tested offline. The
generation/judging loop needs Postgres + Qdrant + an OpenAI key and spends API
credits, so it only runs when invoked explicitly.

Usage (from project root):
    python experiments/rag_rerank_ablation.py run --limit 15   # cheap pilot
    python experiments/rag_rerank_ablation.py run              # full top-150
    python experiments/rag_rerank_ablation.py report           # re-print summary

Outputs:
    results/rag_eval/rerank_ab/<arm>/<CVE>.json     cached briefs per arm
    results/rag_eval/rerank_ab_summary.json         aggregate comparison
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from statistics import mean

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

N_DEFAULT = 150
# The cross-encoder "improved" arm was confirmed inferior in the 15-CVE pilot
# (67% abstention); the full run compares the bi-encoder baseline against the
# LLM relevance filter (CoVe), which gave the better precision/coverage frontier.
ARMS = {
    "baseline": dict(rerank=False, verify_relevance=False),       # bi-encoder only
    "cove_only": dict(rerank=False, verify_relevance=True),       # bi-encoder + CoVe
}

RESULTS_DIR = Path("results") / "rag_eval"
AB_DIR = RESULTS_DIR / "rerank_ab"


# ── Pure aggregation (unit-tested offline, no I/O) ────────────────────────

def summarize(rows: list[dict]) -> dict:
    """Aggregate per-brief metric rows for one arm into summary statistics.

    Each row: {n_techniques, judge_relevant(0/1), over_rationalized(0/1),
               advisory_cited(0/1), fabricated_id(0/1), faithfulness(float|None)}.
    """
    n = len(rows)
    if n == 0:
        return {"n_briefs": 0}
    faith = [r["faithfulness"] for r in rows if r.get("faithfulness") is not None]
    # Relevance is judged only over briefs that actually cite a technique;
    # abstentions (gate declined all) are reported separately, not as "irrelevant".
    with_tech = [r for r in rows if r["n_techniques"] > 0]
    rel_den = len(with_tech) or 1
    return {
        "n_briefs": n,
        "mean_techniques_per_brief": round(mean(r["n_techniques"] for r in rows), 3),
        "abstain_rate": round(sum(1 for r in rows if r["n_techniques"] == 0) / n, 4),
        "technique_relevant_rate": round(
            sum(r["judge_relevant"] for r in with_tech) / rel_den, 4),
        "over_rationalization_rate": round(
            sum(r["over_rationalized"] for r in rows) / n, 4),
        "advisory_citation_rate": round(sum(r["advisory_cited"] for r in rows) / n, 4),
        "fabricated_id_rate": round(sum(r["fabricated_id"] for r in rows) / n, 4),
        "faithfulness_mean": round(mean(faith), 4) if faith else None,
        "n_faithfulness_scored": len(faith),
    }


def _compare(base: dict, imp: dict) -> dict:
    def delta(key):
        b, i = base.get(key), imp.get(key)
        if b is None or i is None:
            return None
        return round(i - b, 4)
    return {k: delta(k) for k in (
        "technique_relevant_rate", "over_rationalization_rate",
        "advisory_citation_rate", "faithfulness_mean", "abstain_rate")}


# ── Experiment run (needs DB + Qdrant + OpenAI) ───────────────────────────

def run(limit: int | None = None) -> None:
    from rag_eval_expansion import (JUDGE_MODEL, JUDGE_SYSTEM, auto_check,
                                    brief_text_for_annotation, select_cves)

    from app.core.settings import get_settings
    from app.db.models import Vulnerability
    from app.db.session import get_session
    from app.rag.attck_loader import (get_technique_registry, load_attck_corpus)
    from app.rag.faithfulness import build_context_text, score_faithfulness
    from app.rag.llm_generator import _get_client, generate_llm_brief
    from app.rag.retriever import build_query_text, retrieve_techniques

    settings = get_settings()
    n = limit or N_DEFAULT
    print(f"[A/B] cross-encoder rerank ablation — top {n} CVEs, arms={list(ARMS)}")
    print("      NOTE: this spends OpenAI credits and needs Postgres + Qdrant.\n")

    top = select_cves().head(n)
    # ensure ATT&CK corpus is loaded for retrieval + grounding
    full = settings.data_dir / "attck" / "enterprise-attack-full.json"
    bundle = full if full.exists() else settings.data_dir / "attck" / "enterprise-attack.json"
    if len(get_technique_registry()) < 100:
        load_attck_corpus(str(bundle))
    client = _get_client()

    import uuid as uuid_mod
    summary = {"experiment": "rag_rerank_ablation", "n_briefs": int(len(top)),
               "arms": {}, "per_arm": {}}

    with get_session() as session:
        vulns = {str(v.id): v for v in session.query(Vulnerability).filter(
            Vulnerability.id.in_([uuid_mod.UUID(v) for v in top["vuln_id"]])).all()}

        for arm, flags in ARMS.items():
            arm_dir = AB_DIR / arm
            arm_dir.mkdir(parents=True, exist_ok=True)
            rows = []
            print(f"── arm: {arm} {flags}")
            for i, rec in top.iterrows():
                v = vulns.get(rec["vuln_id"])
                if v is None or not v.cve_id:
                    continue
                vuln_dict = {
                    "id": str(v.id), "source": v.source, "cve_id": v.cve_id,
                    "vuldb_id": v.vuldb_id, "published_at": v.published_at,
                    "title": v.title, "description": v.description,
                    "cvss_version": v.cvss_version, "cvss_vector": v.cvss_vector,
                    "cvss_base_score": v.cvss_base_score, "cwe_ids": v.cwe_ids,
                    "affected_products_json": v.affected_products_json,
                    "references_json": v.references_json,
                }
                out_path = arm_dir / f"{v.cve_id}.json"
                if out_path.exists():
                    br = json.loads(out_path.read_text())
                else:
                    scores = {"p_stage1": float(rec["p_tabular"]),
                              "p_final": float(rec["p_tabular"])}
                    try:
                        br = generate_llm_brief(vuln_dict, scores,
                                                asof_date="2026-03-03", **flags)
                    except Exception as e:  # noqa: BLE001
                        print(f"   [WARN] {v.cve_id}: {e}")
                        continue
                    out_path.write_text(json.dumps(br, indent=2, default=str))

                checks = auto_check(br, v, get_technique_registry())
                # LLM judge (relevance + over-rationalisation), same rubric
                jprompt = (f"CVE: {v.cve_id}\nCVE DESCRIPTION:\n{(v.description or '')[:600]}"
                           f"\n\nGENERATED BRIEF:\n{brief_text_for_annotation(br)}")
                try:
                    jr = json.loads(client.chat.completions.create(
                        model=JUDGE_MODEL,
                        messages=[{"role": "system", "content": JUDGE_SYSTEM},
                                  {"role": "user", "content": jprompt}],
                        temperature=0.0, max_tokens=200,
                        response_format={"type": "json_object"},
                    ).choices[0].message.content)
                except Exception:  # noqa: BLE001
                    jr = {}
                # RAGAS faithfulness against the retrieved context
                q = build_query_text(v.description or "", v.cwe_ids,
                                     v.affected_products_json)
                techs = retrieve_techniques(q, top_k=3, rerank=flags["rerank"])
                ctx = build_context_text(vuln_dict, techs)
                # faithfulness on the cheaper generator model keeps the full run
                # affordable; the relevance/over-rationalisation judge stays 4o.
                fth = score_faithfulness(client, settings.openai_model,
                                         brief_text_for_annotation(br), ctx)
                rows.append({
                    "cve_id": v.cve_id,
                    "n_techniques": checks["n_techniques_cited"],
                    "judge_relevant": int(bool(jr.get("technique_relevant"))),
                    "over_rationalized": int(bool(jr.get("fabrication_present"))),
                    "advisory_cited": int(bool(checks["advisory_cited_auto"])),
                    "fabricated_id": int(checks["n_fabricated_technique_ids"] > 0),
                    "faithfulness": fth["faithfulness"],
                })
                if len(rows) % 10 == 0:
                    print(f"   … {len(rows)} briefs")
            summary["arms"][arm] = flags
            summary["per_arm"][arm] = summarize(rows)
            print(json.dumps(summary["per_arm"][arm], indent=2))

    base = summary["per_arm"].get("baseline", {})
    summary["improvement_delta"] = {
        arm: _compare(base, summary["per_arm"][arm])
        for arm in summary["per_arm"] if arm != "baseline"
    }
    (RESULTS_DIR / "rerank_ab_summary.json").write_text(json.dumps(summary, indent=2))
    print("\nΔ vs baseline:", json.dumps(summary["improvement_delta"], indent=2))
    print(f"\nSaved -> {RESULTS_DIR}/rerank_ab_summary.json")


def report() -> None:
    p = RESULTS_DIR / "rerank_ab_summary.json"
    if not p.exists():
        print("No summary yet — run:  python experiments/rag_rerank_ablation.py run")
        return
    print(p.read_text())


if __name__ == "__main__":
    t0 = time.time()
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    if mode == "report":
        report()
    else:
        lim = None
        if "--limit" in sys.argv:
            lim = int(sys.argv[sys.argv.index("--limit") + 1])
        run(limit=lim)
    print(f"\n  elapsed: {time.time() - t0:.0f}s")
