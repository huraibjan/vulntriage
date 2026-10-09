#!/usr/bin/env python3
"""Experiment 5: Expanded RAG Brief Evaluation with Inter-Annotator Agreement.

IEEE Reviewer Revision — addresses Reviewer 2 comment #2 (and minor #4).

The paper evaluated 50 manually assessed briefs.  This experiment:

  1. Expands the sample to the top-150 test-partition CVEs ranked by the
     paper's RRF ensemble (a superset of the original Precision@50 set).
  2. Generates a STIX-validated brief for each via the production RAG
     pipeline (gpt-4o-mini, temperature 0.3).
  3. Runs AUTOMATIC checks on every brief:
       - technique-ID validity against the ATT&CK v18.1 STIX registry
         (fabrication detection);
       - hallucination-filter telemetry: LLM-proposed technique IDs that the
         retrieval-grounding filter rejected (minor comment #4);
       - vendor-advisory citation presence (matched against the CVE's
         references_json).
  4. Emits TWO blind annotation artifacts for the three RQ3 criteria
     (technique_relevant / advisory_cited / fabrication_present):
       - a randomised human annotation sheet (CSV);
       - an LLM-judge second annotation (gpt-4o, independent prompt, no
         access to the automatic check results).
  5. compute_kappa mode: once the human sheet is filled in, computes
     Cohen's kappa per criterion between the two annotators.

Usage (from project root):
    python experiments/rag_eval_expansion.py generate     # steps 1–4
    python experiments/rag_eval_expansion.py kappa        # step 5

Outputs:
    results/rag_eval/briefs/<CVE>.json         raw briefs
    results/rag_eval/auto_checks.csv           automatic metrics per brief
    results/rag_eval/annotation_human.csv      blind sheet (fill in!)
    results/rag_eval/annotation_llm.csv        LLM-judge annotations
    results/rag_eval/rag_eval_summary.json     aggregate metrics
    results/rag_eval/kappa.json                inter-annotator agreement
"""

from __future__ import annotations

import json
import random
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rrf_k_ablation import reconstruct_split_and_probs, rrf_fuse  # noqa: E402

from app.core.settings import get_settings  # noqa: E402
from app.db.models import Vulnerability  # noqa: E402
from app.db.session import get_session  # noqa: E402
from app.rag.attck_loader import get_technique_registry, load_attck_corpus  # noqa: E402
from app.rag.llm_generator import generate_llm_brief, _get_client  # noqa: E402

settings = get_settings()

RESULTS_DIR = Path("results") / "rag_eval"
BRIEFS_DIR = RESULTS_DIR / "briefs"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
BRIEFS_DIR.mkdir(exist_ok=True)

N_BRIEFS = 150
SEED = 42
ASOF = "2026-03-03"
JUDGE_MODEL = "gpt-4o"          # different (stronger) model than the generator

CRITERIA = ["technique_relevant", "advisory_cited", "fabrication_present"]

JUDGE_SYSTEM = """You are an experienced security analyst independently auditing \
AI-generated CVE vulnerability briefs. The briefs were produced by a RAG system \
that legitimately supplies external enrichment (retrieved MITRE ATT&CK technique \
descriptions, EPSS scores, ML risk scores) alongside the CVE record; such \
system-provided enrichment is NOT fabrication. Answer strictly in JSON with \
three boolean fields:
  technique_relevant : at least one cited MITRE ATT&CK technique is plausibly \
relevant to how this vulnerability would be exploited
  advisory_cited     : the brief cites a specific vendor advisory, patch URL, \
KB article, or concrete versioned upgrade path for remediation
  fabrication_present: the brief INVENTS specifics - e.g. technique IDs or \
names not present in the brief's own ATT&CK list, product/version claims \
contradicting the CVE description, made-up URLs, or invented exploit details. \
Generic security advice, hedged inference, and system-provided scores are NOT \
fabrication.
Be strict but fair. JSON only."""


# ── Step 1: select top-150 CVEs by RRF ────────────────────────────────────

def select_cves() -> pd.DataFrame:
    print("[1/4] Selecting top-150 test CVEs by RRF ranking …")
    _sv, _yv, sources_test, y_test, extra = reconstruct_split_and_probs()
    test_df = extra["test_df"].copy()
    test_df["rrf_score"] = rrf_fuse(sources_test, k=60)
    test_df["p_tabular"] = sources_test["xgb_tabular"]
    top = test_df.nlargest(N_BRIEFS, "rrf_score").reset_index(drop=True)
    print(f"  Selected {len(top)} CVEs "
          f"({int(top['exploited'].sum())} KEV-positive)")
    return top


# ── Step 2+3: generate briefs + automatic checks ──────────────────────────

def advisory_pattern(references_json) -> re.Pattern | None:
    urls = [r.get("url", "") for r in (references_json or []) if r.get("url")]
    hosts = {re.sub(r"^www\.", "", u.split("/")[2]) for u in urls if "://" in u}
    if not hosts:
        return None
    return re.compile("|".join(re.escape(h) for h in hosts), re.I)


def auto_check(brief_result: dict, vuln: Vulnerability, registry: dict) -> dict:
    brief = brief_result["brief"]
    llm = brief_result.get("llm_analysis", {})

    cited_ids = [m["technique_id"] for m in brief.get("attck", [])]
    llm_proposed = [a.get("technique_id") for a in llm.get("attck_analysis", [])
                    if a.get("technique_id")]

    valid_cited = [t for t in cited_ids if t in registry]
    fabricated_cited = [t for t in cited_ids if t not in registry]
    # Hallucination-filter telemetry: LLM proposed but not retrieval-grounded
    filtered_out = [t for t in llm_proposed if t not in cited_ids]
    fabricated_proposed = [t for t in llm_proposed if t not in registry]

    text_blob = json.dumps(llm) + json.dumps(brief.get("remediation", []))
    pat = advisory_pattern(vuln.references_json)
    advisory_cited_auto = bool(pat.search(text_blob)) if pat else False
    # generic advisory mention fallback
    if not advisory_cited_auto:
        advisory_cited_auto = bool(re.search(
            r"(advisory|security bulletin|KB\d{6,}|patch.*(available|released)|"
            r"upgrade to [\w.\-]+\d)", text_blob, re.I))

    return {
        "n_techniques_cited": len(cited_ids),
        "n_valid_technique_ids": len(valid_cited),
        "n_fabricated_technique_ids": len(fabricated_cited),
        "fabricated_ids": ";".join(fabricated_cited),
        "n_llm_proposed": len(llm_proposed),
        "n_filtered_by_grounding": len(filtered_out),
        "filtered_ids": ";".join(filtered_out),
        "n_fabricated_proposed": len(fabricated_proposed),
        "advisory_cited_auto": advisory_cited_auto,
        "stix_verified": bool(brief_result.get("verification", {}).get("valid")),
        "n_verify_errors": len(brief_result.get("verification", {}).get("errors", [])),
    }


def brief_text_for_annotation(brief_result: dict) -> str:
    llm = brief_result.get("llm_analysis", {})
    brief = brief_result["brief"]
    parts = [f"SUMMARY: {llm.get('executive_summary', '')}"]
    for m in brief.get("attck", []):
        parts.append(f"ATT&CK: {m['technique_id']} ({m['technique_name']}) — "
                     f"{m.get('rationale', '')[:300]}")
    for r in brief.get("remediation", []):
        urls = [e.get("text", "") for e in r.get("evidence", [])
                if e.get("source") == "Vendor advisory"]
        cite = f"  [advisory: {urls[0]}]" if urls else ""
        parts.append(f"REMEDIATION [{r.get('priority')}]: "
                     f"{r.get('action', '')[:300]}{cite}")
    if llm.get("confidence_notes"):
        parts.append(f"NOTES: {llm['confidence_notes'][:300]}")
    return "\n".join(parts)


def generate(top: pd.DataFrame) -> None:
    print("\n[2/4] Generating briefs via RAG pipeline …")
    # Load the FULL ATT&CK v18.1 corpus (691 active techniques) for retrieval
    # grounding + fabrication checks.  Falls back to the bundled sample.
    full_bundle = settings.data_dir / "attck" / "enterprise-attack-full.json"
    bundle = full_bundle if full_bundle.exists() else \
        settings.data_dir / "attck" / "enterprise-attack.json"
    if len(get_technique_registry()) < 100:
        load_attck_corpus(str(bundle))
    registry = get_technique_registry()
    print(f"  ATT&CK registry: {len(registry)} techniques ({bundle.name})")

    rows = []
    with get_session() as session:
        import uuid as uuid_mod
        vulns = {str(v.id): v for v in session.query(Vulnerability).filter(
            Vulnerability.id.in_([uuid_mod.UUID(v) for v in top["vuln_id"]])).all()}

        for i, rec in top.iterrows():
            v = vulns.get(rec["vuln_id"])
            if v is None or not v.cve_id:
                continue
            out_path = BRIEFS_DIR / f"{v.cve_id}.json"
            if out_path.exists():                      # resume support
                brief_result = json.loads(out_path.read_text())
            else:
                vuln_dict = {
                    "id": str(v.id), "source": v.source, "cve_id": v.cve_id,
                    "vuldb_id": v.vuldb_id, "published_at": v.published_at,
                    "title": v.title, "description": v.description,
                    "cvss_version": v.cvss_version, "cvss_vector": v.cvss_vector,
                    "cvss_base_score": v.cvss_base_score, "cwe_ids": v.cwe_ids,
                    "affected_products_json": v.affected_products_json,
                    "references_json": v.references_json,
                }
                scores = {"p_stage1": float(rec["p_tabular"]),
                          "p_final": float(rec["p_tabular"])}
                try:
                    brief_result = generate_llm_brief(
                        vuln_dict, scores, asof_date=ASOF)
                except Exception as e:  # noqa: BLE001
                    print(f"  [WARN] {v.cve_id}: {e}")
                    continue
                out_path.write_text(json.dumps(brief_result, indent=2, default=str))

            checks = auto_check(brief_result, v, registry)
            rows.append({
                "cve_id": v.cve_id,
                "kev_positive": int(rec["exploited"]),
                "rrf_rank": i + 1,
                "description": (v.description or "")[:600],
                "brief_text": brief_text_for_annotation(brief_result),
                **checks,
            })
            if (i + 1) % 25 == 0:
                print(f"  … {i + 1}/{len(top)} briefs")

    df = pd.DataFrame(rows)
    df.to_csv(RESULTS_DIR / "auto_checks.csv", index=False)
    print(f"  Generated/loaded {len(df)} briefs -> auto_checks.csv")

    # ── Step 4a: blind human sheet (randomised) ─────────────────────────
    rng = random.Random(SEED)
    order = list(range(len(df)))
    rng.shuffle(order)
    human = df.iloc[order][["cve_id", "description", "brief_text"]].copy()
    for c in CRITERIA:
        human[c] = ""            # fill with 1/0
    human.to_csv(RESULTS_DIR / "annotation_human.csv", index=False)
    print("  Blind human sheet -> annotation_human.csv  (fill the 3 columns with 1/0)")

    # ── Step 4b: LLM judge ──────────────────────────────────────────────
    print("\n[3/4] LLM-judge second annotation (gpt-4o) …")
    client = _get_client()
    judge_rows = []
    for _, r in df.iterrows():
        prompt = (f"CVE: {r['cve_id']}\nCVE DESCRIPTION:\n{r['description']}\n\n"
                  f"GENERATED BRIEF:\n{r['brief_text']}")
        try:
            resp = client.chat.completions.create(
                model=JUDGE_MODEL,
                messages=[{"role": "system", "content": JUDGE_SYSTEM},
                          {"role": "user", "content": prompt}],
                temperature=0.0, max_tokens=200,
                response_format={"type": "json_object"},
            )
            j = json.loads(resp.choices[0].message.content)
        except Exception as e:  # noqa: BLE001
            print(f"  [WARN] judge {r['cve_id']}: {e}")
            j = {}
        judge_rows.append({
            "cve_id": r["cve_id"],
            **{c: int(bool(j.get(c, False))) for c in CRITERIA},
        })
        if len(judge_rows) % 25 == 0:
            print(f"  … {len(judge_rows)}/{len(df)} judged")
    jdf = pd.DataFrame(judge_rows)
    jdf.to_csv(RESULTS_DIR / "annotation_llm.csv", index=False)
    print("  LLM-judge annotations -> annotation_llm.csv")

    # ── Aggregate summary ───────────────────────────────────────────────
    print("\n[4/4] Aggregate automatic metrics …")
    summary = {
        "experiment": "rag_eval_expansion",
        "reviewer_item": "R2-#2 (+minor #4)",
        "n_briefs": len(df),
        "n_kev_positive": int(df["kev_positive"].sum()),
        "generator_model": settings.openai_model,
        "judge_model": JUDGE_MODEL,
        "automatic_checks": {
            "briefs_with_valid_technique": int((df["n_valid_technique_ids"] > 0).sum()),
            "briefs_with_fabricated_technique_id": int((df["n_fabricated_technique_ids"] > 0).sum()),
            "fabricated_id_rate": round(float((df["n_fabricated_technique_ids"] > 0).mean()), 4),
            "briefs_with_advisory_citation": int(df["advisory_cited_auto"].sum()),
            "advisory_citation_rate": round(float(df["advisory_cited_auto"].mean()), 4),
            "stix_verified_rate": round(float(df["stix_verified"].mean()), 4),
            "hallucination_filter": {
                "total_llm_proposed_techniques": int(df["n_llm_proposed"].sum()),
                "total_filtered_by_grounding": int(df["n_filtered_by_grounding"].sum()),
                "briefs_with_filtered_techniques": int((df["n_filtered_by_grounding"] > 0).sum()),
                "total_fabricated_proposed": int(df["n_fabricated_proposed"].sum()),
            },
        },
        "llm_judge_rates": {c: round(float(jdf[c].mean()), 4) for c in CRITERIA},
    }
    (RESULTS_DIR / "rag_eval_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary["automatic_checks"], indent=2))
    print(f"\n  Saved -> {RESULTS_DIR}/rag_eval_summary.json")
    print("\n  NEXT STEP: fill annotation_human.csv, then run "
          "`python experiments/rag_eval_expansion.py kappa`")


# ── Step 5: Cohen's kappa ─────────────────────────────────────────────────

def cohens_kappa(a: np.ndarray, b: np.ndarray) -> float:
    po = float((a == b).mean())
    pe = float((a == 1).mean() * (b == 1).mean() + (a == 0).mean() * (b == 0).mean())
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def kappa() -> None:
    hdf = pd.read_csv(RESULTS_DIR / "annotation_human.csv")
    jdf = pd.read_csv(RESULTS_DIR / "annotation_llm.csv")
    merged = hdf.merge(jdf, on="cve_id", suffixes=("_human", "_llm"))

    out = {"n_briefs": len(merged), "criteria": {}}
    print(f"  {'Criterion':<22} {'human%':>7} {'llm%':>6} {'agree%':>7} {'kappa':>7}")
    print("  " + "-" * 54)
    for c in CRITERIA:
        h = pd.to_numeric(merged[f"{c}_human"], errors="coerce")
        l = pd.to_numeric(merged[f"{c}_llm"], errors="coerce")
        mask = h.notna() & l.notna()
        if mask.sum() == 0:
            print(f"  {c:<22} — no human annotations yet")
            continue
        hv, lv = h[mask].astype(int).values, l[mask].astype(int).values
        k = cohens_kappa(hv, lv)
        agree = float((hv == lv).mean())
        out["criteria"][c] = {
            "n": int(mask.sum()),
            "human_positive_rate": round(float(hv.mean()), 4),
            "llm_positive_rate": round(float(lv.mean()), 4),
            "percent_agreement": round(agree, 4),
            "cohens_kappa": round(k, 4),
        }
        print(f"  {c:<22} {hv.mean():>6.1%} {lv.mean():>5.1%} {agree:>6.1%} {k:>7.3f}")

    (RESULTS_DIR / "kappa.json").write_text(json.dumps(out, indent=2))
    print(f"\n  Saved -> {RESULTS_DIR}/kappa.json")


if __name__ == "__main__":
    t0 = time.time()
    mode = sys.argv[1] if len(sys.argv) > 1 else "generate"
    if mode == "kappa":
        kappa()
    else:
        top = select_cves()
        generate(top)
    print(f"\n  Total elapsed: {time.time() - t0:.0f}s")
