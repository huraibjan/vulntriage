#!/usr/bin/env python3
"""Second independent automated annotator + Cohen's kappa (R2-2).

Reviewer 2 asked for inter-annotator agreement to demonstrate the objectivity
of the RAG brief evaluation.  We use TWO INDEPENDENT AUTOMATED ANNOTATORS of
different model generations, disclosed truthfully (no human-labeled data is
claimed):

  Annotator A: GPT-4o        -> results/rag_eval/annotation_llm.csv  (existing)
  Annotator B: GPT-5.1       -> results/rag_eval/annotation_llm2.csv (this run)

Both judge the SAME 150 briefs from CVE description + brief text alone, under
the same blind rubric, with no access to the automatic STIX/citation checks.
Cohen's kappa is computed per criterion between A and B.

Usage:  python experiments/second_annotator_kappa.py
Writes: results/rag_eval/annotation_llm2.csv, results/rag_eval/kappa.json
"""

from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from openai import OpenAI

from app.core.settings import get_settings
from rag_eval_expansion import CRITERIA, JUDGE_SYSTEM, cohens_kappa

RES = Path("results/rag_eval")
ANNOTATOR_A = "gpt-4o"           # existing annotation_llm.csv
ANNOTATOR_B = "gpt-5.1"          # this run
B_OUT = RES / "annotation_llm2.csv"


def judge_all(client, rows) -> list[dict]:
    out = []
    for i, r in enumerate(rows, 1):
        prompt = (f"CVE: {r['cve_id']}\nCVE DESCRIPTION:\n{r['description']}\n\n"
                  f"GENERATED BRIEF:\n{r['brief_text']}")
        try:
            # GPT-5.x uses the same chat.completions interface; it ignores
            # temperature and uses default sampling, which is fine for a
            # second independent rater.
            resp = client.chat.completions.create(
                model=ANNOTATOR_B,
                messages=[{"role": "system", "content": JUDGE_SYSTEM},
                          {"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
            )
            j = json.loads(resp.choices[0].message.content)
        except Exception as e:  # noqa: BLE001
            print(f"  [WARN] {r['cve_id']}: {e}")
            j = {}
        out.append({"cve_id": r["cve_id"],
                    **{c: int(bool(j.get(c, False))) for c in CRITERIA}})
        if i % 25 == 0:
            print(f"  … {i}/{len(rows)} judged by {ANNOTATOR_B}")
    return out


def main() -> None:
    t0 = time.time()
    print("=" * 68)
    print(f"  Second annotator ({ANNOTATOR_B}) + Cohen's kappa")
    print("=" * 68)

    rows = list(csv.DictReader(open(RES / "auto_checks.csv")))
    print(f"\n[1/3] Judging {len(rows)} briefs with {ANNOTATOR_B} …")

    if B_OUT.exists():
        print(f"  Reusing existing {B_OUT.name}")
        b_rows = list(csv.DictReader(open(B_OUT)))
    else:
        client = OpenAI(api_key=get_settings().openai_api_key)
        b_rows = judge_all(client, rows)
        with open(B_OUT, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["cve_id", *CRITERIA])
            w.writeheader()
            w.writerows(b_rows)
        print(f"  Saved -> {B_OUT}")

    # ── Load both annotators aligned on cve_id ──────────────────────────
    print("\n[2/3] Aligning annotators A (GPT-4o) and B (GPT-5.1) …")
    a = {r["cve_id"]: r for r in csv.DictReader(open(RES / "annotation_llm.csv"))}
    b = {r["cve_id"]: r for r in b_rows}
    common = [c for c in a if c in b]
    print(f"  {len(common)} briefs rated by both")

    # ── Cohen's kappa per criterion ─────────────────────────────────────
    print("\n[3/3] Cohen's kappa (annotator A vs B) …")
    out = {"annotator_a": ANNOTATOR_A, "annotator_b": ANNOTATOR_B,
           "n_briefs": len(common), "criteria": {}}
    print(f"  {'Criterion':<22}{'A pos%':>8}{'B pos%':>8}{'agree%':>8}{'kappa':>8}  {'strength':<12}")
    print("  " + "-" * 66)
    for c in CRITERIA:
        av = np.array([int(a[k][c]) for k in common])
        bv = np.array([int(b[k][c]) for k in common])
        k = cohens_kappa(av, bv)
        agree = float((av == bv).mean())
        strength = ("almost perfect" if k >= 0.81 else "substantial" if k >= 0.61
                    else "moderate" if k >= 0.41 else "fair" if k >= 0.21
                    else "slight")
        out["criteria"][c] = {
            "n": len(common),
            "annotator_a_positive_rate": round(float(av.mean()), 4),
            "annotator_b_positive_rate": round(float(bv.mean()), 4),
            "percent_agreement": round(agree, 4),
            "cohens_kappa": round(k, 4),
            "strength": strength,
        }
        print(f"  {c:<22}{av.mean():>7.1%}{bv.mean():>8.1%}{agree:>8.1%}"
              f"{k:>8.3f}  {strength:<12}")

    mean_k = float(np.mean([v["cohens_kappa"] for v in out["criteria"].values()]))
    out["mean_kappa"] = round(mean_k, 4)
    print(f"\n  Mean kappa across criteria: {mean_k:.3f}")

    (RES / "kappa.json").write_text(json.dumps(out, indent=2))
    print(f"  Saved -> {RES}/kappa.json  ({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
