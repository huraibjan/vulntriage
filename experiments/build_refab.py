#!/usr/bin/env python3
"""Generate a focused re-judge page for ONLY the fabrication criterion.

The first human pass marked fabrication_present = Yes on all 150 briefs, which
reflected a broad reading of the term. This tool re-collects only that column
under the narrow definition (invents a specific unsupported fact), preserving
the existing technique_relevant and advisory_cited answers so the exported
annotation_human.csv stays complete.

Usage:  python experiments/build_refab.py
Output: experiments/refab.html
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTO = ROOT / "results" / "rag_eval" / "auto_checks.csv"
PRIOR = ROOT / "results" / "rag_eval" / "annotation_human.csv"
OUT = Path(__file__).resolve().parent / "refab.html"


def main() -> None:
    briefs = {r["cve_id"]: {"description": r["description"], "brief": r["brief_text"]}
              for r in csv.DictReader(open(AUTO))}
    prior = {r["cve_id"]: r for r in csv.DictReader(open(PRIOR))}
    # keep the same (shuffled) order the author already worked in
    items = [{"cve_id": cid,
              "description": briefs[cid]["description"],
              "brief": briefs[cid]["brief"],
              "technique_relevant": prior[cid]["technique_relevant"],
              "advisory_cited": prior[cid]["advisory_cited"]}
             for cid in prior if cid in briefs]
    data = json.dumps(items, ensure_ascii=False)
    OUT.write_text(_TEMPLATE.replace("/*__DATA__*/", data), encoding="utf-8")
    print(f"Wrote {OUT}  ({len(items)} briefs, fabrication-only)")
    print("Open it, re-judge fabrication, Download CSV -> save as "
          "results/rag_eval/annotation_human.csv")


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnTriage — Re-judge Fabrication</title>
<style>
  :root{--bg:#faf9f7;--card:#fff;--ink:#111;--muted:#666;--line:#e3e0da;
        --yes:#b3261e;--no:#0a7d33;--accent:#2a5db0;}
  *{box-sizing:border-box;}
  body{margin:0;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);}
  header{position:sticky;top:0;background:var(--card);border-bottom:1px solid var(--line);padding:10px 18px;display:flex;gap:16px;align-items:center;flex-wrap:wrap;}
  header h1{font-size:15px;margin:0;font-weight:700;}
  .bar{flex:1;height:8px;background:var(--line);border-radius:5px;overflow:hidden;min-width:160px;}
  .bar>div{height:100%;background:var(--accent);width:0;transition:width .2s;}
  .count{font-variant-numeric:tabular-nums;font-size:13px;color:var(--muted);}
  main{max-width:820px;margin:0 auto;padding:18px;}
  .def{font-size:13px;background:#fff4f4;border:1px solid #f0c9c9;border-radius:8px;padding:12px 14px;margin-bottom:14px;line-height:1.5;}
  .def b{color:#b3261e;}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;}
  .cve{font-weight:700;font-size:15px;color:var(--accent);}
  h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:16px 0 6px;}
  .text{font-size:14px;line-height:1.5;white-space:pre-wrap;}
  .brief{background:#f6f4ef;border-radius:8px;padding:12px 14px;}
  .q{border-top:1px solid var(--line);padding:16px 0 4px;margin-top:12px;}
  .q p{margin:0 0 10px;font-size:15px;font-weight:600;}
  .opts{display:flex;gap:10px;}
  button.opt{flex:1;padding:12px;border:1.5px solid var(--line);background:#fff;border-radius:8px;cursor:pointer;font-size:15px;font-weight:600;}
  button.opt.no.sel{background:var(--no);color:#fff;border-color:var(--no);}
  button.opt.yes.sel{background:var(--yes);color:#fff;border-color:var(--yes);}
  nav{display:flex;gap:10px;align-items:center;margin-top:16px;}
  nav button{padding:9px 16px;border:1px solid var(--line);background:#fff;border-radius:8px;cursor:pointer;font-size:14px;}
  nav button.primary{background:var(--accent);color:#fff;border-color:var(--accent);}
  .dl{margin-left:auto;}
  .kbd{font:600 11px ui-monospace,Menlo,monospace;background:#eee;border:1px solid #ddd;border-radius:4px;padding:1px 5px;}
  .done{color:var(--no);font-weight:700;}
</style>
</head>
<body>
<header>
  <h1>Re-judge: Fabrication only</h1>
  <div class="bar"><div id="prog"></div></div>
  <span class="count"><span id="idx">1</span>/<span id="tot">0</span> · answered <span id="ans">0</span></span>
  <button class="primary" id="dl">Download CSV</button>
</header>
<main>
  <div class="def">
    <b>Fabrication = the brief states a SPECIFIC fact that is NOT supported by the CVE:</b>
    a made-up ATT&amp;CK technique ID or name, a version number, a URL, or a product/impact claim
    that is not in the CVE data. &nbsp;<b>NOT fabrication:</b> generic security advice, hedged
    language, the system-provided EPSS / ML / ATT&amp;CK values, or a correctly-retrieved technique.
    Keys: <span class="kbd">0</span>=No (default, most briefs) &nbsp; <span class="kbd">1</span>=Yes &nbsp;
    <span class="kbd">&larr;</span>/<span class="kbd">&rarr;</span> navigate.
  </div>
  <div class="card">
    <div class="cve" id="cve"></div>
    <h3>CVE description</h3><div class="text" id="desc"></div>
    <h3>Generated brief</h3><div class="text brief" id="brief"></div>
    <div class="q">
      <p>Does this brief fabricate a specific fact not supported by the CVE?</p>
      <div class="opts"><button class="opt no">No (0)</button><button class="opt yes">Yes (1)</button></div>
    </div>
    <nav><button id="prev">&larr; Prev</button><button id="next" class="primary">Next &rarr;</button>
      <span id="status" class="dl"></span></nav>
  </div>
</main>
<script>
const ITEMS = /*__DATA__*/;
const KEY = "vulntriage_refab_v1";
let fab = JSON.parse(localStorage.getItem(KEY) || "{}");
let i = 0;
const $ = id => document.getElementById(id);
$("tot").textContent = ITEMS.length;
function save(){ localStorage.setItem(KEY, JSON.stringify(fab)); }
function nAns(){ return ITEMS.filter(x => fab[x.cve_id]===0 || fab[x.cve_id]===1).length; }
function render(){
  const it = ITEMS[i];
  $("cve").textContent = it.cve_id;
  $("desc").textContent = it.description || "(no description)";
  $("brief").textContent = it.brief;
  $("idx").textContent = i+1;
  const v = fab[it.cve_id];
  document.querySelector(".no").classList.toggle("sel", v===0);
  document.querySelector(".yes").classList.toggle("sel", v===1);
  const n = nAns(); $("ans").textContent = n;
  $("prog").style.width = (100*n/ITEMS.length)+"%";
  $("status").innerHTML = n===ITEMS.length ? '<span class="done">All 150 done — Download CSV</span>' : "";
}
function setV(v){ fab[ITEMS[i].cve_id]=v; save(); render(); if(i<ITEMS.length-1){ i++; render(); } }
document.querySelector(".no").onclick=()=>setV(0);
document.querySelector(".yes").onclick=()=>setV(1);
$("prev").onclick=()=>{ i=Math.max(0,i-1); render(); };
$("next").onclick=()=>{ i=Math.min(ITEMS.length-1,i+1); render(); };
document.addEventListener("keydown",e=>{
  if(e.key==="0") setV(0); else if(e.key==="1") setV(1);
  else if(e.key==="ArrowRight"){ i=Math.min(ITEMS.length-1,i+1); render(); }
  else if(e.key==="ArrowLeft"){ i=Math.max(0,i-1); render(); }
});
$("dl").onclick=()=>{
  const n=nAns();
  if(n<ITEMS.length && !confirm(`Only ${n}/${ITEMS.length} re-judged. Download anyway?`)) return;
  let out="cve_id,technique_relevant,advisory_cited,fabrication_present\n";
  for(const it of ITEMS){ const f=fab[it.cve_id];
    out+=`${it.cve_id},${it.technique_relevant},${it.advisory_cited},${f===1?1:(f===0?0:"")}\n`; }
  const url=URL.createObjectURL(new Blob([out],{type:"text/csv"}));
  const a=document.createElement("a"); a.href=url; a.download="annotation_human.csv"; a.click();
  URL.revokeObjectURL(url);
};
render();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
