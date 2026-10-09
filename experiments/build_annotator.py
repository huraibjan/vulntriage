#!/usr/bin/env python3
"""Generate a self-contained local annotation page for the 150 RAG briefs.

The author opens experiments/annotate.html in any browser, rates each brief on
the three RQ3 criteria, and downloads annotation_human.csv (the exact columns
the kappa step expects). No server, no dependencies; progress is auto-saved to
the browser's localStorage so annotation can be paused and resumed.

Usage:  python experiments/build_annotator.py
Output: experiments/annotate.html
"""

from __future__ import annotations

import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTO = ROOT / "results" / "rag_eval" / "auto_checks.csv"
OUT = Path(__file__).resolve().parent / "annotate.html"
SEED = 42


def main() -> None:
    rows = list(csv.DictReader(open(AUTO)))
    briefs = [{
        "cve_id": r["cve_id"],
        "description": r["description"],
        "brief": r["brief_text"],
    } for r in rows]
    random.Random(SEED).shuffle(briefs)   # reduce order bias, reproducible
    data = json.dumps(briefs, ensure_ascii=False)

    html = _TEMPLATE.replace("/*__DATA__*/", data)
    OUT.write_text(html, encoding="utf-8")
    print(f"Wrote {OUT}  ({len(briefs)} briefs)")
    print("Open it in a browser, annotate all, then Download CSV ->")
    print("  save as results/rag_eval/annotation_human.csv")


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VulnTriage — Brief Annotation</title>
<style>
  :root { --bg:#faf9f7; --card:#fff; --ink:#111; --muted:#666; --line:#e3e0da;
          --yes:#0a7d33; --no:#b3261e; --accent:#2a5db0; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         background:var(--bg); color:var(--ink); }
  header { position:sticky; top:0; background:var(--card); border-bottom:1px solid var(--line);
           padding:10px 18px; display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  header h1 { font-size:15px; margin:0; font-weight:700; }
  .bar { flex:1; height:8px; background:var(--line); border-radius:5px; overflow:hidden; min-width:160px; }
  .bar > div { height:100%; background:var(--accent); width:0; transition:width .2s; }
  .count { font-variant-numeric:tabular-nums; font-size:13px; color:var(--muted); }
  main { max-width:820px; margin:0 auto; padding:18px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:18px 20px; }
  .cve { font-weight:700; font-size:15px; color:var(--accent); }
  h3 { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted);
       margin:16px 0 6px; }
  .text { font-size:14px; line-height:1.5; white-space:pre-wrap; }
  .brief { background:#f6f4ef; border-radius:8px; padding:12px 14px; }
  .q { border-top:1px solid var(--line); padding:14px 0 4px; }
  .q p { margin:0 0 8px; font-size:14px; }
  .q .hint { color:var(--muted); font-size:12.5px; }
  .opts { display:flex; gap:10px; }
  button.opt { flex:1; padding:10px; border:1.5px solid var(--line); background:#fff; border-radius:8px;
               cursor:pointer; font-size:14px; font-weight:600; }
  button.opt.yes.sel { background:var(--yes); color:#fff; border-color:var(--yes); }
  button.opt.no.sel  { background:var(--no);  color:#fff; border-color:var(--no); }
  nav { display:flex; gap:10px; align-items:center; margin-top:16px; }
  nav button { padding:9px 16px; border:1px solid var(--line); background:#fff; border-radius:8px;
               cursor:pointer; font-size:14px; }
  nav button.primary { background:var(--accent); color:#fff; border-color:var(--accent); }
  .dl { margin-left:auto; }
  .kbd { font:600 11px ui-monospace,Menlo,monospace; background:#eee; border:1px solid #ddd;
         border-radius:4px; padding:1px 5px; }
  .rubric { font-size:12.5px; color:var(--muted); background:#fffbe9; border:1px solid #f0e6b8;
            border-radius:8px; padding:10px 12px; margin-bottom:14px; }
  .done { color:var(--yes); font-weight:700; }
</style>
</head>
<body>
<header>
  <h1>VulnTriage — Brief Annotation</h1>
  <div class="bar"><div id="prog"></div></div>
  <span class="count"><span id="idx">1</span>/<span id="tot">0</span> &nbsp;·&nbsp;
        answered <span id="ans">0</span></span>
  <button class="primary" id="dl">Download CSV</button>
</header>
<main>
  <div class="rubric">
    Rate each brief from the CVE description + brief text only. Keys:
    <span class="kbd">1</span>=Yes <span class="kbd">0</span>=No for the focused question;
    <span class="kbd">&larr;</span>/<span class="kbd">&rarr;</span> navigate.
    <b>technique_relevant</b>: at least one cited ATT&amp;CK technique plausibly fits how this CVE
    is exploited. <b>advisory_cited</b>: the brief cites a specific vendor advisory / patch URL /
    concrete versioned fix. <b>fabrication_present</b>: the brief invents specifics not supported
    by the CVE (made-up IDs, versions, URLs, or facts) — generic advice is NOT fabrication.
  </div>
  <div class="card">
    <div class="cve" id="cve"></div>
    <h3>CVE description</h3><div class="text" id="desc"></div>
    <h3>Generated brief</h3><div class="text brief" id="brief"></div>

    <div class="q" data-k="technique_relevant">
      <p>1. <b>Technique relevant?</b> <span class="hint">a cited ATT&amp;CK technique fits this CVE</span></p>
      <div class="opts"><button class="opt yes">Yes (1)</button><button class="opt no">No (0)</button></div>
    </div>
    <div class="q" data-k="advisory_cited">
      <p>2. <b>Advisory cited?</b> <span class="hint">specific advisory / patch / versioned fix</span></p>
      <div class="opts"><button class="opt yes">Yes (1)</button><button class="opt no">No (0)</button></div>
    </div>
    <div class="q" data-k="fabrication_present">
      <p>3. <b>Fabrication present?</b> <span class="hint">invents specifics not in the CVE</span></p>
      <div class="opts"><button class="opt yes">Yes (1)</button><button class="opt no">No (0)</button></div>
    </div>

    <nav>
      <button id="prev">&larr; Prev</button>
      <button id="next" class="primary">Next &rarr;</button>
      <span id="status" class="dl"></span>
    </nav>
  </div>
</main>
<script>
const BRIEFS = /*__DATA__*/;
const CRIT = ["technique_relevant","advisory_cited","fabrication_present"];
const KEY = "vulntriage_annotations_v1";
let ans = JSON.parse(localStorage.getItem(KEY) || "{}");
let i = 0, focus = 0;

const $ = id => document.getElementById(id);
document.getElementById("tot").textContent = BRIEFS.length;

function save(){ localStorage.setItem(KEY, JSON.stringify(ans)); }
function answeredCount(){ return BRIEFS.filter(b => {
  const a = ans[b.cve_id]; return a && CRIT.every(c => a[c] === 0 || a[c] === 1);
}).length; }

function render(){
  const b = BRIEFS[i];
  $("cve").textContent = b.cve_id;
  $("desc").textContent = b.description || "(no description)";
  $("brief").textContent = b.brief;
  $("idx").textContent = i+1;
  const a = ans[b.cve_id] || {};
  document.querySelectorAll(".q").forEach((q,qi) => {
    const k = q.dataset.k, v = a[k];
    q.querySelector(".yes").classList.toggle("sel", v===1);
    q.querySelector(".no").classList.toggle("sel", v===0);
    q.style.outline = qi===focus ? "2px solid var(--accent)" : "none";
    q.style.outlineOffset = "4px"; q.style.borderRadius = "8px";
  });
  const n = answeredCount();
  $("ans").textContent = n;
  $("prog").style.width = (100*n/BRIEFS.length)+"%";
  $("status").innerHTML = n===BRIEFS.length ? '<span class="done">All 150 done — Download CSV</span>' : "";
}
function setVal(k,v){ const c=BRIEFS[i].cve_id; ans[c]=ans[c]||{}; ans[c][k]=v; save(); render(); }
function go(d){ i=Math.max(0,Math.min(BRIEFS.length-1,i+d)); focus=0; render(); }

document.querySelectorAll(".q").forEach(q => {
  q.querySelector(".yes").onclick = () => setVal(q.dataset.k,1);
  q.querySelector(".no").onclick  = () => setVal(q.dataset.k,0);
});
$("prev").onclick = () => go(-1);
$("next").onclick = () => go(1);
document.addEventListener("keydown", e => {
  if(e.key==="ArrowRight") go(1);
  else if(e.key==="ArrowLeft") go(-1);
  else if(e.key==="1"||e.key==="0"){ setVal(CRIT[focus], e.key==="1"?1:0); focus=(focus+1)%3; render(); }
  else if(e.key==="ArrowDown"){ focus=(focus+1)%3; render(); e.preventDefault(); }
  else if(e.key==="ArrowUp"){ focus=(focus+2)%3; render(); e.preventDefault(); }
});
$("dl").onclick = () => {
  const n = answeredCount();
  if(n<BRIEFS.length && !confirm(`Only ${n}/${BRIEFS.length} answered. Download anyway?`)) return;
  let out = "cve_id,"+CRIT.join(",")+"\n";
  for(const b of BRIEFS){ const a=ans[b.cve_id]||{};
    out += b.cve_id+","+CRIT.map(c => a[c]===1?1:(a[c]===0?0:"")).join(",")+"\n"; }
  const blob = new Blob([out],{type:"text/csv"});
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url; link.download = "annotation_human.csv"; link.click();
  URL.revokeObjectURL(url);
};
render();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
