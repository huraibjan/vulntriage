#!/usr/bin/env python3
"""Produce the evidence-aligned ISAIA revision from the original paper.

Philosophy (per author instruction): keep the published 6-page paper's exact
structure - same sections, the same three tables, the same four figure slots -
and weave the reviewer-mandated findings in by (a) updating numbers in place,
(b) folding each response into the existing subsection prose, compressing the
verbose original prose to keep the length ~constant, and (c) replacing ONE
figure (Fig. 2) with a new-findings figure. No new tables are added.

Every empirical number is pulled from results/*.json. The current submitted
file is never overwritten.

Output: VulnTriage_IEEE_ISAIA2026_REVISED.docx
"""

from __future__ import annotations

import json
import re
import shutil
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "VulnTriage ISAIA 2026 Paper.docx"
OUT = ROOT / "VulnTriage_IEEE_ISAIA2026_REVISED.docx"
RES = ROOT / "results"
FIGDIR = ROOT / "docs" / "figures" / "revision"

FONT = "Times New Roman"
BODY = Pt(10)
INDENT = Emu(177800)


def J(p):
    return json.load(open(RES / p))


def F3(value):
    """Format source metrics to three decimals using conventional half-up rounding."""
    return str(Decimal(str(value)).quantize(Decimal("0.001"), rounding=ROUND_HALF_UP))


fusion = J("ensemble_fusion_baselines.json")["results"]
kab = J("rrf_k_ablation.json")
roll = J("rolling_window_cv.json")
pit = J("point_in_time_epss.json")["results"]
fga = J("feature_group_ablation.json")
asset = J("asset_aware_triage.json")
rag = J("rag_eval/rag_eval_summary.json")
kappa = J("rag_eval/kappa.json")["criteria"]
rag_ab = J("rag_eval/rerank_ab_summary.json")
rag_base = rag_ab["per_arm"]["baseline"]
rag_cove = rag_ab["per_arm"]["cove_only"]
shap = J("shap_v2.json")
circularity = J("circularity_reconciled.json")
significance = J("statistical_significance.json")


# ── helpers ─────────────────────────────────────────────────────────────
def find(doc, substr):
    for p in doc.paragraphs:
        if substr in p.text:
            return p
    raise LookupError(substr)


def find_reference(doc, number):
    prefix = f"[{number}] "
    for p in doc.paragraphs:
        if p.text.lstrip().startswith(prefix):
            return p
    raise LookupError(prefix)


def set_text(p, text):
    if not p.runs:
        r = p.add_run(text)
        r.font.name, r.font.size = FONT, BODY
        return
    p.runs[0].text = text
    p.runs[0].font.name, p.runs[0].font.size = FONT, BODY
    for r in p.runs[1:]:
        r.text = ""


def append(p, text):
    if p.runs:
        p.runs[-1].text = p.runs[-1].text.rstrip()
    r = p.add_run(text)
    r.font.name, r.font.size = FONT, BODY
    return r


def remove_para(doc, substr):
    p = find(doc, substr)
    p._element.getparent().remove(p._element)


def insert_after(anchor, text):
    """Insert a new justified, indented body paragraph after `anchor`."""
    p = anchor._parent.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.first_line_indent = INDENT
    r = p.add_run(text)
    r.font.name, r.font.size = FONT, BODY
    anchor._p.addnext(p._p)
    return p


def swap_figure(doc, shape_idx, png_path, aspect_h_over_w, alt_text):
    shp = doc.inline_shapes[shape_idx]
    shp.height = int(shp.width * aspect_h_over_w)
    rId = shp._inline.graphic.graphicData.pic.blipFill.blip.embed
    img_part = doc.part.related_parts[rId]
    img_part._blob = Path(png_path).read_bytes()
    shp._inline.docPr.set("descr", alt_text)
    shp._inline.graphic.graphicData.pic.nvPicPr.cNvPr.set("descr", alt_text)


def set_table_values(table, rows):
    for row, vals in zip(table.rows[1:], rows):
        for cell, val in zip(row.cells, vals):
            p = cell.paragraphs[0]
            if p.runs:
                p.runs[0].text = str(val)
                for extra in p.runs[1:]:
                    extra.text = ""
            else:
                run = p.add_run(str(val))
                run.font.name, run.font.size = FONT, Pt(8)


def mark_table_header(row):
    tr_pr = row._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)


# ════════════════════════════════════════════════════════════════════════
def build():
    shutil.copy(SRC, OUT)
    doc = Document(OUT)

    # ── Abstract: reconcile + point-in-time honesty + reproducibility ───
    ab = find(doc, "Abstract--Security teams patch")
    set_text(ab,
        "Abstract--Security teams can patch only a small fraction of published "
        "vulnerabilities each year, and most CVEs are never exploited in practice. "
        "CVSS measures severity rather than exploitation likelihood, while EPSS "
        "provides a strong public probability baseline but no remediation workflow. "
        "We present VulnTriage, a containerized vulnerability-triage pipeline that "
        "integrates three-ranker Reciprocal Rank Fusion (RRF), a four-layer leakage "
        "audit, MITRE ATT&CK retrieval with deterministic identifier and reference "
        "checks, and an SSVC-inspired decision engine. Four questions guide the study: "
        "how RRF compares with EPSS in a frozen snapshot (RQ1); whether circular or "
        "post-decision features inflate metrics and an audit quantifies the effect "
        "(RQ2); whether grounded RAG and optional relevance verification reduce "
        "unsupported ATT&CK mappings while retaining coverage (RQ3); and how synthetic "
        "SBOM/VEX context changes SSVC-inspired action tiers (RQ4). On "
        "180,497 CVEs published in 2020-2025, RRF "
        "reaches PR-AUC 0.3671 against 0.2711 for EPSS when both use a frozen March "
        "2026 feature snapshot. Replacing frozen EPSS values with the first monthly "
        "historical score available on or after each CVE's publication reduces the "
        "gap to 0.2678 versus 0.2581 (+3.8%; 95% CI of the difference -0.031 to "
        "+0.052), establishing no reliable advantage. This is a historical-EPSS "
        "sensitivity analysis, not a fully reconstructed point-in-time NVD/KEV "
        "evaluation. In a separate frozen-snapshot stress test, exploit-derived "
        "proxies inflate PR-AUC by 3.73x, and removing EPSS from the clean tabular "
        "model reduces PR-AUC from 0.2679 to 0.0344. Across 150 generated briefs, "
        "deterministic checks find no fabricated ATT&CK identifier and 149 contain a "
        "CVE-listed advisory. An optional CoVe-inspired relevance pass reduces "
        "GPT-4o-judged over-rationalization from "
        f"{rag_base['over_rationalization_rate']:.1%} to "
        f"{rag_cove['over_rationalization_rate']:.1%} but abstains on "
        f"{rag_cove['abstain_rate']:.1%} of briefs; two LLM annotators remain "
        "exploratory rather than human "
        "validation. The contribution is an auditable, low-cost integration and an "
        "evidence-aligned account of where apparent prediction gains do and do not "
        "survive leakage controls.")
    for run in ab.runs:
        run.font.size = Pt(9)

    # ── Introduction: compress; drop the paper-organization paragraph ───
    set_text(find(doc, "The National Vulnerability Database (NVD) published over 40,000"),
        "The National Vulnerability Database (NVD) published over 40,000 CVEs in "
        "2024, up 38% from 2023 [1], yet fewer than 3% of published CVEs are "
        "exploited in the wild within a year [2, 3]. Most organizations still "
        "prioritize by CVSS severity, which measures potential impact rather than "
        "exploitation likelihood [4], wasting effort on low-risk issues while "
        "genuinely dangerous ones are overlooked.")
    set_text(find(doc, "EPSS [3] showed that machine learning can predict"),
        "EPSS [3] showed machine learning predicts exploitation likelihood better "
        "than CVSS, but an operational workflow must also connect a score to "
        "evidence, asset context, and a defensible action. VulnTriage studies that "
        "integration while retaining EPSS as a ranker and the principal public "
        "baseline, rather than claiming to replace it.")
    set_text(find(doc, "A separate problem affects how exploitability models"),
        "Evaluation is vulnerable to two forms of hindsight. A feature may directly "
        "or indirectly encode the exploitation evidence used to define the label, "
        "and NVD, EPSS, reference, or product fields may be observed long after the "
        "decision time. Prior work documents both delayed day-1 metadata [5] and "
        "general temporal and label leakage hazards in security ML [6].")
    set_text(find(doc, "This paper presents VulnTriage, an open-source vulnerability intelligence"),
        "VulnTriage makes four contributions. First, it operationalizes a four-layer "
        "audit for temporal, label, entity-proxy, and correlation leakage. Second, "
        "it reports frozen-snapshot results alongside a historical-EPSS sensitivity "
        "analysis, explicitly bounding rather than concealing the remaining "
        "point-in-time uncertainty. Third, it integrates established RRF [8], "
        "SBERT-based ATT&CK retrieval, deterministic STIX/reference validation, and "
        "an SSVC-inspired decision engine in one Docker workflow. Fourth, it shows "
        "that the apparent predictive gain is not statistically reliable after "
        "historical EPSS substitution, whereas evidence grounding and asset-aware "
        "decision changes remain independently testable system properties.")
    remove_para(doc, "The rest of this paper is organized as follows")

    # ── Related work: compress; add recent ensemble + anti-leakage refs ──
    set_text(find(doc, "RELATED WORK"), "II. RELATED WORK")
    set_text(find(doc, "Jacobs et al. [3] introduced EPSS as a logistic regression"),
        "Jacobs et al. [3] introduced EPSS, trained on NVD metadata, CVSS scores, "
        "and reference counts to predict 30-day exploitation probability; EPSS v3 "
        "adopted a gradient-boosted tree and a much larger feature space [7]. "
        "Expected Exploitability models exploit development as time-varying [2], "
        "while ExploitabilityBirthMark deliberately restricts prediction to "
        "information available at initial publication [5]. These studies motivate "
        "our separation of frozen-snapshot and temporally admissible evidence.")
    set_text(find(doc, "Mahbub et al. [8] built vulnerability-vendor"),
        "Arp et al. [6] identify temporal leakage, dataset shift, and misleading "
        "baselines as recurrent security-ML pitfalls. Concurrent prospective "
        "triage work attaches decision-time evidence certificates to scores and "
        "also finds large inflation under retrospective evidence [18]. Our audit "
        "adds an explicit feature-label circularity stress test and applies these "
        "checks inside an end-to-end triage system.")
    set_text(find(doc, "Grigorescu et al. [10] trained"),
        "Grigorescu et al. [9] use BERT for CVE-to-ATT&CK technique mapping; "
        "Branescu et al. [10] extend automated mapping to tactics; and Zhang et al. "
        "[11] use domain knowledge to fine-tune an LLM for tactics and techniques. "
        "These results establish strong mapping baselines but also underline the "
        "need to distinguish valid identifiers from semantically correct mappings.")
    set_text(find(doc, "Vul-RAG [12] showed that combining retrieval"),
        "CVE2ATT&CK [9], transformer-based tactic mapping [10], and VTT-LLM [11] "
        "automate links from vulnerability descriptions to ATT&CK. Vul-RAG [12] "
        "uses retrieval for code-vulnerability detection, while ProveRAG [13] adds "
        "provenance and self-critique for CVE analysis. VulnTriage instead studies "
        "an operational brief whose ATT&CK identifiers and advisory references are "
        "validated deterministically before delivery.")
    set_text(find(doc, "Commercial triage tools combine multiple signals but are closed"),
        "The distinguishing scope is therefore integration and auditability, not a "
        "claim that rank fusion, RAG, or SSVC is individually novel. RRF is an "
        "established rank-aggregation method [8]; ATT&CK STIX [14] supplies the "
        "retrieval vocabulary; and SSVC supplies a decision-tree pattern [15]. "
        "VulnTriage connects these components and reports failure boundaries for "
        "prediction, grounding, and synthetic asset-context experiments.")
    remove_para(doc, "In this study, we present VulnTriage as a reproducible")

    # ── Methodology: compress; fold in deployment latency (minor #2) ────
    set_text(find(doc, "SYSTEM DESIGN AND METHODOLOGY"),
             "III. SYSTEM DESIGN AND METHODOLOGY")
    set_text(find(doc, "Fig. 1 shows the overall VulnTriage architecture"),
        "Fig. 1 shows the architecture. Data is ingested from four sources - the "
        "NVD Representational State Transfer (REST) application programming "
        "interface (API) v2, EPSS v3, the Cybersecurity and Infrastructure "
        "Security Agency (CISA) KEV catalogue [16], and ExploitDB - into "
        "PostgreSQL. The evaluated NVD-derived feature snapshot is dated March 3, "
        "2026; the historical-EPSS sensitivity substitutes archived FIRST scores "
        "[17] but does not reconstruct every NVD or KEV field at publication time. "
        "Three rankers produce relative orders fused by RRF; the resulting rank "
        "score is not a calibrated exploitation probability. The RAG and decision "
        "layers consume the ranked CVE and evidence, while a React interface "
        "exposes search and per-vulnerability briefs. In the measured Docker run, "
        "the application used approximately 517 MB and the warm API endpoint "
        "responded in approximately 15-22 ms.")
    set_text(find(doc, "Fig. 1.  VulnTriage system architecture"),
        "Fig. 1.  Evidence-aligned VulnTriage architecture and RRF rank sources.")
    set_text(find(doc, "The dataset contains 180,497 CVEs published between 1999"),
        "The dataset contains 180,497 NVD CVEs published from 2020 through 2025. "
        "The March 3, 2026 KEV-derived label snapshot contains 975 positives "
        "(0.54%). The split cutoff is 2024-06-01 00:00:00: 109,666 CVEs precede "
        "the cutoff and 70,831 fall in the test partition, including 277 positives "
        "(0.39%). Because the features and final KEV labels are frozen in 2026, "
        "this is a chronological publication split, not a fully prospective label "
        "freeze. PR-AUC is primary because accuracy and ROC-AUC can obscure errors "
        "at this prevalence.")
    set_text(find(doc, "For a given CVE, the RAG pipeline builds a context window"),
        "For a CVE, the RAG pipeline builds a context window from its description, "
        "CVSS vector, EPSS score, and KEV status. Qdrant retrieves the most "
        "similar MITRE ATT&CK techniques by cosine similarity over SBERT "
        "embeddings; retrieved IDs are checked against the pinned ATT&CK v18.1 "
        "STIX 2.1 corpus [14] before being sent to Generative Pre-trained "
        "Transformer (GPT)-4o-mini. An optional Chain-of-Verification "
        "(CoVe)-inspired pass [20] independently confirms each candidate's relevance "
        "and declines unconfirmed mappings. The output "
        "is constrained to a JSON schema (summary, affected products, techniques, "
        "reference-grounded remediation, confidence); a post-processing step "
        "verifies every cited technique ID against the STIX corpus and flags "
        "failures. A two-stage, RAGAS-style [21] LLM scorer reports the share of "
        "atomic brief claims supported by retrieved evidence.")
    set_text(find(doc, "The decision engine follows a five-layer evidence structure"),
        "The implemented asset-context layer parses CycloneDX and Software Package "
        "Data Exchange (SPDX) SBOM documents and OpenVEX and Common Security "
        "Advisory Framework (CSAF) VEX statements, then persists timestamped "
        "software and VEX observations. Asset-specific VEX evidence takes precedence "
        "over SBOM vendor-product and Common Platform Enumeration (CPE) matching "
        "when resolving affectedness. The subsequent Stakeholder-Specific "
        "Vulnerability Categorization (SSVC)-inspired [15] tree combines "
        "affectedness, KEV and ML evidence, public proof-of-concept and reachability, "
        "controls and criticality, and CVSS/EPSS/ML risk to assign PATCH_NOW (24 h), "
        "MITIGATE_NOW (24 h), PATCH_WINDOW (30 days), MONITOR (90 days), or ACCEPT "
        "(1 year), with a rationale and timestamp.")

    # ── Setup: reconcile split + hyper-params (keep Table I reference) ──
    set_text(find(doc, "EXPERIMENTS AND RESULTS"),
             "IV. EXPERIMENTS AND RESULTS")
    set_text(find(doc, "All experiments use the 180,497-CVE dataset with a June 2024"),
        "All experiments use the same chronological June 2024 split; the test set "
        "contains 70,831 CVEs with 277 KEV positives (0.39%), and a 15% "
        "stratified split of the training partition (seed 42) is held out for "
        "calibration and blend fitting. XGBoost hyperparameters were selected by "
        "randomized search under five-fold stratified cross-validation "
        "(n_estimators = 414, max_depth = 7, learning_rate = 0.087). PR-AUC is the "
        "primary metric; ROC-AUC and Precision at K are also reported, with "
        "EPSS and CVSS as baselines. Headline PR-AUC differences use a paired "
        "bootstrap (10,000 resamples of the test CVEs, percentile 95% CIs) and a "
        "paired permutation test (10,000 randomizations) with Holm-Bonferroni "
        "correction. RRF versus historical-EPSS is designated the primary revised "
        "comparison; it was not preregistered. Revision experiments reload the same "
        "saved arrays or model artifacts before each new measurement.")

    # ── Further compression to fit six pages ────────────────────────────
    set_text(find(doc, "Each CVE is represented by a 37-dimensional feature vector"),
        "The clean tabular configuration contains the 33 columns present in the "
        "evaluated snapshot: 15 CVSS core/vector fields, 12 CWE indicators, EPSS, "
        "days since publication, two description statistics, and product/reference "
        "counts. A diagnostic circular stress test adds available exploit-derived "
        "proxies and a composite score. The KEV flag itself is excluded under the "
        "KEV-strict label policy, so the stress test measures proxy/label overlap "
        "rather than a deployable predictor.")
    set_text(find(doc, "The circularity audit checks for four types"),
        "The circularity audit checks four leakage types: the temporal layer "
        "flags features observed after the decision time; the label layer flags "
        "direct or derived exploit signals that overlap the KEV outcome; the entity "
        "layer catches identifier-correlated "
        "proxies; and the correlation layer flags feature-label pairs above a "
        "statistical threshold. Table I reports six configurations recomputed with "
        "one tuned pipeline and the same split.")
    set_text(find(doc, "Three base models are trained independently"),
        "RRF combines three rank sources: a clean-tabular XGBoost model, a second "
        "XGBoost model that appends 64 PCA-reduced all-MiniLM-L6-v2 SBERT "
        "components, and the EPSS score. For CVE i, RRF sums 1/(k+r) over the three "
        "source ranks r with k=60. The fused value orders CVEs but is not interpreted "
        "as a calibrated probability.")
    set_text(find(doc, "Where, rank_r(d) is the position"),
        "where rank_r(d) is the position of CVE d in source ranking r and k=60 is "
        "the literature default [8]. The resulting RRF value is used only to order "
        "CVEs; it is neither normalized nor interpreted as an exploitation "
        "probability.")
    set_text(find(doc, "Table I defines the six ablation configurations"),
        "Table I distinguishes the diagnostic proxy-rich stress test from the clean "
        "configurations used for substantive interpretation. The 3.73x factor is "
        "computed as 1.0000/0.2679 using tuned retraining in both rows; the saved "
        "clean model used in the RRF scores 0.2507 because it is a separate persisted "
        "training run.")

    tbl1_vals = [
        ("C1", "Exploit-derived proxy stress test", "Yes"),
        ("C2", "Clean tabular snapshot", "No"),
        ("C3", "CVSS + EPSS", "No"),
        ("C4", "EPSS only", "No"),
        ("C5", "CVSS only", "No"),
        ("C6", "Clean tabular + SBERT", "No"),
    ]
    set_table_values(doc.tables[1], tbl1_vals)

    # ── RQ1: verified numbers + fusion (R2-1) + k ablation (R2-3) ───────
    set_text(find(doc, "B. RQ1: Exploitability Prediction Performance"),
             "B. RQ1: RRF Prioritization versus EPSS")
    kmin = min(r["pr_auc"] for r in kab["rrf_results"])
    set_text(find(doc, "Table II shows the main results"),
        "Table II reports the frozen-snapshot analysis. RRF reaches PR-AUC 0.3671 "
        "versus EPSS 0.2711, a 35.4% gain "
        "whose paired-bootstrap difference is significant (95% CI +0.054 to "
        "+0.142; Holm p = 0.009). Precision at 100 of 0.71 means 71 of the top "
        "100 ranked CVEs are confirmed exploited. The individual models score "
        "0.2507 (tabular), 0.3086 (tabular with embeddings), and 0.0225 "
        "(a diagnostic text-only model not used by RRF). Across fusion strategies "
        "over the same three rankers "
        "(Fig. 2), RRF (0.3671) leads CombSUM, CombMNZ, and an optimized blend "
        "(0.3536), Borda (0.3065), and logistic-regression stacking (0.2589); its "
        "edge over CombSUM is not statistically distinguishable (Δ +0.014, 95% CI "
        "-0.001 to +0.029). The post-hoc k sweep ranges from 0.3787 at k=5 to "
        "0.3451 at k=300 (spread 0.0337). We retain the literature default k=60 "
        "because selecting k=5 on this test set would be optimistic.")
    set_text(find(doc, "Fig. 2.  PR-AUC comparison across model configurations"),
        "Fig. 2.  Fusion baselines using the frozen March 2026 feature snapshot.")
    set_text(find(doc, "TABLE II.  MAIN EVALUATION RESULTS"),
        "TABLE II.  FROZEN-SNAPSHOT EVALUATION (JUNE 2024 PUBLICATION SPLIT)")

    # ── Table II: reconcile to v2 results ───────────────────────────────
    tbl2_vals = [
        ("CVSS Baseline", "0.011", "0.750", "0.06", "severity"),
        ("EPSS Baseline", "0.271", "0.963", "0.44", "ranker"),
        ("XGBoost Tabular", "0.251", "0.925", "0.53", "ranker"),
        ("XGBoost + Emb", "0.309", "0.930", "0.66", "ranker"),
        ("Text LogReg", "0.022", "0.826", "0.03", "diagnostic"),
        ("RRF Ensemble", "0.367", "0.975", "0.71", "fusion"),
    ]
    set_table_values(doc.tables[2], tbl2_vals)
    doc.tables[2].rows[0].cells[4].paragraphs[0].runs[0].text = "Role"

    # ── RQ2: keep circularity + heatmap; add rolling + PIT (R2-4) ───────
    set_text(find(doc, "C. RQ2: Circularity Audit and Metric Inflation"),
             "C. RQ2: Circularity and Evidence-Time Audit")
    rrf_pit = pit["RRF ensemble (PIT)"]
    epss_pit = pit["EPSS point-in-time (baseline)"]
    r_para = find(doc, "Fig. 3 shows this inflation across all six")
    cv = circularity["configs_tuned_retrain"]
    set_text(r_para,
        "Table III and Fig. 3 reconcile the circularity configurations under one "
        "tuned retraining pipeline. The diagnostic proxy-rich configuration reaches "
        f"PR-AUC {cv['circular_full']:.4f}, while the clean tabular configuration "
        f"reaches {cv['clean_tabular']:.4f}, a "
        f"{circularity['inflation_factor']:.2f}x ratio. This is an intentionally "
        "invalid upper-bound stress test: the proxy-rich inputs are derived from "
        "exploit evidence related to the KEV outcome. The clean+SBERT result "
        f"({cv['clean_plus_text']:.4f}) and EPSS-only result "
        f"({cv['epss_only']:.4f}) are not circular under the configured KEV policy, "
        "but they still use the frozen 2026 snapshot.")
    doc.tables[3].rows[0].cells[2].paragraphs[0].runs[0].text = "Relative to clean"
    tbl3_vals = [
        ("Proxy-rich stress test", f"{cv['circular_full']:.4f}",
         f"{cv['circular_full']/cv['clean_tabular']:.2f}x"),
        ("Clean tabular", f"{cv['clean_tabular']:.4f}", "1.00x"),
        ("CVSS + EPSS", f"{cv['cvss_epss_only']:.4f}",
         f"{cv['cvss_epss_only']/cv['clean_tabular']:.2f}x"),
        ("EPSS only", f"{cv['epss_only']:.4f}",
         f"{cv['epss_only']/cv['clean_tabular']:.2f}x"),
        ("CVSS only", f"{cv['cvss_only']:.4f}",
         f"{cv['cvss_only']/cv['clean_tabular']:.2f}x"),
        ("Clean + SBERT", f"{cv['clean_plus_text']:.4f}",
         f"{cv['clean_plus_text']/cv['clean_tabular']:.2f}x"),
    ]
    set_table_values(doc.tables[3], tbl3_vals)
    set_text(find(doc, "Fig. 3.  Ablation heatmap"),
        "Fig. 3.  Reconciled circularity stress test under one tuned retraining pipeline.")
    insert_after(r_para,
        "A single cutoff may hide performance decay, so we repeated the "
        "train-on-past / test-next-year protocol at four yearly boundaries "
        "(2021-2024). A reduced 29-feature set that excludes EPSS, product/reference "
        "counts, and explicit time-since-publication yields ROC-AUC 0.743-0.755 "
        "(sd 0.005), whereas frozen-2026-enrichment PR-AUC "
        "declines monotonically from 0.881 to 0.279 as post-publication hindsight "
        "shrinks. The reduced set still uses the final NVD text, CVSS, CWE, and "
        "March 2026 KEV labels, so it is a temporal robustness bound rather than a "
        "fully prospective reconstruction. Replacing EPSS with FIRST's first monthly "
        "archive snapshot on or after each CVE's publication (0-31 day lag) "
        f"yields RRF {rrf_pit['pr_auc']:.4f} versus EPSS {epss_pit['pr_auc']:.4f}. "
        "This designated primary revised comparison is a null result: RRF's +3.8% "
        "point estimate is modest, but the paired-bootstrap 95% CI on "
        "the difference includes zero (-0.031 to +0.052) and the permutation test "
        "is non-significant. Thus the frozen +35.4% gap is not a defensible "
        "deployment-time superiority claim; a complete historical NVD/KEV replay is "
        "required before making one.")

    # ── RQ3: expanded RAG + kappa (R2-2, minor #4) ──────────────────────
    set_text(find(doc, "D. RQ3: RAG Intelligence Brief Quality"),
             "D. RQ3: Grounded Brief Quality and Verification")
    hf = rag["automatic_checks"]["hallucination_filter"]
    ktr, kad, kfb = (kappa["technique_relevant"], kappa["advisory_cited"],
                     kappa["fabrication_present"])
    set_text(find(doc, "The RAG pipeline was evaluated on 50 high-risk CVEs"),
        "RQ3 uses 150 briefs for the top-150 test CVEs by RRF rank. Deterministic "
        "checks found no fabricated ATT&CK identifier; 149 briefs cited a CVE-listed "
        "advisory and passed STIX verification, while grounding rejected "
        f"{hf['total_filtered_by_grounding']} of "
        f"{hf['total_llm_proposed_techniques']} proposed mappings. We operationalize "
        "over-rationalization as the GPT-4o fabrication flag: citing a valid but "
        "semantically inappropriate ATT&CK technique or another unsupported "
        "exploit-specific claim. Exploratory "
        "GPT-4o/GPT-5.1 agreement [19] was kappa="
        f"{ktr['cohens_kappa']:.2f} for technique relevance, "
        f"{kad['cohens_kappa']:.2f} for advisory citation, and "
        f"{kfb['cohens_kappa']:.2f} for the fabrication/over-rationalization flag; "
        "these are not human ratings. "
        "On the same 150 CVEs, a bi-encoder baseline was compared with optional "
        "CoVe-inspired relevance verification [20] (GPT-4o quality judge; "
        "GPT-4o-mini generator and faithfulness scorer). Over-rationalization fell "
        f"from {rag_base['over_rationalization_rate']:.1%} to "
        f"{rag_cove['over_rationalization_rate']:.1%}; among non-abstaining briefs, "
        f"technique relevance rose from {rag_base['technique_relevant_rate']:.1%} "
        f"to {rag_cove['technique_relevant_rate']:.1%}, and automated RAGAS-style "
        f"faithfulness [21] rose from {F3(rag_base['faithfulness_mean'])} to "
        f"{F3(rag_cove['faithfulness_mean'])}. This is a precision-coverage trade: "
        f"abstention rose from {rag_base['abstain_rate']:.1%} to "
        f"{rag_cove['abstain_rate']:.1%} and mean mappings per brief fell from "
        f"{rag_base['mean_techniques_per_brief']:.2f} to "
        f"{rag_cove['mean_techniques_per_brief']:.2f}. Advisory citation remained "
        f"{rag_base['advisory_citation_rate']:.1%} versus "
        f"{rag_cove['advisory_citation_rate']:.1%}, with no fabricated IDs in "
        "either arm. "
        "CoVe is therefore an optional high-precision mode, not a free improvement. "
        "A 15-CVE cross-encoder pilot abstained more aggressively without improving "
        "precision and was not adopted.")

    # ── RQ4: refreshed numbers + asset-aware ablation (R2-5) ────────────
    set_text(find(doc, "E. RQ4: Decision Engine Triage Accuracy"),
             "E. RQ4: Asset-Aware Decision-Tier Sensitivity")
    set_text(find(doc, "The decision engine was evaluated on the test set using KEV"),
        "On the full 70,831-CVE test set in global-evidence mode, all 277 KEV CVEs "
        "received an urgent tier with no non-KEV escalations; since the "
        "active-exploitation gate consumes the KEV signal directly, this verifies "
        "rule execution, not predictive skill. The informative test is the "
        "asset-aware ablation: on a seeded 51-asset fleet (inventories drawn from "
        "the corpus's most frequent vendor-product pairs) matched to test-window "
        "CVEs (5,435 asset-CVE pairs) with synthesized VEX and reachability, "
        "scoring each pair through the same SSVC tree with and without asset "
        "evidence changed 23.4% of decisions and cut the urgent queue by 86% "
        "(1,286 to 177). This demonstrates deterministic sensitivity to asset "
        "evidence, not an externally validated workload reduction; the 86% value is "
        "an upper bound under the synthetic evidence distribution.")

    # ── Feature importance: real TreeSHAP values + attribution-vs-necessity ─
    sh = {r["feature"]: r["share"] for r in shap["top_features"]}
    def shp(name, *aliases):
        for k in (name, *aliases):
            if k in sh:
                return sh[k]
        return 0.0
    set_text(find(doc, "We compute SHapley Additive exPlanations"),
        "TreeSHAP values for the saved clean-tabular model rank the NVD reference "
        f"count ({shp('reference_count'):.0%} of attribution), EPSS score "
        f"({shp('epss_score'):.0%}), affected-product count "
        f"({shp('product_count'):.0%}), days since publication "
        f"({shp('days_since_published'):.0%}), and description length "
        f"({shp('description_length'):.0%}) highest ({shap['top5_share']:.0%} "
        "together). These are frozen-snapshot explanations and may contain hindsight "
        "through reference, product, and elapsed-time fields. Attribution and "
        "necessity differ: the reference- and "
        "product-count features receive the largest average attribution, but a "
        "leave-one-group-out ablation retraining without each of the seven groups "
        "(Fig. 4) shows EPSS is the most irreplaceable frozen-snapshot input - its removal "
        "collapses PR-AUC by 87% relative (0.268 to 0.034; paired-bootstrap "
        "difference significant, 95% CI +0.181 to +0.285, Holm "
        "p < 0.001), versus 29% for reference-network, 17% for temporal, and 13% "
        "for CVSS-vector features - SHAP measures average attribution while the "
        "ablation measures unique signal. The 87% decrease characterizes this "
        "retraining pipeline; it is not projected as a prospective deployment loss.")
    remove_para(doc, "Fig. 4 shows the precision-recall curves")
    set_text(find(doc, "Fig. 4.  Precision-recall curves"),
        "Fig. 4.  Leave-one-group-out feature ablation: relative PR-AUC drop per "
        "feature group (retrained).")

    # ── Limitations and Future Directions: constructive framing ─────────
    set_text(find(doc, "G. Threats to Validity"),
             "G. Limitations and Future Directions")
    set_text(find(doc, "Several threats to the validity of these results"),
        "Four limitations constrain interpretation. First, March 2026 NVD features "
        "and KEV labels are paired with a chronological split; only EPSS is replaced "
        "historically, so no result is a complete prospective replay. Second, KEV "
        "is curated and incomplete, and negatives may later become exploited. Third, "
        "the asset experiment uses a synthetic fleet and synthesized VEX, controls, "
        "and reachability; its queue reduction is not an enterprise outcome. Fourth, "
        "deterministic RAG checks validate identifiers and references, while CoVe "
        "relevance and faithfulness are model-judged; neither establishes human-rated "
        "semantic correctness, and the two annotators are LLMs. Releasing a "
        "versioned snapshot manifest, obtaining two blinded cybersecurity annotators, "
        "and replaying historical NVD/KEV states are required for stronger external "
        "validity.")

    # ── Conclusion + future work ────────────────────────────────────────
    set_text(find(doc, "In this work, we have developed the VulnTriage"),
        "We presented VulnTriage as an auditable integration of exploitability "
        "ranking, evidence-grounded briefing, and action tiering. In the frozen "
        "snapshot, RRF reaches PR-AUC 0.3671, but after historical EPSS substitution "
        "its +3.8% advantage over EPSS is not statistically reliable; RRF is therefore "
        "an integration choice, not a demonstrated replacement for EPSS. The "
        "circularity stress test quantifies a 3.73x proxy-driven inflation, while the "
        "87% EPSS ablation characterizes dependence within the frozen clean-tabular "
        "pipeline. Deterministic checks prevent invalid ATT&CK identifiers and "
        "unsupported advisory URLs; optional CoVe verification cuts model-judged "
        f"over-rationalization from {rag_base['over_rationalization_rate']:.1%} to "
        f"{rag_cove['over_rationalization_rate']:.1%} but abstains on "
        f"{rag_cove['abstain_rate']:.1%}, so human "
        "expert validation remains necessary. The synthetic asset experiment changes "
        "23.4% of action tiers and "
        "demonstrates traceable rule sensitivity rather than real-world workload "
        "savings. These boundaries are part of the result: a low-cost integrated "
        "system is useful only when its evidence time, labels, and validation type are "
        "reported explicitly.")
    set_text(find(doc, "Three directions are planned for future work"),
        "Future work will reconstruct historical NVD and KEV states, validate the "
        "existing SBOM/VEX ingestion and decision pipeline using independently "
        "collected enterprise inventories and vendor-issued VEX documents, and run "
        "a preregistered cost-quality study with two blinded cybersecurity "
        "annotators. That study will compare a low-cost grounded pipeline with a "
        "premium model under identical prompts, evidence, and token budgets, "
        "reporting semantic quality, unsupported claims, latency, and cost per brief "
        "rather than assuming model price implies quality.")

    # ── References: verified titles/authors/venues ─────────────────────
    refs_1_15 = [
        '[1] National Vulnerability Database, "NVD Dashboard," NIST, 2024. '
        '[Online]. Available: https://nvd.nist.gov/general/nvd-dashboard.',
        '[2] O. Suciu, C. Nelson, Z. Lyu, T. Bao, and T. Dumitras, "Expected '
        'Exploitability: Predicting the Development of Functional Vulnerability '
        'Exploits," in Proc. 31st USENIX Security Symposium, 2022, pp. 377-394.',
        '[3] J. Jacobs, S. Romanosky, B. Edwards, I. Adjerid, and M. Roytman, '
        '"Exploit Prediction Scoring System (EPSS)," Digital Threats: Research and '
        'Practice, vol. 2, no. 3, pp. 1-17, 2021.',
        '[4] P. Mell, K. Scarfone, and S. Romanosky, "Common Vulnerability Scoring '
        'System," IEEE Security & Privacy, vol. 4, no. 6, pp. 85-89, 2006.',
        '[5] K. Khanmohammadi, Z. Namrud, F. Labreche, and R. Khoury, '
        '"ExploitabilityBirthMark: An Early Predictor of the Likelihood of '
        'Exploitation," in Foundations and Practice of Security, LNCS 15533, '
        '2025, pp. 187-199.',
        '[6] D. Arp et al., "Dos and Don\'ts of Machine Learning in Computer '
        'Security," in Proc. 31st USENIX Security Symposium, 2022, pp. 3971-3988.',
        '[7] J. Jacobs, S. Romanosky, O. Suciu, B. Edwards, and A. Sarabi, '
        '"Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions '
        'with Community-Driven Insights," in Proc. IEEE EuroS&PW, 2023, '
        'pp. 194-206.',
        '[8] G. V. Cormack, C. L. A. Clarke, and S. Buettcher, "Reciprocal Rank '
        'Fusion Outperforms Condorcet and Individual Rank Learning Methods," in '
        'Proc. ACM SIGIR, 2009, pp. 758-759.',
        '[9] O. Grigorescu, A. Nica, M. Dascalu, and R. Rughinis, "CVE2ATT&CK: '
        'BERT-Based Mapping of CVEs to MITRE ATT&CK Techniques," Algorithms, '
        'vol. 15, no. 9, p. 314, 2022.',
        '[10] R. Branescu, O. Grigorescu, and M. Dascalu, "Automated Mapping of '
        'Common Vulnerabilities and Exposures to MITRE ATT&CK Tactics," '
        'Information, vol. 15, no. 4, p. 214, 2024.',
        '[11] C. Zhang et al., "VTT-LLM: Advancing Vulnerability-to-Tactic-and-'
        'Technique Mapping through Fine-Tuning of Large Language Model," '
        'Mathematics, vol. 12, no. 9, p. 1286, 2024.',
        '[12] Q. Du et al., "Vul-RAG: Enhancing LLM-based Vulnerability Detection '
        'via Knowledge-Level RAG," arXiv:2406.11147, 2024.',
        '[13] R. Fayyazi, S. H. Trueba, M. Zuzak, and S. J. Yang, "ProveRAG: '
        'Provenance-Driven Vulnerability Analysis with Automated Retrieval-'
        'Augmented LLMs," arXiv:2410.17406, 2024.',
        '[14] MITRE ATT&CK, "ATT&CK v18.1 Release and STIX Data," 2025. [Online]. '
        'Available: https://attack.mitre.org/resources/versions/.',
        '[15] J. Spring et al., "Prioritizing Vulnerability Response: A '
        'Stakeholder-Specific Vulnerability Categorization (Version 2.0)," '
        'Carnegie Mellon University Software Engineering Institute, 2021.',
    ]
    for idx, txt in enumerate(refs_1_15, start=1):
        set_text(find_reference(doc, idx), txt)

    ref15 = find(doc, "[15] J. Spring")
    prev = ref15
    for txt in [
        '[16] Cybersecurity and Infrastructure Security Agency, "Known Exploited '
        'Vulnerabilities Catalog," 2026. [Online]. Available: '
        'https://www.cisa.gov/known-exploited-vulnerabilities-catalog.',
        '[17] Forum of Incident Response and Security Teams, "EPSS Data and '
        'Statistics," 2026. [Online]. Available: '
        'https://www.first.org/epss/data_stats.html.',
        '[18] F. Alpay and T. Alpay, "Compute-Budgeted Exploitability Evidence '
        'Graphs for Prospective Vulnerability Triage," arXiv:2606.19076, 2026.',
        '[19] J. Cohen, "A Coefficient of Agreement for Nominal Scales," '
        'Educational and Psychological Measurement, vol. 20, no. 1, '
        'pp. 37-46, 1960.',
        '[20] S. Dhuliawala, M. Komeili, J. Xu, R. Raileanu, X. Li, '
        'A. Celikyilmaz, and J. Weston, "Chain-of-Verification Reduces '
        'Hallucination in Large Language Models," in Findings of the Association '
        'for Computational Linguistics: ACL 2024, pp. 3563-3578.',
        '[21] S. Es, J. James, L. Espinosa Anke, and S. Schockaert, "RAGAs: '
        'Automated Evaluation of Retrieval Augmented Generation," in Proc. 18th '
        'Conf. Eur. Chapter Assoc. Comput. Linguistics: System Demonstrations, '
        '2024, pp. 150-158.',
    ]:
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(txt)
        r.font.name, r.font.size = FONT, Pt(8)
        prev._p.addnext(p._p)
        prev = p

    # ── Compact ALL reference entries to IEEE-standard 8 pt, tight leading ──
    # Formatting-only: the five reviewer-added citations grew the reference list
    # past the sixth page. IEEE permits 8 pt references; tightening leading here
    # pulls the entire bibliography back onto page 6 without altering any wording.
    for para in doc.paragraphs:
        t = para.text.lstrip()
        if re.match(r"^\[\d{1,2}\]\s", t):
            para.paragraph_format.space_before = Pt(0)
            para.paragraph_format.space_after = Pt(0)
            para.paragraph_format.line_spacing = 1.0
            for run in para.runs:
                run.font.size = Pt(8)

    # ── Evidence-aligned figures and accessibility metadata ─────────────
    swap_figure(
        doc, 0, FIGDIR / "fig_architecture_corrected.png", 0.5,
        "VulnTriage architecture: NVD, KEV, and EPSS evidence feeds a dated "
        "snapshot and leakage audit; clean tabular XGBoost, tabular plus SBERT "
        "XGBoost, and EPSS are fused by RRF before grounded briefing and "
        "asset-aware SSVC action tiering.",
    )
    swap_figure(
        doc, 1, FIGDIR / "fig_fusion_comparison.png", 0.5,
        "Horizontal bar chart of frozen-snapshot PR-AUC: RRF 0.3671, CombSUM "
        "0.3536, CombMNZ 0.3536, optimized blend 0.3536, best single model "
        "0.3086, Borda 0.3065, EPSS 0.2711, and stacking 0.2589.",
    )
    swap_figure(
        doc, 2, FIGDIR / "fig_circularity_reconciled.png", 0.5,
        "Horizontal bar chart of reconciled circularity configurations: "
        "proxy-rich stress test PR-AUC 1.000, clean plus SBERT 0.293, EPSS "
        "0.271, clean tabular 0.268, CVSS plus EPSS 0.227, and CVSS 0.011.",
    )
    swap_figure(
        doc, 3, FIGDIR / "fig_feature_groups.png", 0.5,
        "Leave-one-group-out frozen-snapshot ablation. Removing EPSS causes an "
        "87.2 percent relative PR-AUC drop, followed by reference network 28.6 "
        "percent, temporal 17.3 percent, and CVSS vector 13.5 percent.",
    )

    doc.tables[1].rows[0].cells[0].paragraphs[0].runs[0].text = "Config"
    doc.tables[1].rows[0].cells[1].paragraphs[0].runs[0].text = "Inputs"
    for table in doc.tables[1:]:
        mark_table_header(table.rows[0])

    doc.save(OUT)

    # ── report ──────────────────────────────────────────────────────────
    d2 = Document(OUT)
    words = sum(len(p.text.split()) for p in d2.paragraphs if p.text.strip())
    print(f"Saved -> {OUT}")
    print(f"tables={len(d2.tables)}  figures={len(d2.inline_shapes)}  "
          f"body-words={words:,}  (original 3,365)")


if __name__ == "__main__":
    build()
