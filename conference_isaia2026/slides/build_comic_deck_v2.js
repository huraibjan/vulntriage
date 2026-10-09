// Builds version 2 of the comic-strip deck for IEEE ISAIA 2026 (VulnTriage, paper 166).
//
//   NODE_PATH=<dir with node_modules> PPTX_SKILL_DIR=<pptx skill dir> node build_comic_deck_v2.js
//
// Version 1 (build_comic_deck.js) is kept unchanged. Version 2 applies an
// independent review: citations and a reference list, a prior-work and
// contributions slide, definitions on first use, qualifiers the paper attaches
// to each result, American English, readable data panels and no placeholder
// content. Every number is from the accepted paper (paper_166.pdf) or from a
// result file under results/; post-paper checks are labelled as such.

const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const sharp = require("sharp");

const { applyTheme } = require(path.join(process.env.PPTX_SKILL_DIR, "scripts", "apply_theme.js"));

const HERE = __dirname;
const OUT = path.join(HERE, "VulnTriage_ISAIA2026_comic_v2.pptx");
const GEN = path.join(HERE, "..", "art", "generated");
const JPG = path.join(GEN, "jpg_v2");
const ASSETS = path.join(HERE, "..", "assets");
const img = (id) => path.join(JPG, id + ".jpg");

// Frame id -> source PNG (v2 swaps in the regenerated frames).
const FRAMES = {
  "02a_arrive": "02a_arrive", "02b_all_red": "02b_all_red", "02c_few_real": "02c_few_real",
  "03a_score": "03a_score", "03b_board": "03b_board", "04_pipeline": "04_pipeline", "05_testset": "05_testset",
  "06a_win": "06a_win", "07a_date": "07a_date", "08a_audit": "08a_audit_v3_generated",
  "09a_brief": "09a_brief", "10a_ask_twice": "10a_ask_twice", "11a_servers": "11a_servers", "12a_sbom": "12a_sbom",
  "13a_next": "13a_limits_v2", "14a_sunrise": "14a_sunrise",
};

const THEME = {
  name: "VulnTriage Comic",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "1B2233", lt1: "F6F7F9", dk2: "4A5266", lt2: "FFFFFF",
    accent1: "12A594", accent2: "E5484D", accent3: "F5A524", accent4: "3E63DD",
    accent5: "D5D9E0", accent6: "9A9FAB", hlink: "0B7A6E", folHlink: "4A5266",
  },
};
const HEX = THEME.colors;
// Text on light grounds uses darker tints of the accents so it meets contrast requirements.
const TEAL_T = "0B7A6E", AMBER_T = "B45309", RED_T = "C4262E", BLUE_T = "2F4FC2";

const W = 13.333, H = 7.5, M = 0.7;
const TOP = 1.6, GAP = 0.34;

(async () => {
  fs.mkdirSync(JPG, { recursive: true });
  for (const [id, src] of Object.entries(FRAMES)) {
    await sharp(path.join(GEN, src + ".png")).jpeg({ quality: 90 }).toFile(img(id));
  }
  // Cover: 16:9 crop with the title scrim baked in as a gradient (no hard edge).
  const scrim = Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="1536" height="864"><defs><linearGradient id="g" x1="0" x2="1" y1="0" y2="0">` +
    `<stop offset="0" stop-color="#1B2233" stop-opacity="0.92"/><stop offset="0.42" stop-color="#1B2233" stop-opacity="0.86"/>` +
    `<stop offset="0.64" stop-color="#1B2233" stop-opacity="0"/></linearGradient></defs><rect width="1536" height="864" fill="url(#g)"/></svg>`);
  const cover = img("01_cover_169");
  await sharp(path.join(GEN, "01_cover.png")).extract({ left: 0, top: 80, width: 1536, height: 864 })
    .composite([{ input: scrim }]).jpeg({ quality: 92 }).toFile(cover);
  // Closing frame: keep the figures, drop the empty wall.
  await sharp(path.join(GEN, "15a_thanks.png")).extract({ left: 0, top: 0, width: 922, height: 1024 })
    .jpeg({ quality: 90 }).toFile(img("15a_thanks_crop"));

  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";
  pres.title = "VulnTriage: CVE Exploitability Prediction with Reciprocal Rank Fusion and Circularity-Aware Evaluation";
  pres.author = "Huraib Jan Sarhandi, Weitian Wang";
  pres.company = "Montclair State University";
  pres.subject = "IEEE ISAIA 2026, paper 166";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };

  const C = pres.SchemeColor;
  const INK = C.text1, PAPER = C.background1, INK2 = C.text2, WHITE = C.background2, HAIR = C.accent5;

  pres.defineSlideMaster({
    title: "COVER",
    background: { color: HEX.dk1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: M, y: 2.2, w: 6.2, h: 1.3,
        fontSize: 66, bold: true, color: PAPER, align: "left", valign: "bottom", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "subtitle", type: "body", x: M, y: 3.7, w: 5.9, h: 1.5,
        fontSize: 20, color: PAPER, align: "left", valign: "top", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "authors", type: "body", x: M, y: 5.55, w: 5.9, h: 1.1,
        fontSize: 15, color: HAIR, align: "left", valign: "top", margin: 0 }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "STRIP",
    background: { color: HEX.lt1 },
    margin: [0.5, M, 0.6, M],
    objects: [
      { placeholder: { options: { name: "kicker", type: "body", x: M, y: 0.42, w: 10, h: 0.3,
        fontSize: 13, bold: true, color: TEAL_T, charSpacing: 3, align: "left", valign: "middle", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "title", type: "title", x: M, y: 0.72, w: W - 2 * M, h: 0.7,
        fontSize: 30, bold: true, color: INK, align: "left", valign: "middle", margin: 0 }, text: "" } },
      { text: { text: "VulnTriage  ·  IEEE ISAIA 2026  ·  Paper 166", options: {
        x: M, y: 7.08, w: 7, h: 0.26, fontSize: 10, color: INK2, margin: 0 } } },
    ],
    slideNumber: { x: W - M - 0.6, y: 7.08, w: 0.6, h: 0.26, fontSize: 10, color: INK2, align: "right" },
  });

  // ── Helpers ───────────────────────────────────────────────────────────
  let n = 0;
  const name = (s) => `${s} ${++n}`;
  const T = (slide, text, o) => slide.addText(text, { isTextBox: true, margin: 0, valign: "top",
    color: INK, fontSize: 15, objectName: name("Text"), ...o });
  const strip = (section, kicker, title) => {
    const s = pres.addSlide({ masterName: "STRIP", sectionTitle: section });
    s.addText(kicker, { placeholder: "kicker" });
    s.addText(title, { placeholder: "title" });
    return s;
  };
  const picFrame = (slide, id, x, y, w, h, alt) => {
    slide.addImage({ path: img(id), x, y, w, h, altText: alt, objectName: name("Frame art") });
    slide.addShape(pres.shapes.RECTANGLE, { x, y, w, h, fill: { color: WHITE, transparency: 100 },
      line: { color: INK, width: 2 }, objectName: name("Frame border") });
  };
  const blankFrame = (slide, x, y, w, h) => slide.addShape(pres.shapes.RECTANGLE, {
    x, y, w, h, fill: { color: WHITE }, line: { color: INK, width: 2 }, objectName: name("Frame") });
  const caption = (slide, x, y, w, lead, body, h = 1.2) => T(slide, [
    ...(lead ? [{ text: lead + " ", options: { bold: true, color: INK } }] : []),
    { text: body, options: { color: INK2 } },
  ], { x, y, w, h, fontSize: 15 });
  const axis = {
    catAxisLabelColor: INK2, valAxisLabelColor: INK2, catAxisLabelFontSize: 12, valAxisLabelFontSize: 11,
    catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt", dataLabelFontFace: "+mn-lt",
    legendFontFace: "+mn-lt", titleFontFace: "+mn-lt",
    valGridLine: { color: HEX.accent5, size: 0.75 }, catGridLine: { style: "none" },
    catAxisLineShow: false, valAxisLineShow: false,
    showValue: true, dataLabelColor: INK, dataLabelFontSize: 12, dataLabelPosition: "outEnd",
    legendColor: INK2, legendFontSize: 12, titleColor: INK2, titleFontSize: 13, showTitle: true,
  };

  const two = { w: (W - 2 * M - GAP) / 2 };
  two.h = two.w * (1024 / 1536);
  const three = { w: (W - 2 * M - 2 * GAP) / 3 };
  three.h = three.w;
  const capY2 = TOP + two.h + 0.16, capY3 = TOP + three.h + 0.16;
  const X2 = M + two.w + GAP;

  // ════════════════ 1. Cover ════════════════
  pres.addSection({ title: "Opening" });
  {
    const s = pres.addSlide({ masterName: "COVER", sectionTitle: "Opening" });
    s.addImage({ path: cover, x: 0, y: 0, w: W, h: H, objectName: name("Cover art"),
      altText: "Maya, a vulnerability analyst, working at her desk at night with an assistant robot" });
    T(s, "IEEE ISAIA 2026  ·  PAPER 166", { x: M, y: 0.7, w: 6, h: 0.35, fontSize: 13, bold: true, color: C.accent1, charSpacing: 3 });
    s.addText("VulnTriage", { placeholder: "title" });
    s.addText("AI-driven CVE exploitability prediction with Reciprocal Rank Fusion and circularity-aware evaluation", { placeholder: "subtitle" });
    s.addText([
      { text: "Huraib Jan Sarhandi  ·  Weitian Wang", options: { color: PAPER, breakLine: true } },
      { text: "School of Computing, Montclair State University, USA" },
    ], { placeholder: "authors" });
    s.addNotes(
      "Good morning. I am Huraib Jan Sarhandi from Montclair State University, presenting joint work with Professor Weitian Wang. This is paper 166. " +
      "I will tell it as a story. This is Maya. She is a vulnerability analyst, and she stands for the person our system is built for. " +
      "The talk has two threads: a system that ranks vulnerabilities, explains them, and recommends an action; and an audit of our own evaluation that tells us exactly which gains can be trusted.");
  }

  // ════════════════ 2. The problem ════════════════
  {
    const s = strip("Opening", "SCENE 1  ·  THE PROBLEM", "Monday morning: 40,000 new CVEs a year, about 110 a day");
    const ids = ["02a_arrive", "02b_all_red", "02c_few_real"];
    const alts = ["Maya arrives at the office; a wall display reads 40,000+",
      "Maya at her desk; every row on her screen is tagged critical",
      "A desk covered in gray cards with only three red ones"];
    const caps = [
      ["40,000+", "CVEs (Common Vulnerabilities and Exposures) were published by NVD in 2024, up 38% from 2023 [1]."],
      ["Severity is not likelihood.", "Ranked by CVSS severity [4], only 6 of the top 100 test CVEs are on CISA's known-exploited list."],
      ["Fewer than 3%", "of published CVEs are exploited in the wild within a year [2], [3]. The question is which ones."],
    ];
    ids.forEach((id, i) => {
      const x = M + i * (three.w + GAP);
      picFrame(s, id, x, TOP, three.w, three.h, alts[i]);
      caption(s, x, capY3, three.w, caps[i][0], caps[i][1], 1.15);
    });
    s.addNotes(
      "The National Vulnerability Database published over forty thousand CVEs in 2024, about one hundred and ten a day. Maya's team can patch a fraction of them. " +
      "The usual way to prioritize is CVSS, which measures how severe a vulnerability could be, not how likely it is to be used. In our test set, ranking by CVSS puts only six known-exploited vulnerabilities in the top one hundred. " +
      "Yet fewer than three percent of CVEs are exploited within a year. Her real question is: which three percent.");
  }

  // ════════════════ 3. The gap and the questions ════════════════
  {
    const s = strip("Opening", "SCENE 2  ·  THE GAP", "A score is not yet a decision");
    picFrame(s, "03a_score", M, TOP, two.w, two.h, "Maya looks skeptically at a screen showing an EPSS score of 0.94 with question-mark notes");
    caption(s, M, capY2, two.w, "EPSS (Exploit Prediction Scoring System) predicts exploitation better than CVSS [3].",
      "But is this system affected? What would an attacker do with it? What should she do, and by when?");
    picFrame(s, "03b_board", X2, TOP, two.w, two.h, "Maya pins four notes labeled RQ1 to RQ4 on a board");
    T(s, [
      { text: "RQ1 ", options: { bold: true, color: TEAL_T } }, { text: "How does rank fusion compare with EPSS in a frozen snapshot?", options: { color: INK2, breakLine: true } },
      { text: "RQ2 ", options: { bold: true, color: RED_T } }, { text: "Do circular or post-decision features inflate the metrics?", options: { color: INK2, breakLine: true } },
      { text: "RQ3 ", options: { bold: true, color: AMBER_T } }, { text: "Can ATT&CK briefs be grounded while keeping coverage?", options: { color: INK2, breakLine: true } },
      { text: "RQ4 ", options: { bold: true, color: BLUE_T } }, { text: "How does synthetic asset context change the action tier?", options: { color: INK2 } },
    ], { x: X2, y: capY2, w: two.w, h: 1.2, fontSize: 15 });
    s.addNotes(
      "EPSS improved on CVSS by predicting likelihood, and it is our strongest baseline. The 0.94 on her screen is the real March 2026 EPSS score of CVE-2021-41773, the Apache HTTP Server flaw you will see again later. " +
      "But a probability does not tell Maya whether her system is affected, what the attacker would do, or what to do by when. " +
      "So the study asks four questions. RQ1: how does a rank fusion of three sources compare with EPSS in a frozen snapshot. RQ2: do features that encode the label, or that are observed after the decision time, inflate the metrics. " +
      "RQ3: can we generate ATT&CK-mapped briefs whose identifiers and references are verifiable, while keeping coverage. RQ4: how does asset context, a software inventory and VEX statements, synthetic in this study, change the recommended action.");
  }

  // ════════════════ 4. Prior work and contributions ════════════════
  {
    const s = strip("Opening", "POSITIONING", "Prior work and what this study adds");
    blankFrame(s, M, TOP, two.w, two.h + 1.0);
    T(s, "PRIOR WORK", { x: M + 0.35, y: TOP + 0.22, w: two.w - 0.7, h: 0.3, fontSize: 12, bold: true, color: INK2, charSpacing: 2 });
    const prior = [
      ["Exploit prediction", "EPSS [3], [7]; Expected Exploitability [2]; prediction from publication-time data only [5]."],
      ["Evaluation pitfalls in security ML", "Temporal and label leakage [6]; large inflation under retrospective evidence in concurrent work [18]."],
      ["CVE-to-ATT&CK mapping", "CVE2ATT&CK [9]; tactic mapping [10]; VTT-LLM [11]; provenance-driven RAG [13]."],
      ["Building blocks reused, not claimed as new", "Reciprocal Rank Fusion [8], ATT&CK STIX [14], SSVC [15]."],
    ];
    const ph = (two.h + 1.0 - 0.75) / prior.length;
    prior.forEach(([head, body], i) => {
      const y = TOP + 0.65 + i * ph;
      T(s, [{ text: head, options: { bold: true, color: INK, breakLine: true } }, { text: body, options: { color: INK2 } }],
        { x: M + 0.35, y, w: two.w - 0.7, h: ph - 0.08, fontSize: 14 });
    });
    blankFrame(s, X2, TOP, two.w, two.h + 1.0);
    T(s, "CONTRIBUTIONS", { x: X2 + 0.35, y: TOP + 0.22, w: two.w - 0.7, h: 0.3, fontSize: 12, bold: true, color: TEAL_T, charSpacing: 2 });
    const contrib = [
      "A four-layer leakage audit: temporal, label, entity-proxy, and correlation.",
      "Frozen-snapshot results reported beside a historical-EPSS sensitivity analysis that bounds the remaining point-in-time uncertainty.",
      "One Docker workflow integrating RRF, SBERT-based ATT&CK retrieval, deterministic STIX and reference validation, and an SSVC-inspired decision engine.",
      "Evidence that the apparent predictive gain is not statistically reliable after historical-EPSS substitution, while evidence grounding and asset-aware decisions remain independently testable.",
    ];
    contrib.forEach((t, i) => {
      const y = TOP + 0.65 + i * ph;
      T(s, String(i + 1), { x: X2 + 0.3, y, w: 0.45, h: ph - 0.08, fontSize: 22, bold: true, color: TEAL_T, valign: "top" });
      T(s, t, { x: X2 + 0.85, y: y + 0.02, w: two.w - 1.2, h: ph - 0.1, fontSize: 14 });
    });
    s.addNotes(
      "Where this sits. Exploit prediction is an established line of work: EPSS, Expected Exploitability, and prediction restricted to publication-time information. " +
      "Arp and colleagues documented temporal and label leakage as recurring pitfalls in security machine learning, and concurrent work also reports large inflation under retrospective evidence. " +
      "CVE-to-ATT&CK mapping has strong baselines too. None of our building blocks is new: Reciprocal Rank Fusion, the ATT&CK corpus, and SSVC are reused as published. " +
      "Our four contributions are on the right: a four-layer leakage audit; frozen results reported beside a historical-EPSS sensitivity analysis; one integrated, containerized workflow; and a clear account of which gains survive leakage controls and which properties remain independently testable.");
  }

  // ════════════════ 5. Pipeline ════════════════
  pres.addSection({ title: "Method" });
  {
    const s = strip("Method", "SCENE 3  ·  THE SYSTEM", "One pipeline, from public feeds to a recommended action");
    picFrame(s, "04_pipeline", M, TOP, two.w, two.h, "Maya at a whiteboard showing five stages: sources, evidence, rank, explain, decide");
    caption(s, M, capY2, two.w, "Five stages, one Docker deployment.",
      "About 517 MB of memory and a 15 to 22 ms warm API response in the measured run. The fused value orders CVEs; it is not a calibrated probability.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const rows = [
      ["Sources", "NVD, EPSS [3], CISA KEV (Known Exploited Vulnerabilities) [16], ExploitDB"],
      ["Evidence", "33 features and a four-layer leakage audit"],
      ["Rank", "XGBoost on tabular features; XGBoost with 64 SBERT text components; EPSS. Fused by Reciprocal Rank Fusion (RRF) [8]"],
      ["Explain", "ATT&CK v18.1 retrieval [14], GPT-4o-mini brief, identifier and reference checks"],
      ["Decide", "SBOM inventory and VEX statements; SSVC-inspired tree [15]; five action tiers with deadlines"],
    ];
    const rh = (two.h - 0.4) / rows.length;
    rows.forEach(([head, body], i) => {
      const y = TOP + 0.2 + i * rh;
      T(s, String(i + 1), { x: X2 + 0.3, y, w: 0.4, h: rh - 0.06, fontSize: 22, bold: true, color: TEAL_T, valign: "middle" });
      T(s, head, { x: X2 + 0.75, y, w: 1.2, h: rh - 0.06, fontSize: 16, bold: true, valign: "middle" });
      T(s, body, { x: X2 + 1.95, y, w: two.w - 2.25, h: rh - 0.06, fontSize: 14, color: INK2, valign: "middle" });
    });
    caption(s, X2, capY2, two.w, "RRF(d) = Σ 1 / (k + rank(d)) over the three sources, k = 60 [8].",
      "EPSS is both a rank source and the baseline; the study does not claim to replace it.");
    s.addNotes(
      "Maya's pipeline has five stages. Data comes from four public sources, including CISA's Known Exploited Vulnerabilities catalog, which I will call KEV. We build thirty-three features and run a four-layer leakage audit over them. " +
      "Three rank sources are fused with Reciprocal Rank Fusion: an XGBoost model on tabular features, a second XGBoost model that adds sentence embeddings of the description, and the EPSS score itself. " +
      "RRF adds one over sixty plus rank across the three lists, so it needs no score calibration. Sixty is the published default from Cormack and colleagues. " +
      "EPSS is one of our rank sources as well as our baseline; we do not claim to replace it. " +
      "The explain stage retrieves MITRE ATT&CK techniques, has GPT-4o-mini write a brief, and validates every identifier and reference. The decide stage combines that with a software inventory, the SBOM, and exploitability statements, VEX, and assigns one of five action tiers with a deadline, following an SSVC-inspired tree. " +
      "The fused value is a rank. We do not present it as a probability.");
  }

  // ════════════════ 6. Test design ════════════════
  {
    const s = strip("Method", "SCENE 4  ·  THE TEST", "Needles in a haystack, scored under two evidence settings");
    picFrame(s, "05_testset", M, TOP, two.w, two.h, "Maya examines a heap of gray cards with a few red ones; a calendar reads June 2024");
    caption(s, M, capY2, two.w, "Train before June 2024, test after.",
      "Only 277 of 70,831 test CVEs (0.39%) are on CISA's KEV list as of March 2026, so the primary metric is PR-AUC, the area under the precision-recall curve.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const sx = X2 + 0.3, sw = (two.w - 0.6 - 0.4) / 3;
    const stat = (i, big, label) => {
      T(s, big, { x: sx + i * (sw + 0.2), y: TOP + 0.18, w: sw, h: 0.5, fontSize: 26, bold: true, color: INK, valign: "middle" });
      T(s, label, { x: sx + i * (sw + 0.2), y: TOP + 0.7, w: sw, h: 0.5, fontSize: 13, color: INK2 });
    };
    stat(0, "180,497", "NVD CVEs published 2020 to 2025");
    stat(1, "109,666", "training CVEs, before June 1, 2024");
    stat(2, "70,831", "test CVEs, 277 positives");
    T(s, [
      { text: "Frozen snapshot  ", options: { bold: true, color: BLUE_T } },
      { text: "Every feature as observed on March 3, 2026.", options: { color: INK2 } },
    ], { x: sx, y: TOP + 1.4, w: two.w - 0.6, h: 0.36, fontSize: 14 });
    T(s, [
      { text: "Historical EPSS  ", options: { bold: true, color: TEAL_T } },
      { text: "EPSS replaced by the first monthly archived score on or after publication (0 to 31 days later) [17].", options: { color: INK2 } },
    ], { x: sx, y: TOP + 1.82, w: two.w - 0.6, h: 0.62, fontSize: 14 });
    T(s, [
      { text: "Label  ", options: { bold: true } }, { text: "Listed in CISA KEV [16] as of March 3, 2026.", options: { color: INK2, breakLine: true } },
      { text: "Baselines  ", options: { bold: true } }, { text: "CVSS and EPSS.  ", options: { color: INK2 } },
      { text: "Metrics  ", options: { bold: true } }, { text: "PR-AUC (primary), ROC-AUC, Precision@100.", options: { color: INK2 } },
    ], { x: sx, y: TOP + 2.62, w: two.w - 0.6, h: 1.0, fontSize: 14 });
    caption(s, X2, capY2, two.w, "The same test set, scored twice.",
      "Paired bootstrap (10,000 resamples) and paired permutation tests, Holm-Bonferroni corrected. The historical-EPSS comparison was designated primary in revision; it was not preregistered.");
    s.addNotes(
      "The dataset is about one hundred and eighty thousand CVEs. We split chronologically at June 2024, giving about one hundred and ten thousand training CVEs and seventy-one thousand test CVEs. " +
      "Earlier I said fewer than three percent are exploited within a year. Our label is narrower: listing in CISA's KEV catalog as of March 2026, so the positive rate in the test set is 0.39 percent. At that rate accuracy and even ROC-AUC can obscure errors, so PR-AUC is the primary metric. " +
      "The key design decision: we score the same test set twice. In the frozen snapshot, every feature is as it looked in March 2026, which is what you get when you evaluate on a current data pull. " +
      "In the second setting we replace EPSS with the first monthly archived score on or after each CVE's publication, at most thirty-one days later, from FIRST's archive. " +
      "It is a sensitivity analysis: the other NVD fields and the KEV labels are still the March 2026 values, and the comparison was designated primary during revision, not preregistered.");
  }

  // ════════════════ 7. RQ1 frozen ════════════════
  pres.addSection({ title: "Results" });
  {
    const s = strip("Results", "SCENE 5  ·  RQ1, FROZEN SNAPSHOT", "First result: fusion leads on the frozen snapshot");
    picFrame(s, "06a_win", M, TOP, two.w, two.h, "Maya celebrates at her desk; her chart shows one bar ahead of the rest");
    caption(s, M, capY2, two.w, "Fusion beats CVSS, EPSS, and both of its learned inputs.",
      "Precision@100: 71 of its top 100 are KEV-listed, against 44 for EPSS.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["CVSS", "XGBoost tabular", "EPSS", "XGBoost + embeddings", "RRF (k = 60)"],
      values: [0.011, 0.251, 0.271, 0.309, 0.367] }], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "bar", ...axis,
      chartColors: [HEX.accent6, HEX.accent6, HEX.accent4, HEX.accent6, HEX.accent1], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000",
      showLegend: false, title: "PR-AUC, frozen March 2026 snapshot (70,831 test CVEs, 277 positives)",
      barGapWidthPct: 55, catAxisOrientation: "maxMin", objectName: name("Chart frozen PR-AUC"),
    });
    caption(s, X2, capY2, two.w, "0.367 vs. 0.271: +35.4%.",
      "Paired-bootstrap 95% CI of the difference +0.054 to +0.142; Holm-adjusted p = 0.009. RRF's lead over CombSUM is not statistically distinguishable (backup).");
    s.addNotes(
      "First the conventional result. On the frozen snapshot, RRF reaches a PR-AUC of 0.367 against 0.271 for EPSS, a thirty-five percent gain. The paired-bootstrap interval excludes zero and the Holm-adjusted p-value is 0.009. " +
      "Seventy-one of the top one hundred ranked CVEs are KEV-listed, against forty-four for EPSS. " +
      "We compared five other fusion methods on the identical three inputs and RRF came first, although its lead over simple score summation is not statistically distinguishable. " +
      "One detail for questions: the tabular ranker inside RRF is the saved model, 0.251. The audit slides retrain that configuration and get 0.268: same features, a separate training run. " +
      "If Maya stopped here, this would be the headline. She does not stop here.");
  }

  // ════════════════ 8. RQ1 historical ════════════════
  {
    const s = strip("Results", "SCENE 6  ·  RQ1, HISTORICAL EPSS", "Then she checks the dates, and the audit catches hindsight");
    picFrame(s, "07a_date", M, TOP, two.w, two.h, "Maya points at her screen: published 2024, score observed 2026");
    caption(s, M, capY2, two.w, "The evidence was dated after the outcome.",
      "A March 2026 EPSS value for a 2024 CVE carries up to 21 months of later evidence [17]. EPSS alone barely moves; the learned rankers that use it as a feature lose the most.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [
      { name: "EPSS", labels: ["Frozen snapshot (March 2026)", "Historical EPSS (month of publication)"], values: [0.271, 0.258] },
      { name: "RRF", labels: ["Frozen snapshot (March 2026)", "Historical EPSS (month of publication)"], values: [0.367, 0.268] },
    ], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", barGrouping: "clustered", ...axis,
      chartColors: [HEX.accent4, HEX.accent1], valAxisMinVal: 0, valAxisMaxVal: 0.5, valAxisMajorUnit: 0.1,
      dataLabelFormatCode: "0.000", showLegend: true, legendPos: "b", title: "PR-AUC, same 70,831 test CVEs (277 positives)",
      barGapWidthPct: 70, objectName: name("Chart frozen vs historical"),
    });
    caption(s, X2, capY2, two.w, "+3.8%, not statistically reliable.",
      "0.268 vs. 0.258; 95% CI of the difference −0.031 to +0.052. The frozen +35.4% gap is not a deployment-time claim, and the audit is what shows it.");
    s.addNotes(
      "This is the central methodological finding. A March 2026 EPSS score for a 2024 vulnerability carries up to twenty-one months of later evidence. " +
      "When we replace it with the first monthly score on or after publication, RRF scores 0.268 and EPSS 0.258. The difference is plus 3.8 percent, the confidence interval spans zero, and the permutation test is not significant. In the top one hundred, the count goes from 71 against 44 to 56 against 53. " +
      "EPSS as a standalone ranker loses little PR-AUC, 0.271 to 0.258. What falls are the two XGBoost rankers that use EPSS as a feature: 0.251 to 0.139 and 0.309 to 0.210. They were retrained with EPSS as of the June 2024 cutoff and tested on scores from the month of publication. Those two ranker figures are from our result file, not from the paper. " +
      "With 277 positives the interval is wide, so this is absence of evidence for a gain, not evidence of equality. One caveat I raise myself: the archive spans two EPSS model versions. " +
      "We report it as a null result. The useful part for other studies is the check itself: re-score with archived EPSS before claiming a gain over EPSS.");
  }

  // ════════════════ 9. RQ2 ════════════════
  {
    const s = strip("Results", "SCENE 7  ·  RQ2, LEAKAGE AUDIT", "So she audits every input for leakage");
    picFrame(s, "08a_audit", M, TOP, three.w, three.h, "Close-up: a magnifying glass over the list of model inputs shows Public PoC flag and Metasploit flag in red");
    caption(s, M, capY3, three.w, "Exploit-derived inputs leak the answer.",
      "Added on purpose as a stress test: PoC and Metasploit flags (shown), a signal count, days since PoC, and a composite score.", 1.2);
    const x2 = M + three.w + GAP, x3 = M + 2 * (three.w + GAP);
    blankFrame(s, x2, TOP, three.w, three.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["Exploit-derived proxies", "Clean tabular (retrained)"], values: [1.0, 0.268] }], {
      x: x2 + 0.1, y: TOP + 0.1, w: three.w - 0.2, h: three.h - 0.2, barDir: "col", ...axis,
      chartColors: [HEX.accent2, HEX.accent1], invertedColors: [HEX.accent2],
      valAxisMinVal: 0, valAxisMaxVal: 1.1, valAxisMajorUnit: 0.25, dataLabelFormatCode: "0.000", showLegend: false,
      title: "PR-AUC, circularity stress test (diagnostic)", barGapWidthPct: 90, objectName: name("Chart circularity"),
    });
    caption(s, x2, capY3, three.w, "3.73× in a deliberately invalid stress test.",
      "1.000 against 0.268 clean. An upper bound on circularity, not a deployable model.", 1.2);
    blankFrame(s, x3, TOP, three.w, three.h);
    s.addChart(pres.charts.LINE, [{ name: "PR-AUC", labels: ["2021-22", "2022-23", "2023-24", "2024-25"], values: [0.881, 0.705, 0.680, 0.279] }], {
      x: x3 + 0.1, y: TOP + 0.1, w: three.w - 0.2, h: three.h - 0.2, ...axis, chartColors: [HEX.accent3],
      lineSize: 3, lineDataSymbolSize: 9, dataLabelPosition: "b",
      valAxisMinVal: 0, valAxisMaxVal: 1.0, valAxisMajorUnit: 0.25, dataLabelFormatCode: "0.000", showLegend: false,
      title: "PR-AUC by test year (June to May), frozen enrichment", objectName: name("Chart rolling window"),
    });
    caption(s, x3, capY3, three.w, "0.88 falls to 0.28",
      "as post-publication hindsight shrinks. A 29-feature publication-time control holds ROC-AUC at 0.743 to 0.755.", 1.2);
    s.addNotes(
      "RQ2 generalizes that observation. The audit checks four leakage types: temporal, label, entity-proxy, and correlation. " +
      "In the middle, a deliberate stress test. We add five signals derived from exploit evidence: proof-of-concept and Metasploit flags, an exploit-signal count, days since the first proof of concept, and a composite score built from them. The model reaches a PR-AUC of one; the clean configuration reaches 0.268. " +
      "That is a 3.73-fold ratio, and it is an intentionally invalid upper bound: the KEV flag itself is excluded, so this measures proxy and label overlap, not a model anyone would deploy. " +
      "On the right, the same pipeline and hyperparameters retrained at four yearly boundaries with frozen enrichment. PR-AUC falls from 0.88 for the oldest test year to 0.28 for the most recent. " +
      "As a control, a 29-feature set without EPSS, product and reference counts, and elapsed time stays flat at ROC-AUC 0.743 to 0.755 across the same windows. One caveat: the oldest window also has about twice the positive rate, which lifts PR-AUC somewhat by itself. The control still uses final NVD text and March 2026 labels, so it is a bound, not a prospective replay.");
  }

  // ════════════════ 10. RQ3 grounding ════════════════
  {
    const s = strip("Results", "SCENE 8  ·  RQ3, GROUNDED BRIEFS", "Every identifier and link in a brief is checked exactly");
    picFrame(s, "09a_brief", M, TOP, two.w, two.h, "Maya reads a brief handed over by the assistant robot; each line carries a check-mark stamp");
    caption(s, M, capY2, two.w, "GPT-4o-mini writes each brief from retrieved ATT&CK techniques.",
      "A technique must exist in the pinned ATT&CK v18.1 corpus [14]; a link is kept only if it is on the CVE's own reference list.");
    blankFrame(s, X2, TOP, two.w, two.h);
    T(s, "150 briefs: the top 150 test CVEs by RRF rank (84 in KEV)",
      { x: X2 + 0.35, y: TOP + 0.2, w: two.w - 0.7, h: 0.32, fontSize: 13, color: INK2 });
    const rows = [
      ["0 of 150", "briefs contained a fabricated ATT&CK identifier", TEAL_T],
      ["149 of 150", "briefs cited an advisory listed on the CVE record", TEAL_T],
      ["2 of 271", "LLM-proposed mappings were outside the retrieved set and removed; none was a non-existent ID", AMBER_T],
    ];
    const rh = (two.h - 0.75) / 3;
    rows.forEach(([big, label, col], i) => {
      const y = TOP + 0.6 + i * rh;
      T(s, big, { x: X2 + 0.35, y, w: 2.3, h: rh, fontSize: 30, bold: true, color: col, valign: "middle" });
      T(s, label, { x: X2 + 2.75, y, w: two.w - 3.1, h: rh, fontSize: 14, color: INK2, valign: "middle" });
    });
    caption(s, X2, capY2, two.w, "Exact-match checks, not opinions.",
      "They cover identifiers and links. Whether a valid technique is the right one is a semantic question, addressed next.");
    s.addNotes(
      "RQ3 concerns the explanation layer, which uses a language model, GPT-4o-mini. The rule covers two things that can be checked exactly: technique identifiers and reference links. " +
      "For each CVE we retrieve the nearest ATT&CK techniques, check that every identifier exists in the pinned ATT&CK version 18.1 corpus, generate a structured brief, and keep a remediation link only if it appears verbatim in the CVE's own reference list. " +
      "On briefs for the one hundred and fifty highest-ranked test CVEs, eighty-four of them in KEV: no fabricated technique identifier, and one hundred and forty-nine cite a CVE-listed advisory. " +
      "The model never proposed an identifier that does not exist; the two removals were techniques outside the retrieved set. These are exact-match checks. " +
      "On the free text, an automated scorer finds on average 58 percent of a brief's claims supported by the retrieved evidence, so semantic quality is the next question.");
  }

  // ════════════════ 11. RQ3 verification ════════════════
  {
    const s = strip("Results", "SCENE 9  ·  RQ3, VERIFICATION", "A verification pass asks: does this technique really apply?");
    picFrame(s, "10a_ask_twice", M, TOP, two.w, two.h, "Maya, arms crossed, questions the robot, which keeps one card and sets two aside");
    caption(s, M, capY2, two.w, "A Chain-of-Verification-inspired pass [20]",
      "asks the model whether each retrieved technique describes how this CVE would be exploited, and drops the rest. Over-rationalized: a valid technique that does not fit, or another unsupported claim.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [
      { name: "Standard retrieval", labels: ["Over-rationalized", "Relevant technique (non-abstaining)", "Abstained"], values: [27.3, 87.8, 1.3] },
      { name: "With verification", labels: ["Over-rationalized", "Relevant technique (non-abstaining)", "Abstained"], values: [12.0, 95.9, 34.7] },
    ], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", barGrouping: "clustered", ...axis,
      chartColors: [HEX.accent4, HEX.accent1], valAxisMinVal: 0, valAxisMaxVal: 110, valAxisMajorUnit: 25,
      dataLabelFormatCode: '0.0"%"', valAxisLabelFormatCode: '0"%"', showLegend: true, legendPos: "b",
      title: "150 briefs per arm, GPT-4o judge", barGapWidthPct: 60, objectName: name("Chart verification"),
    });
    caption(s, X2, capY2, two.w, "Higher precision at the cost of coverage.",
      "Mappings per brief fall from 2.96 to 0.83. One LLM judge (GPT-4o); agreement with a second LLM is κ = 0.55 on relevance and 0.29 on over-rationalization. No human raters.");
    s.addNotes(
      "The residual failure mode is over-rationalization: retrieval surfaces a technique that is lexically similar but wrong, and the model justifies it instead of declining it. A GPT-4o judge flags this in 27 percent of standard briefs. " +
      "So before the brief is written, a Chain-of-Verification-inspired pass asks, for each candidate, whether it describes how this CVE would be exploited. Over-rationalization drops to 12 percent. " +
      "Relevance, measured only on the briefs that still carry a mapping, about 148 and then 98, rises from 88 to 96 percent. " +
      "The cost: the system abstains on about 35 percent of briefs, and the average brief goes from about three mapped techniques to fewer than one. This is a precision and coverage trade-off, offered as an optional mode. " +
      "The evidence type matters. Every bar here is one GPT-4o judge. On the baseline briefs we compared it with a second model, GPT-5.1: agreement was moderate on relevance, kappa 0.55, and fair on the over-rationalization flag, kappa 0.29. So the 27 to 12 drop is exploratory, not a human rating.");
  }

  // ════════════════ 12. RQ4 ════════════════
  {
    const s = strip("Results", "SCENE 10  ·  RQ4, ASSET CONTEXT", "Not every machine matters equally");
    picFrame(s, "11a_servers", M, TOP, two.w, two.h, "Maya walks past four server racks; one is lit red");
    caption(s, M, capY2, two.w, "An SSVC-inspired tree [15] assigns five tiers with deadlines:",
      "Patch now (24 h), Mitigate now (24 h), Patch in window (30 days), Monitor (90 days), Accept (1 year). The first two form the urgent queue.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const bx = X2 + 0.3, half = (two.w - 0.6 - 0.3) / 2;
    T(s, "Synthetic fleet: 51 assets, 5,435 asset-CVE pairs",
      { x: bx, y: TOP + 0.15, w: two.w - 0.6, h: 0.3, fontSize: 13, color: INK2 });
    T(s, "PAPER: VEX PER CVE", { x: bx, y: TOP + 0.52, w: half, h: 0.26, fontSize: 11, bold: true, color: INK2, charSpacing: 1 });
    T(s, "23.4%", { x: bx, y: TOP + 0.78, w: half, h: 0.6, fontSize: 34, bold: true, color: INK, valign: "middle" });
    T(s, "of decisions change", { x: bx, y: TOP + 1.38, w: half, h: 0.28, fontSize: 14, color: INK2 });
    T(s, "STRICTER: VEX PER ASSET", { x: bx + half + 0.3, y: TOP + 0.52, w: half, h: 0.26, fontSize: 11, bold: true, color: TEAL_T, charSpacing: 1 });
    T(s, "19.1%", { x: bx + half + 0.3, y: TOP + 0.78, w: half, h: 0.6, fontSize: 34, bold: true, color: TEAL_T, valign: "middle" });
    T(s, "of decisions still change", { x: bx + half + 0.3, y: TOP + 1.38, w: half, h: 0.28, fontSize: 14, color: INK2 });
    s.addChart(pres.charts.BAR, [{ name: "Urgent pairs", labels: ["No asset context", "Asset context (paper)", "Asset context (stricter)"],
      values: [1286, 177, 533] }], {
      x: bx - 0.1, y: TOP + 1.72, w: two.w - 0.4, h: two.h - 1.8, barDir: "bar", ...axis,
      chartColors: [HEX.accent6, HEX.accent4, HEX.accent1], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 1500, valAxisMajorUnit: 500, dataLabelFormatCode: "#,##0", valAxisLabelFormatCode: "#,##0",
      showLegend: false, title: "Urgent queue (asset-CVE pairs)",
      barGapWidthPct: 45, catAxisOrientation: "maxMin", objectName: name("Chart urgent queue"),
    });
    caption(s, X2, capY2, two.w, "The effect holds under a stricter rule.",
      "Applying a VEX statement only to the asset it names still cuts the urgent queue by 59% (86% in the paper). Both measure rule sensitivity to synthetic evidence, not enterprise workload.");
    s.addNotes(
      "RQ4 asks what happens when the decision engine knows about the asset. The same vulnerability does not matter equally on every machine. " +
      "An SSVC-inspired tree assigns one of five tiers, from Patch now within twenty-four hours down to Accept with annual review, and records why. The first two tiers form the urgent queue. " +
      "Without asset context, every KEV vulnerability goes to an urgent tier; that only verifies the rule executes. The informative test is an ablation on a seeded synthetic fleet of fifty-one assets and about fifty-four hundred asset and CVE pairs. " +
      "In the paper, asset evidence changes 23.4 percent of decisions and cuts the urgent queue from 1,286 to 177, an 86 percent reduction. There, a VEX statement recorded for a CVE applies wherever that CVE appears. " +
      "Since the paper we hardened the engine with a stricter rule: a VEX statement applies only to the asset it names. Under that conservative rule the effect holds: 19.1 percent of decisions still change and the urgent queue still falls by 59 percent, to 533. " +
      "So the direction is robust to how widely a statement is applied. As the paper states, this is sensitivity to synthetic evidence; it is not a measured reduction in enterprise workload.");
  }

  // ════════════════ 13. Demonstration ════════════════
  pres.addSection({ title: "Discussion" });
  {
    const s = strip("Discussion", "SCENE 11  ·  SINCE THE PAPER", "A real inventory in, a short justified list out: a demonstration");
    picFrame(s, "12a_sbom", M, TOP, two.w, two.h, "Maya holds a very long printed inventory; her screen shows a short list");
    caption(s, M, capY2, two.w, "A real software bill of materials (SBOM),",
      "generated with Syft from the public Apache HTTP Server 2.4.49 image and registered by us as internet-facing and high-criticality. Installed versions are compared with NVD's vulnerable version ranges.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const tx = X2 + 0.3, tw = two.w - 0.6;
    T(s, "legacy-web-frontend (httpd 2.4.49): 73 matching CVEs", { x: tx, y: TOP + 0.15, w: tw, h: 0.3, fontSize: 14, bold: true });
    const tiles = [["Patch now", "3", RED_T], ["Mitigate now", "1", RED_T], ["Patch in window", "0", AMBER_T], ["Monitor", "17", BLUE_T], ["Accept", "52", TEAL_T]];
    const tileW = (tw - 0.4) / 5;
    tiles.forEach(([label, num, col], i) => {
      const x = tx + i * (tileW + 0.1);
      s.addShape(pres.shapes.RECTANGLE, { x, y: TOP + 0.55, w: tileW, h: 0.82, fill: { color: PAPER }, line: { color: HAIR, width: 1 }, objectName: name("Tile") });
      T(s, label, { x: x + 0.08, y: TOP + 0.6, w: tileW - 0.1, h: 0.26, fontSize: 11, bold: true, color: col });
      T(s, num, { x: x + 0.08, y: TOP + 0.86, w: tileW - 0.1, h: 0.46, fontSize: 22, bold: true, valign: "middle" });
    });
    const findings = [
      ["CVE-2021-42013", "Patch now", "Known exploited; installed 2.4.49 is the vulnerable version"],
      ["CVE-2021-41773", "Patch now", "Known exploited; installed 2.4.49 is the vulnerable version"],
      ["CVE-2024-38475", "Patch now", "Known exploited; vulnerable from 2.4.0 up to 2.4.60"],
      ["CVE-2021-44790", "Mitigate now", "Public PoC, not confirmed reachable; vulnerable below 2.4.52"],
    ];
    const fy = TOP + 1.52, fh = (two.h - 1.52 - 0.42) / findings.length;
    findings.forEach(([cve, act, ev], i) => {
      const y = fy + i * fh;
      T(s, cve, { x: tx, y, w: 1.55, h: fh, fontSize: 13, bold: true, valign: "middle", fontFace: "Courier New" });
      T(s, act, { x: tx + 1.6, y, w: 1.15, h: fh, fontSize: 13, bold: true, color: RED_T, valign: "middle" });
      T(s, ev, { x: tx + 2.8, y, w: tw - 2.8, h: fh, fontSize: 12, color: INK2, valign: "middle" });
    });
    T(s, "Transcribed from the VulnTriage Assets page (full screenshot in backup).",
      { x: tx, y: TOP + two.h - 0.36, w: tw, h: 0.26, fontSize: 11, color: INK2, italic: true });
    caption(s, X2, capY2, two.w, "73 matching CVEs, 4 urgent, 52 accepted.",
      "CVE-2021-41773 and CVE-2021-42013, both in CISA KEV, are Patch now with the installed version as evidence. A known-answer check, not an evaluation.");
    s.addNotes(
      "The paper listed validating the SBOM and VEX pipeline on real inventories as future work, so here is where that stands. " +
      "This is a real software bill of materials, generated with Syft from the public Apache HTTP Server 2.4.49 image. We registered it as an internet-facing, high-criticality asset. " +
      "The system compares each installed version with the vulnerable version ranges NVD publishes. Seventy-three CVEs match the installed products; four are urgent, and fifty-two are accepted because the installed version is outside the vulnerable range. " +
      "The two at the top are the 2021 path-traversal vulnerabilities, both in the KEV catalog, and the evidence line shows the installed version inside the vulnerable range. " +
      "This is a known-answer demonstration, one of three public images we ran, not an evaluation. Versions are compared with upstream ranges, so a distribution backport can still be reported unless a VEX statement resolves it.");
  }

  // ════════════════ 14. Limitations and next steps ════════════════
  {
    const s = strip("Discussion", "SCENE 12  ·  LIMITATIONS AND NEXT STEPS", "What this study bounds, and what comes next");
    picFrame(s, "13a_next", M, TOP, two.w, two.h, "Maya beside a whiteboard headed Next steps: historical replay, real inventories, human raters, cost-quality study");
    caption(s, M, capY2, two.w, "The boundaries are part of the result.",
      "Each number holds for its evidence date, its label (KEV listing), and its kind of validation: exact-match, LLM-judged, or synthetic.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const lim = [
      ["One 2026 snapshot.", "Only EPSS is replaced historically.", "Replay historical NVD and KEV states."],
      ["KEV labels are curated and incomplete [16].", "Negatives may later be exploited.", "Covered by the same historical replay."],
      ["Synthetic asset evidence.", "The fleet, VEX statements, controls, and reachability are simulated.", "Enterprise inventories and vendor-issued VEX."],
      ["LLM-judged brief quality.", "Identifier and link checks are exact; relevance is not human-rated.", "Two blinded cybersecurity annotators; a preregistered cost-quality study."],
    ];
    const rh = (two.h - 0.3) / lim.length;
    lim.forEach(([head, body, next], i) => {
      const y = TOP + 0.15 + i * rh;
      s.addShape(pres.shapes.RECTANGLE, { x: X2 + 0.3, y: y + 0.1, w: 0.22, h: 0.22, fill: { color: WHITE },
        line: { color: INK, width: 1.5 }, objectName: name("Checkbox") });
      T(s, [
        { text: head + " ", options: { bold: true, color: INK } }, { text: body, options: { color: INK2, breakLine: true } },
        { text: "Next: ", options: { bold: true, color: TEAL_T } }, { text: next, options: { color: INK2 } },
      ], { x: X2 + 0.7, y: y + 0.03, w: two.w - 1.0, h: rh - 0.06, fontSize: 13.5 });
    });
    caption(s, X2, capY2, two.w, "Four open boxes.", "Each one needs data or people this study did not have.");
    s.addNotes(
      "Here is what the study bounds, and what comes next. These four limitations are stated in the paper. " +
      "First, this is a chronological split over a single 2026 snapshot. We replaced EPSS historically, but not every NVD field or the KEV labels. The next step is a full historical replay. " +
      "Second, KEV is curated and incomplete; strictly, we predict KEV listing. " +
      "Third, the asset experiment uses a synthetic fleet. The next step is independently collected enterprise inventories and vendor-issued VEX documents; the ingestion pipeline is already in place. " +
      "Fourth, the deterministic checks on identifiers and links are exact, but the semantic quality of the briefs is judged by language models. The next step is two blinded cybersecurity annotators and a preregistered cost-quality study. " +
      "Each of these needs data or people this study did not have. If asked about human ground truth: we have since run one retrieval-only comparison against MITRE's analyst mappings, and it is in the backup slides.");
  }

  // ════════════════ 15. Conclusions ════════════════
  {
    const s = strip("Discussion", "SCENE 13  ·  CONCLUSIONS", "What the study establishes");
    picFrame(s, "14a_sunrise", M, TOP, two.w, two.h, "Sunrise; Maya with a coffee looks at a short tidy list on her screen");
    caption(s, M, capY2, two.w, "Next:",
      "a full historical replay of NVD and KEV, real enterprise inventories and vendor VEX, two blinded human annotators, and a preregistered cost-quality study.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const take = [
      ["RRF reaches PR-AUC 0.367 against 0.271 for EPSS on the frozen snapshot; with historical EPSS the +3.8% difference is not statistically reliable.", TEAL_T],
      ["A leakage audit quantifies hindsight: a deliberately invalid stress test reaches 1.000 (3.73× the clean 0.268), and frozen enrichment inflates older test years.", RED_T],
      ["No fabricated ATT&CK identifier in 150 briefs under exact-match checks; optional verification cuts LLM-judged over-rationalization from 27.3% to 12.0% and abstains on 34.7%.", AMBER_T],
      ["On a synthetic fleet, asset evidence changes 19% to 23% of asset-CVE decisions, depending on VEX scope, each with a recorded rationale.", BLUE_T],
    ];
    const rh = (two.h - 0.3) / take.length;
    take.forEach(([t, col], i) => {
      const y = TOP + 0.15 + i * rh;
      T(s, String(i + 1), { x: X2 + 0.3, y, w: 0.45, h: rh - 0.06, fontSize: 24, bold: true, color: col, valign: "middle" });
      T(s, t, { x: X2 + 0.85, y, w: two.w - 1.15, h: rh - 0.06, fontSize: 13.5, valign: "middle" });
    });
    caption(s, X2, capY2, two.w, "An auditable integration built around EPSS, not a replacement for it.",
      "The contribution is the workflow and the evidence-aligned evaluation around the score.");
    s.addNotes(
      "To conclude. One: rank fusion gives a clear, significant gain in the frozen evaluation, and that gain is not statistically reliable once EPSS is taken from the month of publication. RRF is an integration choice, not a demonstrated replacement for EPSS. " +
      "Two: the leakage audit quantifies two sources of hindsight, feature and label circularity and retroactive enrichment, and both are large. " +
      "Three: deterministic checks prevent invalid identifiers and unsupported links, and optional verification improves judged precision at a real coverage cost. " +
      "Four: asset evidence changes roughly one fifth to one quarter of recommended actions in a synthetic setting, with every change traceable to evidence. " +
      "The takeaway for other studies: re-score with archived EPSS before reporting a gain over EPSS. " +
      "Maya ends with a shorter list, and its evidence and limits are stated.");
  }

  // ════════════════ 16. Thank you ════════════════
  {
    const s = strip("Discussion", "THE END", "Thank you. Questions and discussion");
    const cw = two.h * (922 / 1024);
    picFrame(s, "15a_thanks_crop", M, TOP, cw, two.h, "Maya and the assistant robot wave goodbye");
    caption(s, M, capY2, cw, "Maya is fictional.", "The numbers are not: each comes from the paper or from the study's recorded result files.");
    const px = M + cw + GAP, pw = W - M - px;
    blankFrame(s, px, TOP, pw, two.h);
    T(s, [
      { text: "In one line", options: { bold: true, color: TEAL_T, fontSize: 13, breakLine: true } },
      { text: "Frozen snapshot: RRF 0.367 vs. EPSS 0.271 (+35.4%). With historical EPSS: 0.268 vs. 0.258 (+3.8%, not significant). The audit is what tells the two apart.", options: { color: INK, bold: true, fontSize: 16 } },
    ], { x: px + 0.4, y: TOP + 0.25, w: pw - 0.8, h: 1.35, fontSize: 16 });
    T(s, [
      { text: "Huraib Jan Sarhandi", options: { bold: true, color: INK, fontSize: 18, breakLine: true } },
      { text: "sarhandih1@montclair.edu", options: { color: INK2, breakLine: true, paraSpaceAfter: 8 } },
      { text: "Weitian Wang", options: { bold: true, color: INK, fontSize: 18, breakLine: true } },
      { text: "wangw@montclair.edu", options: { color: INK2, breakLine: true, paraSpaceAfter: 8 } },
      { text: "School of Computing, Montclair State University, USA", options: { color: INK2, breakLine: true, paraSpaceAfter: 8 } },
      { text: "Code: ", options: { bold: true, color: INK } },
      { text: "github.com/huraibjan/vulntriage", options: { color: TEAL_T } },
    ], { x: px + 0.4, y: TOP + 1.7, w: pw - 0.8, h: two.h - 1.9, fontSize: 15, valign: "top" });
    caption(s, px, capY2, pw, "Paper 166, IEEE ISAIA 2026.",
      "Illustrations are AI-generated for this talk; all data, charts, and results come from the study.");
    s.addNotes(
      "Thank you. I am happy to take questions. Likely ones, with short answers. " +
      "Why not just use EPSS? With historical EPSS we do not show a reliable ranking gain over it; the system's value is the audited workflow around the score. " +
      "Why keep RRF? Under historical EPSS it is not worse than EPSS on any metric we report: PR-AUC 0.268 against 0.258, ROC-AUC 0.918 against 0.855, top-100 hits 56 against 53. I do not claim it is better. " +
      "Why KEV? It is a public, curated catalog; it is narrower than exploited in the wild, which is why the base rate is 0.39 percent and not 3 percent. " +
      "Why k equals 60? It is the default from Cormack and colleagues; a post hoc sweep on the test set gave 0.379 at k equals 5, and choosing it there would be optimistic. " +
      "Is an LLM judging an LLM circular? The central claims are exact-match checks; the judged figures are labeled exploratory. " +
      "Concurrent work, Alpay and Alpay 2026, also reports large inflation under retrospective evidence, consistent with our finding.");
  }

  // ════════════════ 17. References ════════════════
  {
    const s = strip("Discussion", "REFERENCES", "References cited in this talk");
    const refs = [
      "[1] National Vulnerability Database, \"NVD Dashboard,\" NIST, 2024.",
      "[2] O. Suciu et al., \"Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits,\" in Proc. USENIX Security, 2022.",
      "[3] J. Jacobs et al., \"Exploit Prediction Scoring System (EPSS),\" Digital Threats: Research and Practice, vol. 2, no. 3, 2021.",
      "[4] P. Mell, K. Scarfone, and S. Romanosky, \"Common Vulnerability Scoring System,\" IEEE Security & Privacy, vol. 4, no. 6, 2006.",
      "[5] K. Khanmohammadi et al., \"ExploitabilityBirthMark: An Early Predictor of the Likelihood of Exploitation,\" in FPS, LNCS 15533, 2025.",
      "[6] D. Arp et al., \"Dos and Don'ts of Machine Learning in Computer Security,\" in Proc. USENIX Security, 2022.",
      "[7] J. Jacobs et al., \"Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights,\" in Proc. IEEE EuroS&PW, 2023.",
      "[8] G. V. Cormack, C. L. A. Clarke, and S. Buettcher, \"Reciprocal Rank Fusion Outperforms Condorcet and Individual Rank Learning Methods,\" in Proc. ACM SIGIR, 2009.",
      "[9] O. Grigorescu et al., \"CVE2ATT&CK: BERT-Based Mapping of CVEs to MITRE ATT&CK Techniques,\" Algorithms, vol. 15, no. 9, 2022.",
      "[10] R. Branescu, O. Grigorescu, and M. Dascalu, \"Automated Mapping of CVEs to MITRE ATT&CK Tactics,\" Information, vol. 15, no. 4, 2024.",
      "[11] C. Zhang et al., \"VTT-LLM,\" Mathematics, vol. 12, no. 9, 2024.",
      "[13] R. Fayyazi et al., \"ProveRAG: Provenance-Driven Vulnerability Analysis with Automated Retrieval-Augmented LLMs,\" arXiv:2410.17406, 2024.",
      "[14] MITRE ATT&CK, \"ATT&CK v18.1 Release and STIX Data,\" 2025.",
      "[15] J. Spring et al., \"Prioritizing Vulnerability Response: A Stakeholder-Specific Vulnerability Categorization (Version 2.0),\" CMU SEI, 2021.",
      "[16] CISA, \"Known Exploited Vulnerabilities Catalog,\" 2026.",
      "[17] FIRST, \"EPSS Data and Statistics,\" 2026.",
      "[18] F. Alpay and T. Alpay, \"Compute-Budgeted Exploitability Evidence Graphs for Prospective Vulnerability Triage,\" arXiv:2606.19076, 2026.",
      "[20] S. Dhuliawala et al., \"Chain-of-Verification Reduces Hallucination in Large Language Models,\" in Findings of ACL, 2024.",
      "Backup slides only: [A] P. Mell and J. Spring, \"Likely Exploited Vulnerabilities,\" NIST CSWP 41, 2025.  [B] MITRE Center for Threat-Informed Defense, Mappings Explorer: CISA KEV to ATT&CK, 2025.",
    ];
    const colW = (W - 2 * M - 0.4) / 2, halfN = 10;
    T(s, refs.slice(0, halfN).map((t, i, a) => ({ text: t, options: { breakLine: i < a.length - 1, paraSpaceAfter: 5 } })),
      { x: M, y: TOP - 0.05, w: colW, h: 5.3, fontSize: 11.5, color: INK2 });
    T(s, refs.slice(halfN).map((t, i, a) => ({ text: t, options: { breakLine: i < a.length - 1, paraSpaceAfter: 5 } })),
      { x: M + colW + 0.4, y: TOP - 0.05, w: colW, h: 5.3, fontSize: 11.5, color: INK2 });
    s.addNotes("Reference numbers follow the paper's reference list, so [n] here is [n] in the paper. [A] and [B] are used only on the backup slides.");
  }

  // ════════════════ Backup ════════════════
  pres.addSection({ title: "Backup" });
  const full = { x: M, w: W - 2 * M, h: 4.0 };
  const backupCaption = (s, lead, body) => caption(s, M, TOP + full.h + 0.16, full.w, lead, body, 1.05);
  {
    const s = strip("Backup", "BACKUP  ·  FUSION METHODS", "Six fusion methods over the same three rank sources");
    blankFrame(s, full.x, TOP, full.w, full.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["RRF (k = 60)", "CombSUM", "CombMNZ", "Optimized blend", "Borda count", "Logistic-regression stacking"],
      values: [0.3671, 0.3536, 0.3536, 0.3536, 0.3065, 0.2589] }], {
      x: full.x + 0.2, y: TOP + 0.12, w: full.w - 0.4, h: full.h - 0.24, barDir: "bar", ...axis,
      chartColors: [HEX.accent1, HEX.accent6, HEX.accent6, HEX.accent6, HEX.accent6, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000", showLegend: false,
      title: "PR-AUC, frozen snapshot (70,831 test CVEs)", barGapWidthPct: 55, catAxisOrientation: "maxMin", objectName: name("Chart fusion baselines"),
    });
    backupCaption(s, "RRF vs. CombSUM: Δ +0.014, 95% CI −0.001 to +0.029.",
      "CombSUM, CombMNZ, and the optimized blend coincide (the blend converged to equal weights). A post hoc k sweep from 5 to 300 spans 0.379 to 0.345; k = 60 is kept because choosing k on the test set would be optimistic.");
    s.addNotes("Backup for questions on the fusion choice and on k. All methods use the identical three rank sources.");
  }
  {
    const s = strip("Backup", "BACKUP  ·  FEATURE NECESSITY", "On the frozen snapshot, EPSS is the least replaceable input");
    blankFrame(s, full.x, TOP, full.w, full.h);
    s.addChart(pres.charts.BAR, [{ name: "Relative PR-AUC drop", labels: ["EPSS", "Reference and product counts", "Days since publication", "CVSS vector"],
      values: [87, 29, 17, 13] }], {
      x: full.x + 0.2, y: TOP + 0.12, w: full.w - 0.4, h: full.h - 0.24, barDir: "bar", ...axis,
      chartColors: [HEX.accent4, HEX.accent6, HEX.accent6, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 100, valAxisMajorUnit: 25, dataLabelFormatCode: '0"%"', valAxisLabelFormatCode: '0"%"',
      showLegend: false, title: "Relative PR-AUC drop when a feature group is removed and the model retrained (top 4 of 7 groups)",
      barGapWidthPct: 55, catAxisOrientation: "maxMin", objectName: name("Chart feature ablation"),
    });
    backupCaption(s, "Removing EPSS takes PR-AUC from 0.268 to 0.034.",
      "TreeSHAP ranks reference count first (33%), then EPSS (27%): attribution measures average contribution, ablation measures unique signal. Measured with the March 2026 EPSS value; not a projection of deployment loss.");
    s.addNotes("Backup for questions on interpretability and on how much of the model is EPSS.");
  }
  {
    const s = strip("Backup", "BACKUP  ·  CHECKS SINCE THE PAPER", "Two further checks: analyst-labeled mappings and NIST LEV");
    blankFrame(s, M, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [{ name: "Top-3 hit rate", labels: ["VulnTriage retriever", "Constant guess: 3 most common techniques"], values: [0.267, 0.754] }], {
      x: M + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", ...axis,
      chartColors: [HEX.accent1, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 1, valAxisMajorUnit: 0.25, dataLabelFormatCode: "0.000", showLegend: false,
      title: "Top-3 hit rate vs. CTID analyst mappings [B] (345 KEV CVEs)", barGapWidthPct: 90, objectName: name("Chart CTID"),
    });
    caption(s, M, capY2, two.w, "Retrieval alone, with no LLM, agrees with analysts on 27%.",
      "Exploitation-technique mappings only: 0.222 (334 CVEs). CTID also maps impact, which a description often cannot reveal, and the constant guess is fitted on the same CVEs.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["NIST LEV", "EPSS", "RRF"], values: [0.252, 0.271, 0.367] }], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", ...axis,
      chartColors: [HEX.accent3, HEX.accent4, HEX.accent1], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000", showLegend: false,
      title: "PR-AUC, frozen snapshot, 70,831 test CVEs", barGapWidthPct: 90, objectName: name("Chart LEV"),
    });
    caption(s, X2, capY2, two.w, "RRF stays ahead of NIST's LEV metric [A].",
      "RRF minus LEV +0.115, 95% CI +0.063 to +0.164. LEV vs. EPSS: −0.019, CI −0.041 to +0.005 (2,000 resamples; LEV from monthly snapshots).");
    s.addNotes(
      "Backup. Two checks run since the paper. Left: agreement between our ATT&CK retriever alone, with no language model, and MITRE CTID's analyst mappings for KEV vulnerabilities: a top-three hit rate of 0.267, against 0.754 for always guessing the three most common techniques. " +
      "It is not a direct comparison with the brief-level relevance in RQ3: the analysts also map impact, which a description often does not reveal, and the constant guess is fitted on the same CVEs. It does show that retrieval is the component to improve, and that model-judged relevance is not human-validated accuracy. " +
      "Right: NIST's Likely Exploited Vulnerabilities metric as an additional baseline on the frozen snapshot. RRF remains significantly ahead of it, and LEV is not reliably different from EPSS as a ranker here. " +
      "Sources: results/ctid_attack_eval.json and results/lev_baseline.json.");
  }
  {
    const s = strip("Backup", "BACKUP  ·  DEMONSTRATION SCREENSHOT", "The Assets page behind the demonstration slide");
    const shot = path.join(ASSETS, "assets_page.png");
    const ih = 4.9, iw = ih * (1215 / 729);
    blankFrame(s, (W - iw) / 2 - 0.08, TOP - 0.08, iw + 0.16, ih + 0.16);
    s.addImage({ path: shot, x: (W - iw) / 2, y: TOP, w: iw, h: ih, objectName: name("Screenshot assets page"),
      altText: "VulnTriage Assets page showing a prioritized finding queue for an Apache HTTP Server 2.4.49 container" });
    s.addNotes("Backup: the application screen that the demonstration slide transcribes. Columns: CVE, action, SLA, CVSS, installed component with its match evidence, decision rationale, and the action without asset context.");
  }

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
