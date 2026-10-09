// Builds the comic-strip version of the IEEE ISAIA 2026 deck for VulnTriage.
//
//   NODE_PATH=<dir with node_modules> PPTX_SKILL_DIR=<pptx skill dir> node build_comic_deck.js
//
// One character (Maya, a vulnerability analyst) moves through the study frame by
// frame; every frame carries its caption underneath. Illustrations come from
// ../art/generated (see ../art/generate_frames.py). Every number is from the
// accepted paper (paper_166.pdf) or an artifact under results/.

const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const sharp = require("sharp");

const { applyTheme } = require(path.join(process.env.PPTX_SKILL_DIR, "scripts", "apply_theme.js"));

const HERE = __dirname;
const OUT = path.join(HERE, "VulnTriage_ISAIA2026_comic.pptx");
const GEN = path.join(HERE, "..", "art", "generated");
const ASSETS = path.join(HERE, "..", "assets");
// Frames are placed as JPEG copies: the PNG originals make the file too large to share.
const img = (id) => path.join(GEN, "jpg", id + ".jpg");

const THEME = {
  name: "VulnTriage Comic",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "1B2233", // ink
    lt1: "F6F7F9", // paper
    dk2: "4A5266", // secondary ink
    lt2: "FFFFFF", // frame fill
    accent1: "12A594", // teal
    accent2: "E5484D", // alert red
    accent3: "F5A524", // amber
    accent4: "3E63DD", // blue
    accent5: "D5D9E0", // hairline
    accent6: "9A9FAB", // grey series
    hlink: "12A594",
    folHlink: "4A5266",
  },
};
const HEX = THEME.colors;

const W = 13.333, H = 7.5, M = 0.7;
const TOP = 1.6;                 // top edge of every frame row
const GAP = 0.34;

(async () => {
  // Cover: crop the 3:2 illustration to the 16:9 slide.
  fs.mkdirSync(path.join(GEN, "jpg"), { recursive: true });
  for (const f of fs.readdirSync(GEN).filter((f) => /^\d\d.*\.png$/.test(f) && !f.includes("_169"))) {
    await sharp(path.join(GEN, f)).jpeg({ quality: 90 }).toFile(img(f.replace(/\.png$/, "")));
  }
  const cover = path.join(GEN, "jpg", "01_cover_169.jpg");
  await sharp(path.join(GEN, "01_cover.png")).extract({ left: 0, top: 80, width: 1536, height: 864 })
    .jpeg({ quality: 92 }).toFile(cover);

  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";
  pres.title = "VulnTriage: CVE Exploitability Prediction with Reciprocal Rank Fusion and Circularity-Aware Evaluation";
  pres.author = "Huraib Jan Sarhandi, Weitian Wang";
  pres.company = "Montclair State University";
  pres.subject = "IEEE ISAIA 2026";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };

  const C = pres.SchemeColor;
  const INK = C.text1, PAPER = C.background1, INK2 = C.text2, WHITE = C.background2;
  const TEAL = C.accent1, RED = C.accent2, AMBER = C.accent3, BLUE = C.accent4, HAIR = C.accent5;

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
      { placeholder: { options: { name: "kicker", type: "body", x: M, y: 0.42, w: 9, h: 0.3,
        fontSize: 12, bold: true, color: TEAL, charSpacing: 3, align: "left", valign: "middle", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "title", type: "title", x: M, y: 0.72, w: W - 2 * M, h: 0.7,
        fontSize: 30, bold: true, color: INK, align: "left", valign: "middle", margin: 0 }, text: "" } },
      { text: { text: "VulnTriage  ·  IEEE ISAIA 2026", options: {
        x: M, y: 7.08, w: 6, h: 0.26, fontSize: 10, color: INK2, margin: 0 } } },
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
  // An inked comic frame holding an illustration.
  const picFrame = (slide, id, x, y, w, h, alt) => {
    slide.addImage({ path: img(id), x, y, w, h, altText: alt, objectName: name("Frame art") });
    slide.addShape(pres.shapes.RECTANGLE, { x, y, w, h, fill: { color: WHITE, transparency: 100 },
      line: { color: INK, width: 2 }, objectName: name("Frame border") });
  };
  // An inked frame with a white ground, for a chart or a card ("her screen").
  const blankFrame = (slide, x, y, w, h) => slide.addShape(pres.shapes.RECTANGLE, {
    x, y, w, h, fill: { color: WHITE }, line: { color: INK, width: 2 }, objectName: name("Frame") });
  // Caption under a frame: optional bold lead-in, then the sentence.
  const caption = (slide, x, y, w, lead, body, h = 1.15) => T(slide, [
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

  // Frame geometry
  const two = { w: (W - 2 * M - GAP) / 2 };          // two frames, 3:2
  two.h = two.w * (1024 / 1536);
  const three = { w: (W - 2 * M - 2 * GAP) / 3 };    // three square frames
  three.h = three.w;
  const capY2 = TOP + two.h + 0.16, capY3 = TOP + three.h + 0.16;
  const X2 = M + two.w + GAP;

  // ════════════════ 1. Cover ════════════════
  pres.addSection({ title: "Opening" });
  {
    const s = pres.addSlide({ masterName: "COVER", sectionTitle: "Opening" });
    s.addImage({ path: cover, x: 0, y: 0, w: W, h: H, objectName: name("Cover art"),
      altText: "Maya, a vulnerability analyst, working at her desk at night with an assistant robot" });
    s.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 7.2, h: H, fill: { color: INK, transparency: 25 },
      line: { color: INK, width: 0, transparency: 100 }, objectName: name("Title scrim") });
    T(s, "IEEE ISAIA 2026  ·  PAPER 166", { x: M, y: 0.7, w: 6, h: 0.35, fontSize: 13, bold: true, color: TEAL, charSpacing: 3 });
    s.addText("VulnTriage", { placeholder: "title" });
    s.addText("AI-driven CVE exploitability prediction with Reciprocal Rank Fusion and circularity-aware evaluation", { placeholder: "subtitle" });
    s.addText([
      { text: "Huraib Jan Sarhandi  ·  Weitian Wang", options: { color: PAPER, breakLine: true } },
      { text: "School of Computing, Montclair State University, USA" },
    ], { placeholder: "authors" });
    s.addNotes(
      "Good morning. I am Huraib Jan Sarhandi from Montclair State University, presenting joint work with Professor Weitian Wang. " +
      "I am going to tell this as a story. This is Maya. She is a vulnerability analyst, and she stands for the person our system is built for. " +
      "The talk has two threads: a system that ranks vulnerabilities, explains them and recommends an action; and an audit of our own evaluation that changed what we are able to claim.");
  }

  // ════════════════ 2. The problem ════════════════
  {
    const s = strip("Opening", "SCENE 1  ·  THE PROBLEM", "Monday morning: forty thousand new vulnerabilities");
    const ids = ["02a_arrive", "02b_all_red", "02c_few_real"];
    const alts = ["Maya arrives at the office; a wall display reads 40,000+",
      "Maya at her desk; every row on her screen is tagged critical",
      "A desk covered in grey cards with only three red ones"];
    const caps = [
      ["40,000+", "CVEs were published by NVD in 2024, up 38% on the year before."],
      ["Everything is critical.", "Sorted by CVSS, nothing stands out. Severity is not likelihood."],
      ["Fewer than 3%", "are exploited in the wild within a year. The question is which ones."],
    ];
    ids.forEach((id, i) => {
      const x = M + i * (three.w + GAP);
      picFrame(s, id, x, TOP, three.w, three.h, alts[i]);
      caption(s, x, capY3, three.w, caps[i][0], caps[i][1], 1.1);
    });
    s.addNotes(
      "NVD published over forty thousand CVEs in 2024. Maya's team can patch a fraction of them. " +
      "The usual way to prioritise is CVSS, which measures how bad a vulnerability could be, not how likely it is to be used. Sorted that way, everything on her screen is critical. " +
      "Yet fewer than three percent are exploited within a year. Her real question is: which three percent.");
  }

  // ════════════════ 3. A score is not a decision ════════════════
  {
    const s = strip("Opening", "SCENE 2  ·  THE GAP", "A score is not yet a decision");
    picFrame(s, "03a_score", M, TOP, two.w, two.h, "Maya looks sceptically at a screen showing an EPSS score of 0.94 with question-mark notes");
    caption(s, M, capY2, two.w, "EPSS predicts exploitation better than CVSS.",
      "But is this system affected? What would an attacker do with it? What should she do, and by when?");
    picFrame(s, "03b_board", X2, TOP, two.w, two.h, "Maya pins four notes labelled RQ1 to RQ4 on a board");
    T(s, [
      { text: "RQ1 ", options: { bold: true, color: TEAL } }, { text: "How does rank fusion compare with EPSS?   ", options: { color: INK2 } },
      { text: "RQ2 ", options: { bold: true, color: RED } }, { text: "Do leaky features inflate the metrics?", options: { color: INK2, breakLine: true } },
      { text: "RQ3 ", options: { bold: true, color: AMBER } }, { text: "Can ATT&CK briefs be grounded and verified?   ", options: { color: INK2 } },
      { text: "RQ4 ", options: { bold: true, color: BLUE } }, { text: "How does asset context change the action?", options: { color: INK2 } },
    ], { x: X2, y: capY2, w: two.w, h: 1.15, fontSize: 15 });
    s.addNotes(
      "EPSS improved on CVSS by predicting likelihood, and it is our strongest baseline. But a probability does not tell Maya whether her system is affected, what the attacker would do, or what to do by when. " +
      "So the study asks four questions. RQ1: how does a rank fusion of three sources compare with EPSS. RQ2: do features that encode the label, or that are observed after the decision time, inflate the metrics. " +
      "RQ3: can we generate ATT&CK-mapped briefs whose identifiers and references are verifiable. RQ4: how does asset context, a software inventory and vendor VEX statements, change the recommended action.");
  }

  // ════════════════ 4. Pipeline ════════════════
  pres.addSection({ title: "Method" });
  {
    const s = strip("Method", "SCENE 3  ·  THE SYSTEM", "She builds one pipeline, from public feeds to an action");
    picFrame(s, "04_pipeline", M, TOP, two.w, two.h, "Maya at a whiteboard showing five stages: sources, evidence, rank, explain, decide");
    caption(s, M, capY2, two.w, "Five stages, one Docker stack.",
      "React and FastAPI over PostgreSQL and Qdrant. The fused value orders CVEs; it is not a calibrated probability.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const rows = [
      ["Sources", "NVD, EPSS, CISA KEV, ExploitDB"],
      ["Evidence", "33 clean features and a four-layer leakage audit"],
      ["Rank", "XGBoost tabular, XGBoost with text embeddings, and EPSS, fused by RRF (k = 60)"],
      ["Explain", "ATT&CK retrieval with identifier and reference checks"],
      ["Decide", "SBOM and VEX context, five action tiers with SLAs"],
    ];
    const rh = (two.h - 0.5) / rows.length;
    rows.forEach(([head, body], i) => {
      const y = TOP + 0.25 + i * rh;
      T(s, String(i + 1), { x: X2 + 0.3, y, w: 0.4, h: rh - 0.08, fontSize: 22, bold: true, color: TEAL, valign: "middle" });
      T(s, head, { x: X2 + 0.75, y, w: 1.3, h: rh - 0.08, fontSize: 16, bold: true, valign: "middle" });
      T(s, body, { x: X2 + 2.05, y, w: two.w - 2.35, h: rh - 0.08, fontSize: 14, color: INK2, valign: "middle" });
    });
    caption(s, X2, capY2, two.w, "EPSS is a rank source and the baseline.",
      "The study does not claim to replace it.");
    s.addNotes(
      "Maya's pipeline has five stages. Data comes from four public sources. We build thirty-three features and run a four-layer leakage audit over them. " +
      "Three rank sources are fused with Reciprocal Rank Fusion: an XGBoost model on tabular features, a second XGBoost model that adds sentence embeddings of the description, and the EPSS score itself. " +
      "EPSS is one of our rank sources as well as our baseline; we do not claim to replace it. " +
      "The explain stage retrieves MITRE ATT&CK techniques and validates every identifier and reference. The decide stage combines that with asset evidence and assigns one of five action tiers with a deadline. " +
      "The fused value is a rank. We do not present it as a probability.");
  }

  // ════════════════ 5. Test set ════════════════
  {
    const s = strip("Method", "SCENE 4  ·  THE TEST", "Needles in a haystack, scored under two evidence settings");
    picFrame(s, "05_testset", M, TOP, two.w, two.h, "Maya examines a heap of grey cards with a few red ones; a calendar reads June 2024");
    caption(s, M, capY2, two.w, "A chronological split at June 2024.",
      "277 known-exploited CVEs among 70,831 in the test set: 0.39%, so PR-AUC is the primary metric.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const sx = X2 + 0.35, sw = (two.w - 0.7 - 0.3) / 2;
    const stat = (x, y, big, label, col) => {
      T(s, big, { x, y, w: sw, h: 0.6, fontSize: 32, bold: true, color: col, valign: "middle" });
      T(s, label, { x, y: y + 0.62, w: sw, h: 0.5, fontSize: 13, color: INK2 });
    };
    stat(sx, TOP + 0.25, "180,497", "NVD CVEs, 2020 to 2025", INK);
    stat(sx + sw + 0.3, TOP + 0.25, "70,831", "test CVEs", INK);
    T(s, [
      { text: "Frozen snapshot  ", options: { bold: true, color: BLUE } },
      { text: "every feature as observed in March 2026, the common practice.", options: { color: INK2, breakLine: true, paraSpaceAfter: 8 } },
      { text: "Historical EPSS  ", options: { bold: true, color: TEAL } },
      { text: "the first monthly score on or after each CVE's publication.", options: { color: INK2 } },
    ], { x: sx, y: TOP + 1.65, w: two.w - 0.7, h: two.h - 1.85, fontSize: 15 });
    caption(s, X2, capY2, two.w, "The same test set, scored twice.",
      "Paired bootstrap (10,000 resamples) and permutation tests, Holm-Bonferroni corrected.");
    s.addNotes(
      "The dataset is one hundred and eighty thousand CVEs. We split chronologically at June 2024, giving about seventy-one thousand test CVEs. Only two hundred and seventy-seven are in CISA's Known Exploited Vulnerabilities catalogue. " +
      "That is 0.39 percent, so accuracy and even ROC are misleading and we use PR-AUC. " +
      "The key design decision: we score the same test set twice. In the frozen snapshot, every feature is as it looked in March 2026; that is how most studies evaluate. " +
      "In the second setting we replace EPSS with the score that existed when each CVE was published, from FIRST's archive. It is a sensitivity analysis, not a full replay.");
  }

  // ════════════════ 6. RQ1 frozen ════════════════
  pres.addSection({ title: "Results" });
  {
    const s = strip("Results", "SCENE 5  ·  RQ1, FROZEN SNAPSHOT", "First result: a clear win");
    picFrame(s, "06a_win", M, TOP, two.w, two.h, "Maya celebrates at her desk; her chart shows one bar ahead of the rest");
    caption(s, M, capY2, two.w, "Rank fusion leads every baseline.",
      "71 of the top 100 ranked CVEs are confirmed exploited, against 44 for EPSS.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["CVSS", "XGBoost tabular", "EPSS", "XGBoost + embeddings", "RRF (k = 60)"],
      values: [0.011, 0.251, 0.271, 0.309, 0.367] }], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "bar", ...axis,
      chartColors: [HEX.accent6, HEX.accent6, HEX.accent4, HEX.accent6, HEX.accent1], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000",
      showLegend: false, title: "PR-AUC, frozen March 2026 snapshot", barGapWidthPct: 55, catAxisOrientation: "maxMin",
      objectName: name("Chart frozen PR-AUC"),
    });
    caption(s, X2, capY2, two.w, "0.367 against 0.271: +35.4%.",
      "Paired-bootstrap 95% CI of the difference +0.054 to +0.142. Its edge over CombSUM is not distinguishable.");
    s.addNotes(
      "First the conventional result. In the frozen snapshot, RRF reaches a PR-AUC of 0.367 against 0.271 for EPSS, a thirty-five percent gain that is statistically significant. " +
      "Seventy-one of the top one hundred ranked CVEs are confirmed exploited, against forty-four for EPSS. " +
      "We compared five other fusion methods on the identical three inputs and RRF came first, although its lead over simple score averaging is within noise. " +
      "If Maya stopped here, this would be the headline. She does not stop here.");
  }

  // ════════════════ 7. RQ1 historical ════════════════
  {
    const s = strip("Results", "SCENE 6  ·  RQ1, HISTORICAL EPSS", "Then she checks the date on the evidence");
    picFrame(s, "07a_date", M, TOP, two.w, two.h, "Maya points at her screen: published 2024, score observed 2026");
    caption(s, M, capY2, two.w, "The score came from the future.",
      "EPSS is updated daily and rises once exploitation is seen. A 2026 score already knows what happened.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [
      { name: "EPSS", labels: ["Frozen snapshot", "Historical EPSS"], values: [0.2711, 0.2581] },
      { name: "RRF", labels: ["Frozen snapshot", "Historical EPSS"], values: [0.3671, 0.2678] },
    ], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", barGrouping: "clustered", ...axis,
      chartColors: [HEX.accent4, HEX.accent1], valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1,
      dataLabelFormatCode: "0.000", showLegend: true, legendPos: "b", title: "PR-AUC on the same 70,831 test CVEs",
      barGapWidthPct: 70, objectName: name("Chart frozen vs historical"),
    });
    caption(s, X2, capY2, two.w, "+3.8%, and not statistically reliable.",
      "0.2678 against 0.2581; 95% CI −0.031 to +0.052. A null result, reported as one.");
    s.addNotes(
      "This is the central finding. EPSS scores are updated daily, and they rise after exploitation is observed. A 2026 EPSS score for a 2024 vulnerability already knows what happened. " +
      "When we replace it with the first monthly score available on or after publication, RRF scores 0.268 and EPSS 0.258. " +
      "The difference is plus 3.8 percent, the confidence interval spans zero, and the permutation test is not significant. So the thirty-five percent gap was largely hindsight. " +
      "We report this as a null result. We do not claim RRF beats EPSS at deployment time. The same check applies to any study that evaluates on current enrichment data.");
  }

  // ════════════════ 8. RQ2 ════════════════
  {
    const s = strip("Results", "SCENE 7  ·  RQ2, LEAKAGE AUDIT", "So she audits everything");
    picFrame(s, "08a_audit", M, TOP, three.w, three.h, "Close-up: a magnifying glass over the list of model inputs shows Public PoC flag and Metasploit flag in red");
    caption(s, M, capY3, three.w, "Two inputs leak the answer.", "The audit checks temporal, label, entity-proxy and correlation leakage.", 1.1);
    const x2 = M + three.w + GAP, x3 = M + 2 * (three.w + GAP);
    blankFrame(s, x2, TOP, three.w, three.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["Exploit-derived proxies", "Clean tabular"], values: [1.0, 0.268] }], {
      x: x2 + 0.1, y: TOP + 0.1, w: three.w - 0.2, h: three.h - 0.2, barDir: "col", ...axis,
      chartColors: [HEX.accent2, HEX.accent1], invertedColors: [HEX.accent2],
      valAxisMinVal: 0, valAxisMaxVal: 1.2, valAxisMajorUnit: 0.4, dataLabelFormatCode: "0.000", showLegend: false,
      title: "Circularity stress test", barGapWidthPct: 90, objectName: name("Chart circularity"),
    });
    caption(s, x2, capY3, three.w, "3.73× inflation", "when inputs come from the same exploit evidence as the label.", 1.1);
    blankFrame(s, x3, TOP, three.w, three.h);
    s.addChart(pres.charts.LINE, [{ name: "PR-AUC", labels: ["2021-22", "2022-23", "2023-24", "2024-25"], values: [0.881, 0.705, 0.680, 0.279] }], {
      x: x3 + 0.1, y: TOP + 0.1, w: three.w - 0.2, h: three.h - 0.2, ...axis, chartColors: [HEX.accent3],
      lineSize: 3, lineDataSymbolSize: 9, dataLabelPosition: "t",
      valAxisMinVal: 0, valAxisMaxVal: 1.2, valAxisMajorUnit: 0.4, dataLabelFormatCode: "0.000", showLegend: false,
      title: "Frozen enrichment, by test year", objectName: name("Chart rolling window"),
    });
    caption(s, x3, capY3, three.w, "0.88 falls to 0.28", "as hindsight shrinks. Older years only look better.", 1.1);
    s.addNotes(
      "RQ2 generalises that observation. Maya audits four leakage types: temporal, label, entity-proxy and correlation. " +
      "In the middle, a deliberate stress test. If the features include signals derived from exploit evidence, such as proof-of-concept and Metasploit indicators, the model reaches a PR-AUC of one. The clean configuration reaches 0.268. That is a 3.73 times inflation. " +
      "On the right, the same model retrained at four yearly boundaries with frozen enrichment. PR-AUC falls from 0.88 for the oldest test year to 0.28 for the most recent. Nothing about the model changed; older vulnerabilities simply had more time for their enrichment to catch up with reality.");
  }

  // ════════════════ 9. RQ3 grounding ════════════════
  {
    const s = strip("Results", "SCENE 8  ·  RQ3, GROUNDED BRIEFS", "The assistant may not invent anything");
    picFrame(s, "09a_brief", M, TOP, two.w, two.h, "Maya reads a brief handed over by the assistant robot; each line carries a tick stamp");
    caption(s, M, capY2, two.w, "Every identifier is checked against the registry.",
      "A technique must exist in ATT&CK v18.1; a link is kept only if it is on the CVE's own reference list.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const rows = [
      ["0 of 150", "briefs contained a fabricated ATT&CK identifier", TEAL],
      ["149 of 150", "briefs cite an advisory listed on the CVE record", TEAL],
      ["2 of 271", "proposed mappings were rejected by retrieval grounding", AMBER],
    ];
    const rh = (two.h - 0.4) / 3;
    rows.forEach(([big, label, col], i) => {
      const y = TOP + 0.2 + i * rh;
      T(s, big, { x: X2 + 0.35, y, w: 2.35, h: rh, fontSize: 32, bold: true, color: col, valign: "middle" });
      T(s, label, { x: X2 + 2.8, y, w: two.w - 3.15, h: rh, fontSize: 15, color: INK2, valign: "middle" });
    });
    caption(s, X2, capY2, two.w, "Exact-match checks, not opinions.",
      "They do not establish that a valid technique is the right one.");
    s.addNotes(
      "RQ3 concerns the explanation layer, which uses a language model. Maya's rule is simple: the assistant may not invent anything. " +
      "For each CVE we retrieve the nearest ATT&CK techniques, check that every identifier exists in the pinned ATT&CK version 18.1 corpus, generate a structured brief with GPT-4o-mini, and keep a remediation link only if it appears verbatim in the CVE's own reference list. " +
      "On one hundred and fifty briefs: no fabricated technique identifier, and one hundred and forty-nine cite a CVE-listed advisory. These are exact-match checks. What they do not establish is whether a valid technique is the right technique.");
  }

  // ════════════════ 10. RQ3 verification ════════════════
  {
    const s = strip("Results", "SCENE 9  ·  RQ3, VERIFICATION", "She asks it to check its own work");
    picFrame(s, "10a_ask_twice", M, TOP, two.w, two.h, "Maya, arms crossed, questions the robot, which keeps one card and sets two aside");
    caption(s, M, capY2, two.w, "Does this technique really apply?",
      "A Chain-of-Verification pass keeps only the mappings the model can confirm, and abstains otherwise.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [
      { name: "Standard retrieval", labels: ["Over-rationalized", "Technique relevance", "Abstention"], values: [27.3, 87.8, 1.3] },
      { name: "With verification", labels: ["Over-rationalized", "Technique relevance", "Abstention"], values: [12.0, 95.9, 34.7] },
    ], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", barGrouping: "clustered", ...axis,
      chartColors: [HEX.accent4, HEX.accent1], valAxisMinVal: 0, valAxisMaxVal: 110, valAxisMajorUnit: 25,
      dataLabelFormatCode: '0.0"%"', valAxisLabelFormatCode: '0"%"', showLegend: true, legendPos: "b",
      title: "150 briefs, GPT-4o quality judge", barGapWidthPct: 60, objectName: name("Chart verification"),
    });
    caption(s, X2, capY2, two.w, "Precision is bought with coverage.",
      "An optional mode, not a free improvement. The judges are LLMs (κ = 0.55, 0.44, 0.29), not human raters.");
    s.addNotes(
      "The residual failure mode is over-rationalization. Retrieval sometimes surfaces a technique that is lexically similar but wrong, and the model justifies it instead of declining it. A GPT-4o judge flags this in 27 percent of standard briefs. " +
      "So Maya asks the assistant to check its own work: for each candidate, does it actually describe how this CVE would be exploited. Over-rationalization drops to 12 percent and relevance rises from 88 to 96 percent. " +
      "The cost: the system abstains on about 35 percent of briefs. This is a precision and coverage trade-off, offered as a mode, not a default. " +
      "The evidence type matters: these judgements come from two language models with moderate to fair agreement. They are not human ratings.");
  }

  // ════════════════ 11. RQ4 ════════════════
  {
    const s = strip("Results", "SCENE 10  ·  RQ4, ASSET CONTEXT", "Not every machine matters equally");
    picFrame(s, "11a_servers", M, TOP, two.w, two.h, "Maya walks past four server racks; one is lit red");
    caption(s, M, capY2, two.w, "Five action tiers, each with a deadline:",
      "Patch now (24 h), Mitigate now (24 h), Patch window (30 days), Monitor (90 days), Accept (1 year).");
    blankFrame(s, X2, TOP, two.w, two.h);
    const half = (two.w - 0.7 - 0.3) / 2, bx = X2 + 0.35;
    T(s, "Synthetic fleet: 51 assets, 5,435 asset-CVE pairs", { x: bx, y: TOP + 0.22, w: two.w - 0.7, h: 0.35, fontSize: 13, color: INK2 });
    T(s, "AS PUBLISHED", { x: bx, y: TOP + 0.75, w: half, h: 0.3, fontSize: 12, bold: true, color: INK2, charSpacing: 2 });
    T(s, "23.4%", { x: bx, y: TOP + 1.05, w: half, h: 0.75, fontSize: 40, bold: true, color: INK2, valign: "middle" });
    T(s, "of decisions changed. Urgent queue 1,286 to 177 (−86%).", { x: bx, y: TOP + 1.9, w: half, h: 1.0, fontSize: 14, color: INK2 });
    T(s, "CORRECTED AFTER AUDIT", { x: bx + half + 0.3, y: TOP + 0.75, w: half, h: 0.3, fontSize: 12, bold: true, color: TEAL, charSpacing: 2 });
    T(s, "19.1%", { x: bx + half + 0.3, y: TOP + 1.05, w: half, h: 0.75, fontSize: 40, bold: true, color: TEAL, valign: "middle" });
    T(s, "of decisions changed. Urgent queue 1,286 to 533 (−58.6%).", { x: bx + half + 0.3, y: TOP + 1.9, w: half, h: 1.0, fontSize: 14, color: INK2 });
    caption(s, X2, capY2, two.w, "She found a bug in her own engine.",
      "A VEX statement for one asset had been applied to others. Both figures are rule sensitivity on synthetic evidence, not enterprise savings.");
    s.addNotes(
      "RQ4 asks what happens when the decision engine knows about the asset. The same vulnerability does not matter equally on every machine. The engine assigns one of five tiers, from patch now within twenty-four hours down to accept with annual review, and records why. " +
      "The informative test is an ablation on a seeded synthetic fleet of fifty-one assets. The paper reports that asset evidence changed 23.4 percent of decisions and cut the urgent queue by 86 percent. " +
      "After publication we kept auditing and found a defect: a VEX not-affected statement recorded for one asset was being applied to other assets holding the same CVE. " +
      "With statements scoped correctly, the same seeded experiment gives 19.1 percent and a 58.6 percent reduction. I am presenting the corrected figure. " +
      "Either way this is a sensitivity result on synthetic evidence, not a measured workload saving in an enterprise.");
  }

  // ════════════════ 12. Real inventories ════════════════
  pres.addSection({ title: "Discussion" });
  {
    const s = strip("Discussion", "SCENE 11  ·  SINCE THE PAPER", "A long inventory goes in, a short justified list comes out");
    picFrame(s, "12a_sbom", M, TOP, two.w, two.h, "Maya holds a very long printed inventory; her screen shows a short list");
    caption(s, M, capY2, two.w, "A real software bill of materials.",
      "Installed versions are compared with NVD's vulnerable ranges, so a patched component is not reported.");
    const shot = path.join(ASSETS, "assets_page.png");
    blankFrame(s, X2, TOP, two.w, two.h);
    if (fs.existsSync(shot)) {
      const ih = two.h - 0.2, iw = Math.min(two.w - 0.2, ih * (1215 / 729));
      s.addImage({ path: shot, x: X2 + (two.w - iw) / 2, y: TOP + (two.h - iw * (729 / 1215)) / 2, w: iw, h: iw * (729 / 1215),
        objectName: name("Screenshot assets page"),
        altText: "VulnTriage Assets page showing a prioritised finding queue for an Apache httpd 2.4.49 container" });
    }
    caption(s, X2, capY2, two.w, "73 matching CVEs, 4 urgent.",
      "On httpd 2.4.49, CVE-2021-41773 and CVE-2021-42013 are Patch now, with the installed version as evidence.");
    s.addNotes(
      "The paper listed validating the SBOM and VEX pipeline on real inventories as future work, so here is where that stands. " +
      "This is a real software bill of materials, generated with Syft from the public Apache httpd 2.4.49 image and registered as an internet-facing, high-criticality asset. " +
      "The system compares each installed version with the vulnerable version ranges NVD publishes. Seventy-three CVEs match the installed products; four are urgent. " +
      "The two at the top are the 2021 path-traversal vulnerabilities, both in the KEV catalogue, and the evidence line shows the installed version inside the vulnerable range. " +
      "This is a demonstration on three public images, not an evaluation.");
  }

  // ════════════════ 13. Limitations ════════════════
  {
    const s = strip("Discussion", "SCENE 12  ·  LIMITATIONS", "What she cannot claim");
    picFrame(s, "13a_limits", M, TOP, two.w, two.h, "Maya shrugs honestly beside a whiteboard with four unticked boxes");
    caption(s, M, capY2, two.w, "The boundaries are part of the result.",
      "A low-cost system is useful only when its evidence time, labels and validation type are stated.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const lim = [
      ["Not a prospective replay", "Features and KEV labels are a March 2026 snapshot; only EPSS is replaced historically."],
      ["KEV is incomplete", "Negatives may later be exploited, so recall is a lower bound."],
      ["Synthetic asset evidence", "The fleet, VEX statements, controls and reachability are simulated."],
      ["No human ratings", "Relevance is LLM-judged. Against MITRE CTID analyst mappings, retrieval alone hits in the top 3 for 27% of CVEs."],
    ];
    const rh = (two.h - 0.4) / lim.length;
    lim.forEach(([head, body], i) => {
      const y = TOP + 0.2 + i * rh;
      s.addShape(pres.shapes.RECTANGLE, { x: X2 + 0.35, y: y + 0.12, w: 0.24, h: 0.24, fill: { color: WHITE },
        line: { color: INK, width: 1.5 }, objectName: name("Checkbox") });
      T(s, [{ text: head + "  ", options: { bold: true, color: INK } }, { text: body, options: { color: INK2 } }],
        { x: X2 + 0.8, y: y + 0.05, w: two.w - 1.15, h: rh - 0.1, fontSize: 14 });
    });
    caption(s, X2, capY2, two.w, "Four open boxes.", "Each one is a study we have not yet run.");
    s.addNotes(
      "Maya is plain about what she cannot claim. " +
      "First, this is a chronological split over a single 2026 snapshot. We replaced EPSS historically, but not every NVD field or the KEV labels. " +
      "Second, KEV is curated and incomplete; strictly, we predict KEV inclusion. Third, the asset experiment uses a synthetic fleet. " +
      "Fourth, the semantic quality of the briefs is judged by language models. Since the paper we ran one check against human ground truth: MITRE's Center for Threat-Informed Defense publishes analyst mappings from KEV vulnerabilities to ATT&CK. " +
      "On 345 of those, our retriever alone places an analyst-chosen technique in its top three for only 27 percent. The comparison is not like for like, because the analysts also map impact, which a description often does not reveal, but it confirms that model-judged relevance must not be read as human-validated accuracy.");
  }

  // ════════════════ 14. Conclusions ════════════════
  {
    const s = strip("Discussion", "SCENE 13  ·  CONCLUSIONS", "A shorter list, and an honest account of it");
    picFrame(s, "14a_sunrise", M, TOP, two.w, two.h, "Sunrise; Maya with a coffee looks at a short tidy list on her screen");
    caption(s, M, capY2, two.w, "Next:",
      "a full historical replay of NVD and KEV, real enterprise inventories, two blinded human annotators, and a preregistered cost-quality study.");
    blankFrame(s, X2, TOP, two.w, two.h);
    const take = [
      ["RRF reaches PR-AUC 0.367 in the frozen snapshot; with historical EPSS the +3.8% advantage is not reliable.", TEAL],
      ["Exploit-derived proxies inflate PR-AUC 3.73×, and frozen enrichment flatters older test years.", RED],
      ["Grounding holds fabricated ATT&CK IDs at zero; verification trades 34.7% abstention for precision.", AMBER],
      ["Asset evidence changes about one in five action tiers on a synthetic fleet, with a traceable rationale.", BLUE],
    ];
    const rh = (two.h - 0.4) / take.length;
    take.forEach(([t, col], i) => {
      const y = TOP + 0.2 + i * rh;
      T(s, String(i + 1), { x: X2 + 0.3, y, w: 0.45, h: rh - 0.08, fontSize: 24, bold: true, color: col, valign: "middle" });
      T(s, t, { x: X2 + 0.85, y, w: two.w - 1.2, h: rh - 0.08, fontSize: 14, valign: "middle" });
    });
    caption(s, X2, capY2, two.w, "An integration, not a replacement for EPSS.",
      "Its value is the audited workflow around the score.");
    s.addNotes(
      "To conclude. One: rank fusion gives a clear gain in the conventional frozen evaluation, and that gain is not statistically reliable once EPSS is taken at publication time. " +
      "Two: we quantified two sources of inflation, feature-label circularity and retroactive enrichment, and both are large. " +
      "Three: deterministic grounding prevents invalid identifiers and unsupported links, and optional verification improves precision at a real coverage cost. " +
      "Four: asset evidence changes roughly one in five recommended actions in a synthetic setting, with every change traceable to evidence. " +
      "Maya ends with a shorter list and an honest account of how she got it. Future work is a full historical replay, real enterprise inventories, human annotation, and a preregistered cost-quality study.");
  }

  // ════════════════ 15. Thank you ════════════════
  {
    const s = strip("Discussion", "THE END", "Thank you. Questions and discussion");
    picFrame(s, "15a_thanks", M, TOP, two.w, two.h, "Maya and the assistant robot wave goodbye");
    caption(s, M, capY2, two.w, "Maya is fictional.", "The numbers are not: each comes from the paper or a released artifact.");
    blankFrame(s, X2, TOP, two.w, two.h);
    T(s, [
      { text: "Huraib Jan Sarhandi", options: { bold: true, color: INK, fontSize: 20, breakLine: true } },
      { text: "sarhandih1@montclair.edu", options: { color: INK2, breakLine: true, paraSpaceAfter: 14 } },
      { text: "Weitian Wang", options: { bold: true, color: INK, fontSize: 20, breakLine: true } },
      { text: "wangw@montclair.edu", options: { color: INK2, breakLine: true, paraSpaceAfter: 14 } },
      { text: "School of Computing, Montclair State University, USA", options: { color: INK2, breakLine: true, paraSpaceAfter: 14 } },
      { text: "Code and artifacts", options: { bold: true, color: INK, breakLine: true } },
      { text: "github.com/huraibjan/vulntriage", options: { color: TEAL } },
    ], { x: X2 + 0.45, y: TOP + 0.35, w: two.w - 0.9, h: two.h - 0.7, fontSize: 16, valign: "middle" });
    caption(s, X2, capY2, two.w, "Paper 166, IEEE ISAIA 2026.", "Illustrations were generated for this talk.");
    s.addNotes(
      "Thank you. I am happy to take questions. Likely ones, with short answers: " +
      "Why not just use EPSS? Under historical evidence we do not show a reliable ranking gain over it; the system's value is the workflow around the score. " +
      "Is the evaluation inflated? In the frozen setting yes, and we measured by how much. " +
      "Is an LLM judging an LLM circular? The load-bearing claims are exact-match checks; the judged figures are labelled exploratory. " +
      "Concurrent work, for example Alpay and Alpay 2026, also reports large inflation under retrospective evidence, consistent with our finding.");
  }

  // ════════════════ Backup ════════════════
  pres.addSection({ title: "Backup" });
  const full = { x: M, w: W - 2 * M, h: 4.0 };
  const backupChartCaption = (s, lead, body) => caption(s, M, TOP + full.h + 0.16, full.w, lead, body, 1.0);
  {
    const s = strip("Backup", "BACKUP  ·  FUSION METHODS", "Six fusion methods over the same three rank sources");
    blankFrame(s, full.x, TOP, full.w, full.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["RRF (k = 60)", "CombSUM", "CombMNZ", "Optimised blend", "Borda count", "LR stacking"],
      values: [0.3671, 0.3536, 0.3536, 0.3536, 0.3065, 0.2589] }], {
      x: full.x + 0.2, y: TOP + 0.12, w: full.w - 0.4, h: full.h - 0.24, barDir: "bar", ...axis,
      chartColors: [HEX.accent1, HEX.accent6, HEX.accent6, HEX.accent6, HEX.accent6, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000", showLegend: false,
      title: "PR-AUC, frozen snapshot", barGapWidthPct: 55, catAxisOrientation: "maxMin", objectName: name("Chart fusion baselines"),
    });
    backupChartCaption(s, "RRF versus CombSUM: Δ +0.014, 95% CI −0.001 to +0.029.",
      "A k sweep from 5 to 300 moves PR-AUC by 0.034; the literature default k = 60 is kept. Stacking is weakest: few validation positives and mismatched score scales.");
    s.addNotes("Backup for questions on the fusion choice and on k. All methods use the identical three rank sources.");
  }
  {
    const s = strip("Backup", "BACKUP  ·  FEATURE NECESSITY", "EPSS is the least replaceable input in the clean tabular model");
    blankFrame(s, full.x, TOP, full.w, full.h);
    s.addChart(pres.charts.BAR, [{ name: "Relative PR-AUC drop", labels: ["EPSS", "Reference and product counts", "Days since publication", "CVSS vector"],
      values: [87, 29, 17, 13] }], {
      x: full.x + 0.2, y: TOP + 0.12, w: full.w - 0.4, h: full.h - 0.24, barDir: "bar", ...axis,
      chartColors: [HEX.accent2, HEX.accent6, HEX.accent6, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 100, valAxisMajorUnit: 25, dataLabelFormatCode: '0"%"', valAxisLabelFormatCode: '0"%"',
      showLegend: false, title: "Relative PR-AUC drop when the group is removed and the model retrained",
      barGapWidthPct: 55, catAxisOrientation: "maxMin", objectName: name("Chart feature ablation"),
    });
    backupChartCaption(s, "Removing EPSS collapses PR-AUC from 0.268 to 0.034.",
      "TreeSHAP ranks reference count first (33%), then EPSS (27%): attribution measures average contribution, ablation measures unique signal.");
    s.addNotes("Backup for questions on interpretability and on how much of the model is EPSS.");
  }
  {
    const s = strip("Backup", "BACKUP  ·  CHECKS AFTER PUBLICATION", "Two further checks: human ground truth and NIST LEV");
    blankFrame(s, M, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [{ name: "Top-3 hit rate", labels: ["VulnTriage retriever", "Three most common techniques"], values: [0.267, 0.754] }], {
      x: M + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", ...axis,
      chartColors: [HEX.accent1, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 1, valAxisMajorUnit: 0.25, dataLabelFormatCode: "0.000", showLegend: false,
      title: "Agreement with MITRE CTID analyst mappings (345 KEV CVEs)", barGapWidthPct: 90, objectName: name("Chart CTID"),
    });
    caption(s, M, capY2, two.w, "Retrieval alone agrees poorly with analysts.",
      "Exploitation-technique mappings only: 0.222. CTID also maps impact, and the constant guess is fitted on the same CVEs.");
    blankFrame(s, X2, TOP, two.w, two.h);
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["NIST LEV", "EPSS", "RRF"], values: [0.252, 0.271, 0.367] }], {
      x: X2 + 0.15, y: TOP + 0.12, w: two.w - 0.3, h: two.h - 0.24, barDir: "col", ...axis,
      chartColors: [HEX.accent3, HEX.accent4, HEX.accent1], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000", showLegend: false,
      title: "PR-AUC, frozen setting, 70,831 test CVEs", barGapWidthPct: 90, objectName: name("Chart LEV"),
    });
    caption(s, X2, capY2, two.w, "LEV does not beat EPSS as a ranker here.",
      "Difference −0.019, 95% CI −0.041 to +0.005. RRF minus LEV +0.115, CI +0.063 to +0.164.");
    s.addNotes(
      "Backup. Two checks run after the paper was accepted. Left: agreement between our ATT&CK retriever and MITRE CTID's analyst mappings for KEV vulnerabilities, with no language model involved: a top-three hit rate of 0.267, against 0.754 for always guessing the three most common techniques. An unfavourable result, reported as such. " +
      "Right: NIST's Likely Exploited Vulnerabilities metric as an additional baseline in the frozen setting. LEV does not improve on EPSS as a ranker of KEV membership on this test set, and RRF remains ahead of it. " +
      "Sources: results/ctid_attack_eval.json and results/lev_baseline.json.");
  }

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
