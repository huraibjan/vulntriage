// Builds the IEEE ISAIA 2026 conference deck for VulnTriage.
//
//   NODE_PATH=<dir with node_modules> node build_deck.js
//
// Every number on the slides is taken from the accepted paper (paper_166.pdf) or
// from an artifact under results/. Optional post-paper results are read from
// beyond_paper.json next to this file, so the deck never states a number that
// was not produced by a script.

const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");

const SKILL = process.env.PPTX_SKILL_DIR;
const { applyTheme } = require(path.join(SKILL, "scripts", "apply_theme.js"));

const HERE = __dirname;
const OUT = path.join(HERE, "VulnTriage_ISAIA2026.pptx");
const ASSETS = path.join(HERE, "..", "assets");
const BEYOND = fs.existsSync(path.join(HERE, "beyond_paper.json"))
  ? JSON.parse(fs.readFileSync(path.join(HERE, "beyond_paper.json"), "utf8"))
  : {};

const THEME = {
  name: "VulnTriage Dark",
  headFontFace: "Arial",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "0B1220", // page background
    lt1: "EAF0F9", // primary text
    dk2: "141E33", // card surface
    lt2: "9AA8BF", // muted text
    accent1: "22D3B7", // teal: validated / safe signal
    accent2: "FF5D73", // coral: threat / inflation
    accent3: "F7B955", // amber: caution
    accent4: "5B8DEF", // blue: baseline series
    accent5: "22304D", // raised surface
    accent6: "6F7F9B",
    hlink: "22D3B7",
    folHlink: "9AA8BF",
  },
};
const HEX = THEME.colors;

const W = 13.333, H = 7.5, M = 0.7;
const CONTENT_Y = 2.05;          // top of the content area on content slides
const CONTENT_B = 6.75;          // bottom of the content area

async function icon(Comp, hex, size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(
    React.createElement(Comp, { color: "#" + hex, size: String(size) })
  );
  const buf = await sharp(Buffer.from(svg)).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}

(async () => {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_WIDE";
  pres.title = "VulnTriage: CVE Exploitability Prediction with Reciprocal Rank Fusion and Circularity-Aware Evaluation";
  pres.author = "Huraib Jan Sarhandi, Weitian Wang";
  pres.company = "Montclair State University";
  pres.subject = "IEEE ISAIA 2026";
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };

  const C = pres.SchemeColor;
  const BG = C.text1, INK = C.background1, SURF = C.text2, MUTED = C.background2;
  const TEAL = C.accent1, CORAL = C.accent2, AMBER = C.accent3, BLUE = C.accent4, RAISED = C.accent5;

  // ── Layouts ───────────────────────────────────────────────────────────
  const footer = [
    { text: { text: "VulnTriage  ·  IEEE ISAIA 2026", options: {
      x: M, y: 7.02, w: 6, h: 0.3, fontSize: 10, color: MUTED, margin: 0 } } },
  ];
  pres.defineSlideMaster({
    title: "TITLE",
    background: { color: HEX.dk1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: M, y: 2.35, w: 8.6, h: 1.25,
        fontSize: 60, bold: true, color: INK, align: "left", valign: "bottom", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "subtitle", type: "body", x: M, y: 3.75, w: 8.6, h: 1.25,
        fontSize: 20, color: INK, align: "left", valign: "top", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "authors", type: "body", x: M, y: 5.35, w: 8.6, h: 1.1,
        fontSize: 16, color: MUTED, align: "left", valign: "top", margin: 0 }, text: "" } },
    ],
  });
  pres.defineSlideMaster({
    title: "CONTENT",
    background: { color: HEX.dk1 },
    margin: [0.5, M, 0.75, M],
    objects: [
      { placeholder: { options: { name: "kicker", type: "body", x: M, y: 0.5, w: 9, h: 0.32,
        fontSize: 13, bold: true, color: TEAL, charSpacing: 3, align: "left", valign: "middle", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "title", type: "title", x: M, y: 0.85, w: W - 2 * M, h: 1.0,
        fontSize: 32, bold: true, color: INK, align: "left", valign: "top", margin: 0 }, text: "" } },
      ...footer,
    ],
    slideNumber: { x: W - M - 0.6, y: 7.02, w: 0.6, h: 0.3, fontSize: 10, color: MUTED, align: "right" },
  });
  pres.defineSlideMaster({
    title: "CLOSING",
    background: { color: HEX.dk1 },
    objects: [
      { placeholder: { options: { name: "title", type: "title", x: M, y: 1.5, w: 8.2, h: 1.3,
        fontSize: 54, bold: true, color: INK, align: "left", valign: "bottom", margin: 0 }, text: "" } },
      { placeholder: { options: { name: "body", type: "body", x: M, y: 3.0, w: 8.2, h: 1.0,
        fontSize: 20, color: MUTED, align: "left", valign: "top", margin: 0 }, text: "" } },
    ],
  });

  // ── Helpers ───────────────────────────────────────────────────────────
  let n = 0;
  const name = (s) => `${s} ${++n}`;
  const T = (slide, text, o) => slide.addText(text, { isTextBox: true, margin: 0, valign: "top",
    color: INK, fontSize: 14, objectName: name("Text"), ...o });
  const card = (slide, x, y, w, h, o = {}) => slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x, y, w, h, rectRadius: 0.12, fill: { color: SURF }, line: { color: RAISED, width: 1 },
    objectName: name("Card"), ...o });
  const chip = async (slide, Comp, x, y, hex, d = 0.62) => {
    slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: RAISED }, line: { color: RAISED, width: 0 },
      objectName: name("Icon chip") });
    const pad = d * 0.27;
    slide.addImage({ data: await icon(Comp, hex), x: x + pad, y: y + pad, w: d - 2 * pad, h: d - 2 * pad,
      objectName: name("Icon") });
  };
  const content = (section, kicker, title) => {
    const s = pres.addSlide({ masterName: "CONTENT", sectionTitle: section });
    s.addText(kicker, { placeholder: "kicker" });
    s.addText(title, { placeholder: "title" });
    return s;
  };
  const stat = (slide, x, y, w, big, label, color = TEAL, bigSize = 44) => {
    T(slide, big, { x, y, w, h: 0.8, fontSize: bigSize, bold: true, color, valign: "middle" });
    T(slide, label, { x, y: y + 0.85, w, h: 0.9, fontSize: 14, color: MUTED });
  };
  const axis = {
    catAxisLabelColor: MUTED, valAxisLabelColor: MUTED, catAxisLabelFontSize: 12, valAxisLabelFontSize: 11,
    catAxisLabelFontFace: "+mn-lt", valAxisLabelFontFace: "+mn-lt", dataLabelFontFace: "+mn-lt",
    legendFontFace: "+mn-lt", titleFontFace: "+mn-lt",
    valGridLine: { color: HEX.accent5, size: 0.75 }, catGridLine: { style: "none" },
    catAxisLineShow: false, valAxisLineShow: false,
    showValue: true, dataLabelColor: INK, dataLabelFontSize: 12, dataLabelPosition: "outEnd",
    legendColor: MUTED, legendFontSize: 12, plotArea: { fill: { color: HEX.dk2, transparency: 100 } },
  };

  // ════════════════════════════════════════════════════════════════════
  // 1. Title
  // ════════════════════════════════════════════════════════════════════
  pres.addSection({ title: "Opening" });
  {
    const s = pres.addSlide({ masterName: "TITLE", sectionTitle: "Opening" });
    T(s, "IEEE ISAIA 2026  ·  PAPER 166", { x: M, y: 0.7, w: 8, h: 0.35, fontSize: 13, bold: true,
      color: TEAL, charSpacing: 3 });
    s.addText("VulnTriage", { placeholder: "title" });
    s.addText("AI-driven CVE exploitability prediction with Reciprocal Rank Fusion and circularity-aware evaluation",
      { placeholder: "subtitle" });
    s.addText([
      { text: "Huraib Jan Sarhandi  ·  Weitian Wang", options: { color: INK, breakLine: true } },
      { text: "School of Computing, Montclair State University, USA" },
    ], { placeholder: "authors" });
    // Motif: concentric hex-shield mark
    const cx = 11.0, cy = 3.75;
    [[4.2, 92], [3.1, 86], [2.0, 78]].forEach(([d, tr]) => s.addShape(pres.shapes.HEXAGON, {
      x: cx - d / 2, y: cy - d / 2, w: d, h: d, fill: { color: TEAL, transparency: tr },
      line: { color: TEAL, width: 1, transparency: 55 }, objectName: name("Hex mark") }));
    s.addImage({ data: await icon(fa.FaShieldAlt, HEX.accent1, 512), x: cx - 0.55, y: cy - 0.6, w: 1.1, h: 1.2,
      objectName: name("Shield") });
    s.addNotes(
      "Good morning. I am Huraib Jan Sarhandi from Montclair State University, presenting joint work with Professor Weitian Wang. " +
      "VulnTriage is a vulnerability-triage pipeline. The talk has two threads: a system that ranks vulnerabilities, explains them and recommends an action; " +
      "and an audit of our own evaluation that changed what we are able to claim. I will be direct about both.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 2. Problem
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Opening", "THE PROBLEM", "Security teams cannot patch everything, and severity is the wrong signal");
    const cw = 3.75, gap = 0.34, y = CONTENT_Y + 0.25, h = 2.95;
    const items = [
      [fa.FaLayerGroup, HEX.accent2, "40,000+", "CVEs published by NVD in 2024, up 38% on 2023", CORAL],
      [fa.FaCrosshairs, HEX.accent1, "< 3%", "of published CVEs are exploited in the wild within a year", TEAL],
      [fa.FaBalanceScale, HEX.accent3, "CVSS", "measures potential impact, not the likelihood of exploitation", AMBER],
    ];
    for (let i = 0; i < items.length; i++) {
      const [Ico, hex, big, label, col] = items[i];
      const x = M + i * (cw + gap);
      card(s, x, y, cw, h);
      await chip(s, Ico, x + 0.35, y + 0.35, hex);
      T(s, big, { x: x + 0.35, y: y + 1.1, w: cw - 0.7, h: 0.75, fontSize: 44, bold: true, color: col, valign: "middle" });
      T(s, label, { x: x + 0.35, y: y + 1.92, w: cw - 0.7, h: 0.7, fontSize: 15, color: MUTED });
    }
    T(s, [
      { text: "EPSS predicts exploitation better than CVSS, but a score is not a workflow. ", options: { color: INK, bold: true } },
      { text: "An analyst still needs evidence, asset context, and a defensible action.", options: { color: MUTED } },
    ], { x: M, y: 5.7, w: W - 2 * M, h: 0.9, fontSize: 18 });
    s.addNotes(
      "NVD published over forty thousand CVEs in 2024. Fewer than three percent are ever exploited within a year. " +
      "Most organisations still prioritise by CVSS, which measures how bad a vulnerability could be, not how likely it is to be used. " +
      "EPSS improved on that by predicting likelihood, and it is our strongest baseline. But a probability on its own does not tell an analyst " +
      "whether the system is affected, what the attacker would do, or what action to take by when. That gap is what VulnTriage studies.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 3. Research questions
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Opening", "RESEARCH QUESTIONS", "Four questions, each answered with its failure boundary");
    const rq = [
      ["RQ1", fa.FaSortAmountDown, "Ranking", "How does three-source Reciprocal Rank Fusion compare with EPSS?"],
      ["RQ2", fa.FaSearch, "Leakage audit", "Do circular or post-decision features inflate metrics, and by how much?"],
      ["RQ3", fa.FaProjectDiagram, "Grounded briefs", "Do grounding and verification reduce unsupported ATT&CK mappings while keeping coverage?"],
      ["RQ4", fa.FaServer, "Asset context", "How does SBOM and VEX evidence change the recommended action tier?"],
    ];
    const cw = (W - 2 * M - 0.34) / 2, ch = 2.05;
    for (let i = 0; i < 4; i++) {
      const [tag, Ico, head, q] = rq[i];
      const x = M + (i % 2) * (cw + 0.34), y = CONTENT_Y + 0.1 + Math.floor(i / 2) * (ch + 0.3);
      card(s, x, y, cw, ch);
      await chip(s, Ico, x + 0.35, y + 0.38, HEX.accent1, 0.7);
      T(s, [{ text: tag + "  ", options: { color: TEAL, bold: true } }, { text: head, options: { bold: true } }],
        { x: x + 1.3, y: y + 0.38, w: cw - 1.6, h: 0.4, fontSize: 19, valign: "middle" });
      T(s, q, { x: x + 1.3, y: y + 0.9, w: cw - 1.6, h: 0.95, fontSize: 15, color: MUTED });
    }
    s.addNotes(
      "The study is organised around four questions. RQ1: how does a rank fusion of three sources compare with EPSS. " +
      "RQ2: do features that encode the label, or that are observed after the decision time, inflate the metrics. " +
      "RQ3: can we generate ATT&CK-mapped briefs whose identifiers and references are verifiable, and does an extra verification pass help. " +
      "RQ4: when we add asset context, meaning a software bill of materials and vendor VEX statements, how do the recommended actions change. " +
      "For each one I will show the result and where it stops holding.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 4. Architecture
  // ════════════════════════════════════════════════════════════════════
  pres.addSection({ title: "Method" });
  {
    const s = content("Method", "SYSTEM", "One auditable pipeline from public feeds to a recommended action");
    const y0 = CONTENT_Y + 0.15, bh = 3.55;
    const cols = [
      { head: "Sources", ico: fa.FaDatabase, lines: ["NVD API v2", "EPSS (FIRST)", "CISA KEV", "ExploitDB"] },
      { head: "Evidence", ico: fa.FaFilter, lines: ["33 clean features", "Four-layer leakage audit", "SBERT text embeddings"] },
      { head: "Rank", ico: fa.FaSortAmountDown, lines: ["XGBoost tabular", "XGBoost + embeddings", "EPSS score", "Fused by RRF, k = 60"] },
      { head: "Explain", ico: fa.FaProjectDiagram, lines: ["ATT&CK retrieval (Qdrant)", "STIX ID validation", "Reference grounding", "Optional verification"] },
      { head: "Decide", ico: fa.FaClipboardCheck, lines: ["SBOM and VEX context", "SSVC-inspired tree", "Five tiers with SLAs", "Recorded rationale"] },
    ];
    const gap = 0.3, cw = (W - 2 * M - gap * 4) / 5;
    for (let i = 0; i < cols.length; i++) {
      const c = cols[i], x = M + i * (cw + gap);
      card(s, x, y0, cw, bh);
      await chip(s, c.ico, x + 0.28, y0 + 0.3, HEX.accent1, 0.6);
      T(s, c.head, { x: x + 0.28, y: y0 + 1.05, w: cw - 0.5, h: 0.4, fontSize: 19, bold: true });
      T(s, c.lines.map((t, j) => ({ text: t, options: { breakLine: j < c.lines.length - 1, paraSpaceAfter: 6 } })),
        { x: x + 0.28, y: y0 + 1.55, w: cw - 0.45, h: 1.85, fontSize: 14, color: MUTED });
      if (i < cols.length - 1) {
        s.addImage({ data: await icon(fa.FaChevronRight, HEX.accent1), x: x + cw + 0.06, y: y0 + bh / 2 - 0.09,
          w: 0.18, h: 0.18, objectName: name("Arrow") });
      }
    }
    T(s, "React interface and FastAPI service over PostgreSQL and Qdrant, in one Docker Compose stack. The fused value orders CVEs; it is not a calibrated probability.",
      { x: M, y: 5.95, w: W - 2 * M, h: 0.7, fontSize: 15, color: MUTED });
    s.addNotes(
      "The pipeline has five stages. Data comes from four public sources into PostgreSQL. We build thirty-three features and run a four-layer leakage audit over them. " +
      "Three rank sources are fused with Reciprocal Rank Fusion: an XGBoost model on tabular features, a second XGBoost model that adds sentence embeddings of the description, and the EPSS score itself. " +
      "Note that EPSS is one of our rank sources as well as our baseline; we do not claim to replace it. " +
      "The explain stage retrieves MITRE ATT&CK techniques and validates every identifier and reference deterministically. " +
      "The decide stage combines that with asset evidence and assigns one of five action tiers with a deadline. " +
      "One point I want to be precise about: the fused value is a rank. We do not present it as a probability.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 5. Evaluation design
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Method", "EVALUATION DESIGN", "The same test set, scored under two evidence settings");
    const sw = 2.55;
    stat(s, M, CONTENT_Y + 0.1, sw, "180,497", "NVD CVEs published 2020 to 2025");
    stat(s, M, CONTENT_Y + 2.15, sw, "70,831", "test CVEs, published on or after 1 June 2024");
    stat(s, M + sw + 0.3, CONTENT_Y + 0.1, sw, "277", "CISA KEV positives in the test set", CORAL);
    stat(s, M + sw + 0.3, CONTENT_Y + 2.15, sw, "0.39%", "prevalence, so PR-AUC is the primary metric", CORAL);

    const x = 6.75, cw = W - M - x;
    card(s, x, CONTENT_Y + 0.1, cw, 1.85);
    T(s, "Frozen snapshot", { x: x + 0.35, y: CONTENT_Y + 0.32, w: cw - 0.7, h: 0.4, fontSize: 19, bold: true, color: BLUE });
    T(s, "Every feature as observed in March 2026. This is the common practice, and it lets post-publication knowledge into the features.",
      { x: x + 0.35, y: CONTENT_Y + 0.8, w: cw - 0.7, h: 1.0, fontSize: 15, color: MUTED });
    card(s, x, CONTENT_Y + 2.2, cw, 1.85);
    T(s, "Historical EPSS", { x: x + 0.35, y: CONTENT_Y + 2.42, w: cw - 0.7, h: 0.4, fontSize: 19, bold: true, color: TEAL });
    T(s, "EPSS replaced by the first monthly score on or after each CVE's publication, from the FIRST archive. A sensitivity analysis, not a full replay.",
      { x: x + 0.35, y: CONTENT_Y + 2.9, w: cw - 0.7, h: 1.0, fontSize: 15, color: MUTED });
    T(s, "Significance: paired bootstrap (10,000 resamples) and paired permutation test, Holm-Bonferroni corrected.",
      { x: M, y: 6.25, w: W - 2 * M, h: 0.45, fontSize: 14, color: MUTED });
    s.addNotes(
      "The dataset is one hundred and eighty thousand CVEs published from 2020 to 2025. We split chronologically at June 2024, which gives about seventy-one thousand test CVEs. " +
      "Only two hundred and seventy-seven are in CISA's Known Exploited Vulnerabilities catalogue, a prevalence of 0.39 percent, so accuracy and even ROC are misleading and we use PR-AUC. " +
      "The key design decision is on the right. We score the same test set twice. In the frozen snapshot, every feature is as it looked in March 2026; that is how most studies evaluate. " +
      "In the second setting we replace EPSS with the score that existed when each CVE was published, taken from FIRST's historical archive. " +
      "It is a sensitivity analysis: we did not reconstruct every NVD field historically, and I will say so again under limitations.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 6. RQ1 frozen
  // ════════════════════════════════════════════════════════════════════
  pres.addSection({ title: "Results" });
  {
    const s = content("Results", "RQ1  ·  FROZEN SNAPSHOT", "In the frozen snapshot, rank fusion leads every baseline");
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["CVSS", "XGBoost tabular", "EPSS", "XGBoost + embeddings", "RRF (k = 60)"],
      values: [0.011, 0.251, 0.271, 0.309, 0.367] }], {
      x: M, y: CONTENT_Y, w: 7.4, h: 4.55, barDir: "bar", ...axis,
      chartColors: [HEX.accent6, HEX.accent6, HEX.accent4, HEX.accent6, HEX.accent1], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000",
      showLegend: false, showTitle: true, title: "PR-AUC, frozen March 2026 snapshot", titleColor: MUTED, titleFontSize: 13,
      barGapWidthPct: 55, catAxisOrientation: "maxMin", objectName: name("Chart frozen PR-AUC"),
    });
    const x = 8.65, cw = W - M - x;
    stat(s, x, CONTENT_Y + 0.05, cw, "0.367 vs 0.271", "RRF against EPSS: +35.4%, paired-bootstrap 95% CI +0.054 to +0.142", TEAL, 34);
    stat(s, x, CONTENT_Y + 1.95, cw, "71 of 100", "top-ranked CVEs are confirmed exploited (EPSS: 44)", TEAL, 34);
    T(s, "RRF also leads CombSUM, Borda and stacking on the same three sources, though its edge over CombSUM is not statistically distinguishable.",
      { x, y: CONTENT_Y + 3.75, w: cw, h: 0.95, fontSize: 14, color: MUTED });
    s.addNotes(
      "First the conventional result. In the frozen snapshot, RRF reaches a PR-AUC of 0.367 against 0.271 for EPSS, a thirty-five percent gain that is statistically significant. " +
      "Operationally, seventy-one of the top one hundred ranked CVEs are confirmed exploited, against forty-four for EPSS. " +
      "We also compared five other fusion methods on the identical three inputs, and RRF came first, although its lead over simple score averaging is within noise. " +
      "If I stopped here, this would be the headline. The next slide is why I do not stop here.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 7. RQ1 historical
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Results", "RQ1  ·  HISTORICAL EPSS", "With the EPSS score that existed at publication, the advantage is not reliable");
    s.addChart(pres.charts.BAR, [
      { name: "EPSS", labels: ["Frozen snapshot", "Historical EPSS"], values: [0.2711, 0.2581] },
      { name: "RRF", labels: ["Frozen snapshot", "Historical EPSS"], values: [0.3671, 0.2678] },
    ], {
      x: M, y: CONTENT_Y, w: 6.9, h: 4.55, barDir: "col", barGrouping: "clustered", ...axis,
      chartColors: [HEX.accent4, HEX.accent1], valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1,
      dataLabelFormatCode: "0.000", showLegend: true, legendPos: "b",
      showTitle: true, title: "PR-AUC on the same 70,831 test CVEs", titleColor: MUTED, titleFontSize: 13,
      barGapWidthPct: 70, objectName: name("Chart frozen vs historical"),
    });
    const x = 8.15, cw = W - M - x;
    card(s, x, CONTENT_Y + 0.05, cw, 2.35);
    T(s, "+3.8%", { x: x + 0.35, y: CONTENT_Y + 0.25, w: cw - 0.7, h: 0.8, fontSize: 48, bold: true, color: AMBER, valign: "middle" });
    T(s, "0.2678 vs 0.2581. The 95% CI of the difference is −0.031 to +0.052 and the permutation test is non-significant.",
      { x: x + 0.35, y: CONTENT_Y + 1.15, w: cw - 0.7, h: 1.1, fontSize: 15, color: MUTED });
    T(s, [
      { text: "A null result, reported as one. ", options: { bold: true, color: INK } },
      { text: "The +35.4% gap came largely from EPSS values observed after publication. RRF is an integration choice, not a demonstrated replacement for EPSS.", options: { color: MUTED } },
    ], { x, y: CONTENT_Y + 2.7, w: cw, h: 1.8, fontSize: 16 });
    s.addNotes(
      "This is the central finding. EPSS scores are updated daily, and they rise after exploitation is observed. A 2026 EPSS score for a 2024 vulnerability already knows what happened. " +
      "When we replace it with the first monthly score available on or after publication, the picture changes. RRF scores 0.268, EPSS 0.258. " +
      "The difference is plus 3.8 percent, the confidence interval spans zero, and the permutation test is not significant. " +
      "So the thirty-five percent gap was largely hindsight. We report this as a null result. We do not claim RRF beats EPSS at deployment time. " +
      "I would argue this is the more useful contribution: the same check applies to any study that evaluates on current enrichment data.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 8. RQ2
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Results", "RQ2  ·  LEAKAGE AUDIT", "Hindsight inflates the metric in two measurable ways");
    const cw = (W - 2 * M - 0.4) / 2;
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["Exploit-derived proxies", "Clean tabular"], values: [1.0, 0.268] }], {
      x: M, y: CONTENT_Y, w: cw, h: 3.35, barDir: "col", ...axis,
      chartColors: [HEX.accent2, HEX.accent1], invertedColors: [HEX.accent2],
      valAxisMinVal: 0, valAxisMaxVal: 1.2, valAxisMajorUnit: 0.4, dataLabelFormatCode: "0.000", showLegend: false,
      showTitle: true, title: "Feature-label circularity (stress test)", titleColor: MUTED, titleFontSize: 13,
      barGapWidthPct: 90, objectName: name("Chart circularity"),
    });
    s.addChart(pres.charts.LINE, [{ name: "PR-AUC", labels: ["2021-22", "2022-23", "2023-24", "2024-25"], values: [0.881, 0.705, 0.680, 0.279] }], {
      x: M + cw + 0.4, y: CONTENT_Y, w: cw, h: 3.35, ...axis, chartColors: [HEX.accent3],
      lineSize: 3, lineDataSymbolSize: 9, dataLabelPosition: "t",
      valAxisMinVal: 0, valAxisMaxVal: 1.2, valAxisMajorUnit: 0.4, dataLabelFormatCode: "0.000", showLegend: false,
      showTitle: true, title: "Frozen enrichment, by test year", titleColor: MUTED, titleFontSize: 13,
      objectName: name("Chart rolling window"),
    });
    T(s, [{ text: "3.73× ", options: { bold: true, color: CORAL } },
      { text: "inflation when inputs are derived from the same exploit evidence as the label. An intentionally invalid upper bound.", options: { color: MUTED } }],
      { x: M, y: 5.55, w: cw, h: 1.1, fontSize: 16 });
    T(s, [{ text: "0.88 to 0.28 ", options: { bold: true, color: AMBER } },
      { text: "as post-publication hindsight shrinks. Older test years look better only because their features had longer to mature.", options: { color: MUTED } }],
      { x: M + cw + 0.4, y: 5.55, w: cw, h: 1.1, fontSize: 16 });
    s.addNotes(
      "RQ2 generalises that observation. We audit four leakage types: temporal, label, entity-proxy and correlation. Two results. " +
      "On the left, a deliberate stress test. If the features include signals derived from exploit evidence, such as proof-of-concept and Metasploit indicators, the model reaches a PR-AUC of one. The clean configuration reaches 0.268. That is a 3.73 times inflation, and it is exactly what happens when the label is reconstructible from the inputs. " +
      "On the right, the same model retrained at four yearly boundaries with frozen enrichment. PR-AUC falls from 0.88 for the oldest test year to 0.28 for the most recent. Nothing about the model changed; older vulnerabilities simply had more time for their enrichment to catch up with reality.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 9. RQ3 grounding
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Results", "RQ3  ·  GROUNDED BRIEFS", "Deterministic checks hold fabricated identifiers at zero");
    const steps = [
      [fa.FaSearch, "Retrieve", "Nearest ATT&CK techniques by SBERT similarity"],
      [fa.FaFingerprint, "Validate IDs", "Every technique must exist in the v18.1 STIX corpus"],
      [fa.FaRobot, "Generate", "GPT-4o-mini fills a fixed JSON schema"],
      [fa.FaLink, "Ground references", "A URL is kept only if it is in the CVE's own reference list"],
    ];
    const gap = 0.3, cw = (W - 2 * M - gap * 3) / 4, y = CONTENT_Y + 0.05, h = 1.95;
    for (let i = 0; i < steps.length; i++) {
      const [Ico, head, body] = steps[i], x = M + i * (cw + gap);
      card(s, x, y, cw, h);
      await chip(s, Ico, x + 0.28, y + 0.28, HEX.accent1, 0.55);
      T(s, head, { x: x + 1.0, y: y + 0.28, w: cw - 1.2, h: 0.55, fontSize: 17, bold: true, valign: "middle" });
      T(s, body, { x: x + 0.28, y: y + 1.0, w: cw - 0.5, h: 0.85, fontSize: 14, color: MUTED });
    }
    const sy = 4.45, sw = (W - 2 * M - 0.6) / 3;
    stat(s, M, sy, sw, "0 of 150", "briefs contained a fabricated ATT&CK identifier");
    stat(s, M + sw + 0.3, sy, sw, "149 of 150", "briefs cite an advisory listed on the CVE record");
    stat(s, M + 2 * (sw + 0.3), sy, sw, "2 of 271", "proposed mappings rejected by retrieval grounding", AMBER);
    s.addNotes(
      "RQ3 concerns the explanation layer. For each CVE we retrieve the nearest ATT&CK techniques, check that every identifier exists in the pinned ATT&CK version 18.1 corpus, " +
      "generate a structured brief with GPT-4o-mini, and then keep a remediation link only if it appears verbatim in the CVE's own reference list. " +
      "On one hundred and fifty briefs for the top-ranked test CVEs: no fabricated technique identifier, and one hundred and forty-nine cite a CVE-listed advisory. " +
      "These are exact-match checks, not opinions. What they do not establish is whether a valid technique is the right technique. That is the next slide.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 10. RQ3 verification trade-off
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Results", "RQ3  ·  VERIFICATION", "A verification pass buys precision and pays for it in coverage");
    s.addChart(pres.charts.BAR, [
      { name: "Standard retrieval", labels: ["Over-rationalized briefs", "Technique relevance", "Abstention"], values: [27.3, 87.8, 1.3] },
      { name: "With verification", labels: ["Over-rationalized briefs", "Technique relevance", "Abstention"], values: [12.0, 95.9, 34.7] },
    ], {
      x: M, y: CONTENT_Y, w: 7.3, h: 4.55, barDir: "col", barGrouping: "clustered", ...axis,
      chartColors: [HEX.accent4, HEX.accent1], valAxisMinVal: 0, valAxisMaxVal: 110, valAxisMajorUnit: 25,
      dataLabelFormatCode: '0.0"%"', valAxisLabelFormatCode: '0"%"', showLegend: true, legendPos: "b",
      showTitle: true, title: "150 briefs, GPT-4o quality judge", titleColor: MUTED, titleFontSize: 13,
      barGapWidthPct: 60, objectName: name("Chart verification"),
    });
    const x = 8.5, cw = W - M - x;
    T(s, [
      { text: "Over-rationalization: ", options: { bold: true, color: INK } },
      { text: "a valid but semantically inappropriate technique, justified rather than declined.", options: { color: MUTED, breakLine: true } },
    ], { x, y: CONTENT_Y + 0.05, w: cw, h: 1.15, fontSize: 15 });
    T(s, [
      { text: "A Chain-of-Verification pass asks, per candidate, whether it describes how this CVE is exploited.", options: { color: MUTED, breakLine: true, paraSpaceAfter: 8 } },
      { text: "Mappings per brief fall from 2.96 to 0.83.", options: { color: MUTED, breakLine: true, paraSpaceAfter: 8 } },
      { text: "An optional high-precision mode, not a free improvement.", options: { bold: true, color: INK } },
    ], { x, y: CONTENT_Y + 1.3, w: cw, h: 2.2, fontSize: 15 });
    T(s, "Judges are LLMs, not human raters: GPT-4o and GPT-5.1 agree at κ = 0.55 (relevance), 0.44 (advisory), 0.29 (over-rationalization).",
      { x, y: CONTENT_Y + 3.55, w: cw, h: 1.0, fontSize: 13, color: MUTED });
    s.addNotes(
      "The residual failure mode is what we call over-rationalization. Retrieval sometimes surfaces a technique that is lexically similar but wrong, for example a client-side execution technique for a server-side flaw, and the model justifies it instead of declining it. " +
      "A GPT-4o judge flags this in 27 percent of standard briefs. We added an optional Chain-of-Verification pass that asks, for each candidate, whether it actually describes how this CVE would be exploited. " +
      "Over-rationalization drops to 12 percent and relevance rises from 88 to 96 percent. The cost is on the right of the chart: the system abstains on about 35 percent of briefs. " +
      "So this is a precision and coverage trade-off, and we offer it as a mode, not a default. " +
      "I also want to be clear about the evidence type: these judgements come from two language models, with moderate to fair agreement. They are not human ratings.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 11. RQ4
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Results", "RQ4  ·  ASSET CONTEXT", "Asset evidence changes about one in five recommended actions");
    const tiers = [
      ["PATCH NOW", "24 h", HEX.accent2], ["MITIGATE NOW", "24 h", HEX.accent2],
      ["PATCH WINDOW", "30 days", HEX.accent3], ["MONITOR", "90 days", HEX.accent4], ["ACCEPT", "1 year", HEX.accent1],
    ];
    const tx = M, tw = 4.3, th = 0.62, ty = CONTENT_Y + 0.5;
    T(s, "Five action tiers, each with an SLA", { x: tx, y: CONTENT_Y, w: tw, h: 0.4, fontSize: 14, color: MUTED });
    tiers.forEach(([label, sla, hex], i) => {
      const y = ty + i * (th + 0.14);
      card(s, tx, y, tw, th);
      s.addShape(pres.shapes.OVAL, { x: tx + 0.25, y: y + 0.21, w: 0.2, h: 0.2, fill: { color: hex }, line: { color: hex, width: 0 },
        objectName: name("Tier dot") });
      T(s, label, { x: tx + 0.62, y, w: 2.4, h: th, fontSize: 15, bold: true, valign: "middle" });
      T(s, sla, { x: tx + tw - 1.35, y, w: 1.1, h: th, fontSize: 14, color: MUTED, align: "right", valign: "middle" });
    });
    const x = 5.55, cw = W - M - x, half = (cw - 0.3) / 2;
    T(s, "Synthetic fleet: 51 assets, 5,435 asset-CVE pairs, synthesized VEX and reachability",
      { x, y: CONTENT_Y, w: cw, h: 0.4, fontSize: 14, color: MUTED });
    card(s, x, CONTENT_Y + 0.5, half, 2.7);
    T(s, "AS PUBLISHED", { x: x + 0.3, y: CONTENT_Y + 0.7, w: half - 0.6, h: 0.3, fontSize: 12, bold: true, color: MUTED, charSpacing: 2 });
    T(s, "23.4%", { x: x + 0.3, y: CONTENT_Y + 1.05, w: half - 0.6, h: 0.7, fontSize: 40, bold: true, color: MUTED, valign: "middle" });
    T(s, "of decisions changed. Urgent queue 1,286 to 177 (−86%).", { x: x + 0.3, y: CONTENT_Y + 1.85, w: half - 0.6, h: 1.1, fontSize: 14, color: MUTED });
    card(s, x + half + 0.3, CONTENT_Y + 0.5, half, 2.7);
    T(s, "CORRECTED AFTER AUDIT", { x: x + half + 0.6, y: CONTENT_Y + 0.7, w: half - 0.6, h: 0.3, fontSize: 12, bold: true, color: TEAL, charSpacing: 2 });
    T(s, "19.1%", { x: x + half + 0.6, y: CONTENT_Y + 1.05, w: half - 0.6, h: 0.7, fontSize: 40, bold: true, color: TEAL, valign: "middle" });
    T(s, "of decisions changed. Urgent queue 1,286 to 533 (−58.6%).", { x: x + half + 0.6, y: CONTENT_Y + 1.85, w: half - 0.6, h: 1.1, fontSize: 14, color: MUTED });
    T(s, [
      { text: "What changed: ", options: { bold: true, color: INK } },
      { text: "a post-publication audit found that a VEX statement recorded for one asset was also applied to other assets with the same CVE. Scoping statements correctly lowers the effect. Both figures describe rule sensitivity on synthetic evidence, not enterprise workload savings.", options: { color: MUTED } },
    ], { x, y: CONTENT_Y + 3.4, w: cw, h: 1.25, fontSize: 14 });
    s.addNotes(
      "RQ4 asks what happens when the decision engine is given asset context. It assigns one of five tiers, from patch now within twenty-four hours down to accept with annual review, and records why. " +
      "Without asset context, every KEV vulnerability goes to an urgent tier; that only verifies the rule executes. The informative test is the ablation on a seeded synthetic fleet of fifty-one assets. " +
      "The paper reports that asset evidence changed 23.4 percent of decisions and cut the urgent queue by 86 percent. " +
      "After publication we continued auditing the system and found a defect: a VEX not-affected statement recorded for one asset was being applied to other assets holding the same CVE. " +
      "With statements scoped correctly, the same seeded experiment gives 19.1 percent and a 58.6 percent reduction. I am presenting the corrected figure. " +
      "Either way this is a sensitivity result on synthetic evidence. It shows the engine responds traceably to asset evidence; it is not a measured workload saving in an enterprise.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 12. Working system (post-paper)
  // ════════════════════════════════════════════════════════════════════
  pres.addSection({ title: "Discussion" });
  {
    const s = content("Discussion", "SINCE THE PAPER", "The asset workflow now runs on real software inventories");
    const shot = path.join(ASSETS, "assets_page.png");
    const iw = 6.55, ih = iw * (729 / 1215);
    if (fs.existsSync(shot)) {
      s.addImage({ path: shot, x: M, y: CONTENT_Y + 0.05, w: iw, h: ih, objectName: name("Screenshot assets page"),
        altText: "VulnTriage Assets page showing a prioritised finding queue for an Apache httpd 2.4.49 container" });
      s.addShape(pres.shapes.RECTANGLE, { x: M, y: CONTENT_Y + 0.05, w: iw, h: ih, fill: { color: BG, transparency: 100 },
        line: { color: RAISED, width: 1 }, objectName: name("Screenshot frame") });
    }
    T(s, "Real SBOM (Syft) of httpd:2.4.49 registered as an internet-facing asset",
      { x: M, y: CONTENT_Y + ih + 0.2, w: iw, h: 0.4, fontSize: 12, color: MUTED });
    const x = M + iw + 0.45, cw = W - M - x;
    const pts = [
      [fa.FaCodeBranch, "Version-range matching", "Installed versions are compared with NVD's vulnerable ranges, so a patched component is not reported."],
      [fa.FaExclamationTriangle, "A justified short list", "73 matching CVEs reduce to 4 urgent. CVE-2021-41773 and CVE-2021-42013 are PATCH NOW with the version as evidence."],
      [fa.FaSortNumericDown, "Standard outputs", "The fused rank is served as a rank, and each decision also reports the CISA SSVC outcome from derived decision points."],
    ];
    for (let i = 0; i < pts.length; i++) {
      const [Ico, head, body] = pts[i], y = CONTENT_Y + 0.05 + i * 1.5;
      await chip(s, Ico, x, y, HEX.accent1, 0.55);
      T(s, head, { x: x + 0.75, y, w: cw - 0.75, h: 0.35, fontSize: 17, bold: true });
      T(s, body, { x: x + 0.75, y: y + 0.4, w: cw - 0.75, h: 0.95, fontSize: 14, color: MUTED });
    }
    s.addNotes(
      "The paper listed validating the SBOM and VEX pipeline on real inventories as future work, so I want to show where that stands. " +
      "This is a real software bill of materials, generated with Syft from the public Apache httpd 2.4.49 image and registered as an internet-facing, high-criticality asset. " +
      "The system compares each installed version with the vulnerable version ranges NVD publishes. Seventy-three CVEs match the installed products; four are urgent. " +
      "The two at the top are the 2021 path-traversal vulnerabilities, both in the KEV catalogue, and the evidence line shows the installed version inside the vulnerable range. " +
      "The same check on up-to-date images returns no urgent items, because the installed versions fall outside the ranges. " +
      "This is a demonstration on three public images, not an evaluation. It is included to show the workflow is operational." +
      (BEYOND.notes ? " " + BEYOND.notes : ""));
  }

  // ════════════════════════════════════════════════════════════════════
  // 13. Limitations
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Discussion", "LIMITATIONS", "What these results do not establish");
    const lim = [
      [fa.FaHistory, "Not a prospective replay", "Features and KEV labels are a March 2026 snapshot. Only EPSS is replaced historically."],
      [fa.FaTag, "KEV is incomplete", "It is curated and conservative. Negatives may later be exploited, so recall is a lower bound."],
      [fa.FaCubes, "Synthetic asset evidence", "The fleet, VEX statements, controls and reachability are simulated. Queue reductions are not enterprise outcomes."],
      [fa.FaUserCheck, "No human ratings", "Relevance is judged by two LLMs. Against MITRE CTID analyst mappings, retrieval alone hits in the top 3 for 27% of CVEs."],
    ];
    const cw = (W - 2 * M - 0.34) / 2, ch = 2.05;
    for (let i = 0; i < 4; i++) {
      const [Ico, head, body] = lim[i];
      const x = M + (i % 2) * (cw + 0.34), y = CONTENT_Y + 0.1 + Math.floor(i / 2) * (ch + 0.3);
      card(s, x, y, cw, ch);
      await chip(s, Ico, x + 0.35, y + 0.38, HEX.accent3, 0.7);
      T(s, head, { x: x + 1.3, y: y + 0.38, w: cw - 1.6, h: 0.4, fontSize: 19, bold: true, valign: "middle" });
      T(s, body, { x: x + 1.3, y: y + 0.9, w: cw - 1.6, h: 0.95, fontSize: 15, color: MUTED });
    }
    s.addNotes(
      "Four limitations constrain how these results should be read. " +
      "First, this is a chronological split over a single 2026 snapshot. We replaced EPSS historically, but not every NVD field or the KEV labels, so nothing here is a full prospective replay. " +
      "Second, KEV is curated and incomplete. A vulnerability can be exploited without ever being listed, so our recall is a lower bound. Strictly, we predict KEV inclusion. " +
      "Third, the asset experiment uses a synthetic fleet. " +
      "Fourth, the semantic quality of the briefs is judged by language models. The deterministic checks are solid; the relevance figures need human annotators. " +
      "Since the paper we ran one check against human ground truth: MITRE's Center for Threat-Informed Defense publishes analyst mappings from KEV vulnerabilities to ATT&CK. On 345 of those, our retriever alone places a human-chosen technique in its top three for only 27 percent. That comparison is not like for like, because the analysts also map impact, which a description often does not reveal, but it confirms that model-judged relevance must not be read as human-validated accuracy. " +
      "We state these in the paper because a low-cost integrated system is only useful if its evidence time, labels and validation type are explicit.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 14. Conclusions
  // ════════════════════════════════════════════════════════════════════
  {
    const s = content("Discussion", "CONCLUSIONS", "An integration, and an honest account of where its gains survive");
    const cw = 7.0;
    const take = [
      ["RRF reaches PR-AUC 0.367 in the frozen snapshot; with historical EPSS the +3.8% advantage is not statistically reliable.", TEAL],
      ["Exploit-derived proxies inflate PR-AUC 3.73×, and frozen enrichment flatters older test years.", CORAL],
      ["Deterministic grounding holds fabricated ATT&CK IDs at zero; verification trades 34.7% abstention for precision.", TEAL],
      ["Asset evidence changes about one in five action tiers on a synthetic fleet, with a traceable rationale.", AMBER],
    ];
    take.forEach(([t, col], i) => {
      const y = CONTENT_Y + 0.05 + i * 1.08;
      s.addShape(pres.shapes.OVAL, { x: M, y: y + 0.03, w: 0.46, h: 0.46, fill: { color: RAISED }, line: { color: RAISED, width: 0 },
        objectName: name("Number chip") });
      T(s, String(i + 1), { x: M, y: y + 0.03, w: 0.46, h: 0.46, fontSize: 15, bold: true, color: col, align: "center", valign: "middle" });
      T(s, t, { x: M + 0.7, y, w: cw - 0.7, h: 0.95, fontSize: 16, valign: "top" });
    });
    const x = M + cw + 0.5, w2 = W - M - x;
    card(s, x, CONTENT_Y + 0.05, w2, 4.15);
    T(s, "FUTURE WORK", { x: x + 0.35, y: CONTENT_Y + 0.3, w: w2 - 0.7, h: 0.3, fontSize: 12, bold: true, color: TEAL, charSpacing: 2 });
    const fut = [
      "Replay historical NVD and KEV states for a fully prospective evaluation",
      "Validate SBOM and VEX decisions on independently collected enterprise inventories",
      "Two blinded cybersecurity annotators for brief quality",
      "A preregistered cost-quality study of low-cost versus premium models",
    ];
    T(s, fut.map((t, j) => ({ text: t, options: { bullet: true, breakLine: j < fut.length - 1, paraSpaceAfter: 10 } })),
      { x: x + 0.35, y: CONTENT_Y + 0.75, w: w2 - 0.7, h: 3.2, fontSize: 15, color: MUTED });
    s.addNotes(
      "To conclude. One: rank fusion gives a clear gain in the conventional frozen evaluation, and that gain is not statistically reliable once EPSS is taken at publication time. RRF is an integration choice, not a replacement for EPSS. " +
      "Two: we quantified two sources of inflation, feature-label circularity and retroactive enrichment, and both are large. " +
      "Three: deterministic grounding prevents invalid identifiers and unsupported links, and optional verification improves precision at a real coverage cost. " +
      "Four: asset evidence changes roughly one in five recommended actions in a synthetic setting, with every change traceable to evidence. " +
      "The boundaries are part of the result. Future work is a full historical replay, real enterprise inventories, human annotation, and a preregistered cost-quality study.");
  }

  // ════════════════════════════════════════════════════════════════════
  // 15. Closing
  // ════════════════════════════════════════════════════════════════════
  {
    const s = pres.addSlide({ masterName: "CLOSING", sectionTitle: "Discussion" });
    s.addText("Thank you", { placeholder: "title" });
    s.addText("Questions and discussion", { placeholder: "body" });
    T(s, [
      { text: "Huraib Jan Sarhandi", options: { bold: true, color: INK, breakLine: true } },
      { text: "sarhandih1@montclair.edu", options: { color: MUTED, breakLine: true, paraSpaceAfter: 10 } },
      { text: "Weitian Wang", options: { bold: true, color: INK, breakLine: true } },
      { text: "wangw@montclair.edu", options: { color: MUTED, breakLine: true, paraSpaceAfter: 10 } },
      { text: "Code and artifacts: github.com/huraibjan/vulntriage", options: { color: TEAL } },
    ], { x: M, y: 4.3, w: 8.2, h: 2.2, fontSize: 16 });
    const cx = 11.0, cy = 3.75;
    [[4.2, 92], [3.1, 86], [2.0, 78]].forEach(([d, tr]) => s.addShape(pres.shapes.HEXAGON, {
      x: cx - d / 2, y: cy - d / 2, w: d, h: d, fill: { color: TEAL, transparency: tr },
      line: { color: TEAL, width: 1, transparency: 55 }, objectName: name("Hex mark") }));
    s.addImage({ data: await icon(fa.FaShieldAlt, HEX.accent1, 512), x: cx - 0.55, y: cy - 0.6, w: 1.1, h: 1.2,
      objectName: name("Shield") });
    s.addNotes(
      "Thank you. I am happy to take questions. Likely ones, with short answers: " +
      "Why not just use EPSS? Under historical evidence we do not show a reliable ranking gain over it; the system's value is the workflow around the score. " +
      "Is the evaluation inflated? In the frozen setting yes, and we measured by how much. " +
      "Is an LLM judging an LLM circular? The load-bearing claims are exact-match checks; the judged figures are labelled exploratory. " +
      "Concurrent work, for example Alpay and Alpay 2026, also reports large inflation under retrospective evidence, which is consistent with our finding.");
  }

  // ════════════════════════════════════════════════════════════════════
  // Backup slides
  // ════════════════════════════════════════════════════════════════════
  pres.addSection({ title: "Backup" });
  {
    const s = content("Backup", "BACKUP  ·  FUSION METHODS", "Six fusion methods over the same three rank sources");
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["RRF (k = 60)", "CombSUM", "CombMNZ", "Optimised blend", "Borda count", "LR stacking"],
      values: [0.3671, 0.3536, 0.3536, 0.3536, 0.3065, 0.2589] }], {
      x: M, y: CONTENT_Y, w: 7.4, h: 4.55, barDir: "bar", ...axis,
      chartColors: [HEX.accent1, HEX.accent6, HEX.accent6, HEX.accent6, HEX.accent6, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000", showLegend: false,
      showTitle: true, title: "PR-AUC, frozen snapshot", titleColor: MUTED, titleFontSize: 13,
      barGapWidthPct: 55, catAxisOrientation: "maxMin", objectName: name("Chart fusion baselines"),
    });
    const x = 8.65, cw = W - M - x;
    T(s, [
      { text: "RRF versus CombSUM: Δ +0.014, 95% CI −0.001 to +0.029. Not statistically distinguishable.", options: { color: MUTED, breakLine: true, paraSpaceAfter: 10 } },
      { text: "k sweep from 5 to 300 moves PR-AUC by 0.034 (0.379 to 0.345). The literature default k = 60 is kept; choosing k = 5 on the test set would be optimistic.", options: { color: MUTED, breakLine: true, paraSpaceAfter: 10 } },
      { text: "Stacking is weakest: few validation positives and mismatched score scales. Rank fusion is scale-invariant.", options: { color: MUTED } },
    ], { x, y: CONTENT_Y + 0.05, w: cw, h: 4.4, fontSize: 15 });
    s.addNotes("Backup for questions on the fusion choice and on k. All methods use the identical three rank sources.");
  }
  {
    const s = content("Backup", "BACKUP  ·  FEATURE NECESSITY", "EPSS is the least replaceable input in the clean tabular model");
    s.addChart(pres.charts.BAR, [{ name: "Relative PR-AUC drop", labels: ["EPSS", "Reference and product counts", "Days since publication", "CVSS vector"],
      values: [87, 29, 17, 13] }], {
      x: M, y: CONTENT_Y, w: 7.4, h: 4.55, barDir: "bar", ...axis,
      chartColors: [HEX.accent2, HEX.accent6, HEX.accent6, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 100, valAxisMajorUnit: 25, dataLabelFormatCode: '0"%"', valAxisLabelFormatCode: '0"%"',
      showLegend: false, showTitle: true, title: "Relative PR-AUC drop when the group is removed and the model retrained",
      titleColor: MUTED, titleFontSize: 13, barGapWidthPct: 55, catAxisOrientation: "maxMin",
      objectName: name("Chart feature ablation"),
    });
    const x = 8.65, cw = W - M - x;
    T(s, [
      { text: "Removing EPSS collapses PR-AUC from 0.268 to 0.034 (95% CI of the difference +0.181 to +0.285).", options: { color: MUTED, breakLine: true, paraSpaceAfter: 10 } },
      { text: "TreeSHAP attribution ranks reference count first (33%), then EPSS (27%). Attribution measures average contribution; ablation measures unique signal.", options: { color: MUTED, breakLine: true, paraSpaceAfter: 10 } },
      { text: "These are frozen-snapshot explanations and may carry hindsight through reference, product and elapsed-time fields.", options: { color: MUTED } },
    ], { x, y: CONTENT_Y + 0.05, w: cw, h: 4.4, fontSize: 15 });
    s.addNotes("Backup for questions on interpretability and on how much of the model is EPSS.");
  }

  {
    const s = content("Backup", "BACKUP  ·  CHECKS AFTER PUBLICATION", "Two further checks: human ground truth and the NIST LEV baseline");
    const cw = (W - 2 * M - 0.4) / 2;
    s.addChart(pres.charts.BAR, [{ name: "Top-3 hit rate", labels: ["VulnTriage retriever", "Three most common techniques"], values: [0.267, 0.754] }], {
      x: M, y: CONTENT_Y, w: cw, h: 3.35, barDir: "col", ...axis,
      chartColors: [HEX.accent1, HEX.accent6], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 1, valAxisMajorUnit: 0.25, dataLabelFormatCode: "0.000", showLegend: false,
      showTitle: true, title: "Agreement with MITRE CTID analyst mappings (345 KEV CVEs)", titleColor: MUTED, titleFontSize: 13,
      barGapWidthPct: 90, objectName: name("Chart CTID"),
    });
    s.addChart(pres.charts.BAR, [{ name: "PR-AUC", labels: ["NIST LEV", "EPSS", "RRF"], values: [0.252, 0.271, 0.367] }], {
      x: M + cw + 0.4, y: CONTENT_Y, w: cw, h: 3.35, barDir: "col", ...axis,
      chartColors: [HEX.accent3, HEX.accent4, HEX.accent1], invertedColors: [HEX.accent6],
      valAxisMinVal: 0, valAxisMaxVal: 0.45, valAxisMajorUnit: 0.1, dataLabelFormatCode: "0.000", showLegend: false,
      showTitle: true, title: "PR-AUC, frozen setting, 70,831 test CVEs", titleColor: MUTED, titleFontSize: 13,
      barGapWidthPct: 90, objectName: name("Chart LEV"),
    });
    T(s, [{ text: "Retrieval alone agrees poorly with analysts. ", options: { bold: true, color: INK } },
      { text: "Exploitation-technique mappings only: 0.222. CTID also maps impact, which a description often cannot reveal, and the constant guess is fitted on the same CVEs.", options: { color: MUTED } }],
      { x: M, y: 5.5, w: cw, h: 1.2, fontSize: 14 });
    T(s, [{ text: "LEV does not beat EPSS as a ranker here. ", options: { bold: true, color: INK } },
      { text: "Difference −0.019, 95% CI −0.041 to +0.005. RRF minus LEV +0.115, CI +0.063 to +0.164. Monthly snapshots approximate NIST's 30-day windows.", options: { color: MUTED } }],
      { x: M + cw + 0.4, y: 5.5, w: cw, h: 1.2, fontSize: 14 });
    s.addNotes(
      "Backup. Two checks run after the paper was accepted. Left: agreement between our ATT&CK retriever and MITRE CTID's analyst mappings for KEV vulnerabilities, with no language model involved. " +
      "A top-three hit rate of 0.267, against 0.754 for always guessing the three most common techniques. This is an unfavourable result and we report it as such. " +
      "Right: NIST's Likely Exploited Vulnerabilities metric as an additional baseline in the frozen setting. LEV does not improve on EPSS as a ranker of KEV membership on this test set, and RRF remains ahead of it. " +
      "Sources: results/ctid_attack_eval.json and results/lev_baseline.json.");
  }

  await pres.writeFile({ fileName: OUT });
  await applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})().catch((e) => { console.error(e); process.exit(1); });
