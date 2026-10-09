#!/usr/bin/env python3
"""Standardized revision figures for the IEEE paper (reviewer minor #1).

Reads ONLY the released results JSONs — every figure regenerates from the
same artifacts the tables cite, so figures and tables cannot drift apart.

Conventions (uniform across all five figures):
  - single-column IEEE width (3.5 in), 300 dpi, serif (Times) 8-9 pt
  - PR-AUC always on the value axis with identical label text
  - context bars in neutral gray with direct value labels (identity is on
    the category axis); the proposed method in accent blue
  - two-series charts use the validated blue/red pair + hatching on one
    series so the figure survives grayscale printing and CVD
  - recessive grid (x-only, 0.4 alpha), no top/right spines, no legend for
    single-series plots

Usage:  python experiments/generate_revision_figures.py
Writes: docs/figures/revision/*.png (+ .pdf)
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = Path(__file__).resolve().parent.parent
RES = ROOT / "results"
OUT = ROOT / "docs" / "figures" / "revision"
OUT.mkdir(parents=True, exist_ok=True)

# Palette (validated: blue/red adjacent CVD dE 32.8; gray = de-emphasis with
# direct labels as relief)
ACCENT = "#2a78d6"
CONTRAST = "#e34948"
NEUTRAL = "#9aa0a6"
INK = "#0b0b0b"
INK2 = "#52514e"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 8,
    "axes.titlesize": 9,
    "axes.labelsize": 8,
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5,
    "axes.edgecolor": INK2,
    "axes.linewidth": 0.6,
    "text.color": INK,
    "axes.labelcolor": INK,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "figure.dpi": 300,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

FIG_W = 3.5  # IEEE single column inches


def style_ax(ax, grid_axis="x"):
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis=grid_axis, color=INK2, alpha=0.25, linewidth=0.4)
    ax.set_axisbelow(True)


def save(fig, name):
    for ext in ("png", "pdf"):
        fig.savefig(OUT / f"{name}.{ext}")
    plt.close(fig)
    print(f"  wrote {name}.png/.pdf")


# ── Fig R1: fusion-method comparison (R2-1) ───────────────────────────────

def fig_fusion():
    d = json.load(open(RES / "ensemble_fusion_baselines.json"))["results"]
    keep = {
        "RRF (ours, k=60)": "RRF (k=60)",
        "CombSUM (equal-weight avg)": "CombSUM",
        "CombMNZ": "CombMNZ",
        "Optimised weighted blend": "Opt. blend",
        "Borda count": "Borda",
        "Stacking (LogReg meta-learner)": "Stacking",
        "Best single model (tab+emb)": "Best single",
        "EPSS (single-model baseline)": "EPSS",
    }
    rows = [(short, d[full]["pr_auc"]) for full, short in keep.items()]
    rows.sort(key=lambda r: r[1])
    labels = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    colors = [ACCENT if l == "RRF (k=60)" else NEUTRAL for l in labels]

    fig, ax = plt.subplots(figsize=(FIG_W, 1.75))
    bars = ax.barh(labels, vals, color=colors, height=0.62)
    for b, v in zip(bars, vals):
        ax.text(v + 0.004, b.get_y() + b.get_height() / 2, f"{v:.4f}",
                va="center", fontsize=7, color=INK)
    ax.set_xlabel("PR-AUC (frozen March 2026 feature snapshot)")
    ax.set_xlim(0, 0.44)
    style_ax(ax)
    save(fig, "fig_fusion_comparison")


# ── Fig R2: RRF k ablation (R2-3) ─────────────────────────────────────────

def fig_k_ablation():
    d = json.load(open(RES / "rrf_k_ablation.json"))
    ks = [r["k"] for r in d["rrf_results"]]
    aucs = [r["pr_auc"] for r in d["rrf_results"]]

    fig, ax = plt.subplots(figsize=(FIG_W, 1.9))
    ax.plot(ks, aucs, color=ACCENT, linewidth=1.4, marker="o",
            markersize=3.5, markerfacecolor=ACCENT)
    ax.set_xscale("log")
    ax.set_xticks(ks)
    ax.set_xticklabels([str(k) for k in ks])
    ax.minorticks_off()
    # annotate default
    k60 = next(r for r in d["rrf_results"] if r["k"] == 60)
    ax.annotate(f"default k=60\n({k60['pr_auc']:.4f})", xy=(60, k60["pr_auc"]),
                xytext=(90, k60["pr_auc"] + 0.012), fontsize=7, color=INK,
                arrowprops=dict(arrowstyle="-", color=INK2, linewidth=0.6))
    ax.set_xlabel("RRF constant k (log scale)")
    ax.set_ylabel("PR-AUC")
    ax.set_ylim(0.33, 0.39)
    style_ax(ax, grid_axis="y")
    save(fig, "fig_k_ablation")


# ── Fig R3: rolling windows, dual config (R2-4) ───────────────────────────

def fig_rolling():
    d = json.load(open(RES / "rolling_window_cv.json"))
    wins = [w for w in d["windows"] if w.get("frozen_enrichment")]
    labels = [f"{w['test_start'][:4]}–{str(int(w['test_start'][:4]) + 1)[2:]}"
              for w in wins]
    frozen = [w["frozen_enrichment"]["pr_auc"] for w in wins]
    safe = [w["pub_time_safe"]["pr_auc"] for w in wins]

    import numpy as np
    x = np.arange(len(wins))
    w = 0.36
    fig, ax = plt.subplots(figsize=(FIG_W, 1.75))
    b1 = ax.bar(x - w / 2, frozen, w, color=ACCENT,
                label="Frozen 2026 enrichment", edgecolor="white",
                linewidth=0.5)
    b2 = ax.bar(x + w / 2, safe, w, color=CONTRAST, hatch="///",
                label="Publication-time-safe", edgecolor="white",
                linewidth=0.5)
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.015,
                    f"{b.get_height():.2f}", ha="center", fontsize=6.5,
                    color=INK)
    ax.set_xticks(x, labels)
    ax.set_xlabel("Test window (train on all prior years)")
    ax.set_ylabel("PR-AUC")
    ax.set_ylim(0, 1.0)
    ax.legend(fontsize=6.5, frameon=False, loc="upper right")
    style_ax(ax, grid_axis="y")
    save(fig, "fig_rolling_window")


# ── Fig R4: feature-group LOGO ablation (R2-6) ────────────────────────────

def fig_groups():
    d = json.load(open(RES / "feature_group_ablation.json"))
    rows = [(r["group"], -100 * r["relative_drop"])
            for r in d["method_a_logo_retrain"]]
    rows.sort(key=lambda r: r[1])
    nice = {
        "enrichment_epss": "EPSS enrichment",
        "reference_network": "Reference network",
        "temporal": "Temporal",
        "cvss_vector": "CVSS vector",
        "text": "Text statistics",
        "cwe": "CWE indicators",
        "cvss_core": "CVSS core",
    }
    labels = [nice.get(g, g) for g, _ in rows][::-1]
    vals = [v for _, v in rows][::-1]

    fig, ax = plt.subplots(figsize=(FIG_W, 1.75))
    bars = ax.barh(labels, vals, color=ACCENT, height=0.62)
    for b, v in zip(bars, vals):
        ax.text(v + 1.2, b.get_y() + b.get_height() / 2, f"−{v:.1f}%",
                va="center", fontsize=7, color=INK)
    ax.set_xlabel("Relative PR-AUC drop, frozen snapshot (retrained), %")
    ax.set_xlim(0, 100)
    style_ax(ax)
    save(fig, "fig_feature_groups")


# ── Fig R5: frozen vs point-in-time EPSS (honest headline) ────────────────

def fig_pit():
    pit = json.load(open(RES / "point_in_time_epss.json"))["results"]
    frozen = {"RRF ensemble": 0.36714, "EPSS baseline": 0.27105}
    pitv = {"RRF ensemble": pit["RRF ensemble (PIT)"]["pr_auc"],
            "EPSS baseline": pit["EPSS point-in-time (baseline)"]["pr_auc"]}

    import numpy as np
    models = list(frozen.keys())
    x = np.arange(len(models))
    w = 0.36
    fig, ax = plt.subplots(figsize=(FIG_W, 2.0))
    b1 = ax.bar(x - w / 2, [frozen[m] for m in models], w, color=ACCENT,
                label="Frozen 2026 EPSS (naive)", edgecolor="white",
                linewidth=0.5)
    b2 = ax.bar(x + w / 2, [pitv[m] for m in models], w, color=CONTRAST,
                hatch="///", label="Point-in-time EPSS (honest)",
                edgecolor="white", linewidth=0.5)
    for bars in (b1, b2):
        for b in bars:
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 0.006,
                    f"{b.get_height():.3f}", ha="center", fontsize=7,
                    color=INK)
    # gain-vs-EPSS annotations, anchored to the RRF bars they describe
    ax.annotate("+35.4%\nvs EPSS", xy=(0 - w / 2, frozen["RRF ensemble"] + 0.030),
                ha="center", fontsize=6.8, color=INK, fontweight="bold")
    ax.annotate("+3.8%\nvs EPSS", xy=(0 + w / 2, pitv["RRF ensemble"] + 0.030),
                ha="center", fontsize=6.8, color=INK, fontweight="bold")
    ax.set_xticks(x, models)
    ax.set_ylabel("PR-AUC")
    ax.set_ylim(0, 0.44)
    ax.legend(fontsize=6.5, frameon=False, loc="upper right")
    style_ax(ax, grid_axis="y")
    save(fig, "fig_pit_vs_frozen")


# ── Fig R6: evidence-aligned system architecture ──────────────────────────

def fig_architecture():
    fig, ax = plt.subplots(figsize=(FIG_W, 1.75))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    def box(x, y, w, h, title, body, color=NEUTRAL):
        patch = FancyBboxPatch(
            (x, y), w, h,
            boxstyle="round,pad=0.012,rounding_size=0.018",
            linewidth=0.8, edgecolor=color, facecolor="white",
        )
        ax.add_patch(patch)
        ax.text(x + w / 2, y + h - 0.055, title, ha="center", va="center",
                fontsize=6.6, fontweight="bold", color=INK)
        ax.text(x + w / 2, y + h / 2 - 0.025, body, ha="center", va="center",
                fontsize=5.2, color=INK2, linespacing=1.15)

    def arrow(x1, y1, x2, y2):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->", color=INK2, lw=0.8))

    box(0.02, 0.61, 0.20, 0.28, "Evidence", "NVD CVEs\nCISA KEV\nFIRST EPSS")
    box(
        0.28, 0.61, 0.29, 0.28, "Evidence snapshot",
        "Frozen March 2026 features\nHistorical-EPSS sensitivity\nLeakage audit",
        color=ACCENT,
    )
    box(
        0.63, 0.61, 0.34, 0.28, "Three rankers",
        "Clean-tabular XGBoost\nTabular + SBERT XGBoost\nEPSS",
    )
    box(
        0.63, 0.18, 0.34, 0.25, "RRF prioritization",
        "Relative rank score, k = 60\nNot a calibrated probability",
        color=ACCENT,
    )
    box(
        0.28, 0.18, 0.29, 0.25, "Grounded brief",
        "ATT&CK retrieval\nSTIX + URL verification\nEvidence-based abstention",
    )
    box(
        0.02, 0.18, 0.20, 0.25, "Action tier",
        "Asset context\nSSVC rules\nAudit rationale",
    )

    arrow(0.22, 0.75, 0.28, 0.75)
    arrow(0.57, 0.75, 0.63, 0.75)
    arrow(0.80, 0.61, 0.80, 0.43)
    arrow(0.63, 0.305, 0.57, 0.305)
    arrow(0.28, 0.305, 0.22, 0.305)
    save(fig, "fig_architecture_corrected")


# ── Fig R7: reconciled circularity stress test ───────────────────────────

def fig_circularity():
    d = json.load(open(RES / "circularity_reconciled.json"))
    vals = d["configs_tuned_retrain"]
    rows = [
        ("Circular proxy-rich", vals["circular_full"]),
        ("Clean + SBERT", vals["clean_plus_text"]),
        ("EPSS only", vals["epss_only"]),
        ("Clean tabular", vals["clean_tabular"]),
        ("CVSS + EPSS", vals["cvss_epss_only"]),
        ("CVSS only", vals["cvss_only"]),
    ]
    rows.sort(key=lambda item: item[1])
    labels = [r[0] for r in rows]
    scores = [r[1] for r in rows]
    colors = [
        CONTRAST if label == "Circular proxy-rich"
        else ACCENT if label == "Clean tabular"
        else NEUTRAL
        for label in labels
    ]

    fig, ax = plt.subplots(figsize=(FIG_W, 1.75))
    bars = ax.barh(labels, scores, color=colors, height=0.62)
    for b, v in zip(bars, scores):
        ax.text(v + 0.012, b.get_y() + b.get_height() / 2, f"{v:.3f}",
                va="center", fontsize=7, color=INK)
    ax.set_xlabel("PR-AUC (single tuned retraining pipeline)")
    ax.set_xlim(0, 1.12)
    ax.text(
        0.98, 0.04, f"Circular/clean = {d['inflation_factor']:.2f}×",
        transform=ax.transAxes, ha="right", va="bottom", fontsize=6.7,
        color=INK2,
    )
    style_ax(ax)
    save(fig, "fig_circularity_reconciled")


if __name__ == "__main__":
    print("Generating standardized revision figures …")
    fig_fusion()
    fig_k_ablation()
    fig_rolling()
    fig_groups()
    fig_pit()
    fig_architecture()
    fig_circularity()
    print(f"All figures -> {OUT}")
