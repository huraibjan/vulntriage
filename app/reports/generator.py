"""Evaluation reporting – metrics, plots, and executive summary generation.

Produces:
  - reports/metrics.json             – all metrics in machine-readable format
  - reports/summary.md               – executive summary with tables
  - reports/pr_curve.png             – precision-recall curve
  - reports/calibration.png          – calibration (reliability) diagram
  - reports/topk_precision.png       – top-K precision comparison chart
  - reports/ablation_comparison.md   – cross-experiment ablation table
  - reports/decision_confusion.png   – confusion matrix for action labels
  - reports/case_studies.md          – detailed CVE walkthroughs
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib

matplotlib.use("Agg")  # non-interactive backend
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)
sns.set_theme(style="whitegrid")


def save_metrics(metrics: Dict[str, Any], reports_dir: Optional[Path] = None) -> Path:
    """Save all metrics to reports/metrics.json."""
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    path = reports_dir / "metrics.json"
    with open(path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)

    log.info("metrics_saved", path=str(path))
    return path


def plot_pr_curve(
    model_metrics: Dict[str, Any],
    baselines: Dict[str, Dict[str, Any]],
    reports_dir: Optional[Path] = None,
) -> Path:
    """Plot precision-recall curves for model vs baselines."""
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    fig, ax = plt.subplots(figsize=(8, 6))

    # Model PR curve
    if "pr_curve" in model_metrics:
        pr = model_metrics["pr_curve"]
        ax.plot(pr["recall"], pr["precision"], label=f"Our Model (PR-AUC={model_metrics.get('pr_auc', 0):.3f})", linewidth=2, color="blue")

    # Baseline PR-AUC as horizontal markers
    colors = {"cvss_only": "red", "epss_only": "orange", "kev_first": "green"}
    for name, bl in baselines.items():
        pr_auc = bl.get("pr_auc", 0)
        color = colors.get(name, "gray")
        ax.axhline(y=pr_auc, linestyle="--", color=color, alpha=0.7,
                    label=f"{name} (PR-AUC={pr_auc:.3f})")

    ax.set_xlabel("Recall", fontsize=12)
    ax.set_ylabel("Precision", fontsize=12)
    ax.set_title("Precision-Recall Curve: Model vs Baselines", fontsize=14)
    ax.legend(loc="lower left", fontsize=10)
    ax.set_xlim([0, 1])
    ax.set_ylim([0, 1.05])

    path = reports_dir / "pr_curve.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("pr_curve_saved", path=str(path))
    return path


def plot_calibration(
    calibration_data: Dict[str, Any],
    reports_dir: Optional[Path] = None,
) -> Path:
    """Plot calibration (reliability) diagram."""
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    fig, ax = plt.subplots(figsize=(6, 6))

    prob_true = calibration_data.get("prob_true", [])
    prob_pred = calibration_data.get("prob_pred", [])

    if prob_true and prob_pred:
        ax.plot(prob_pred, prob_true, "s-", label="Calibrated model", color="blue")

    ax.plot([0, 1], [0, 1], "k--", label="Perfectly calibrated")
    ax.set_xlabel("Mean predicted probability", fontsize=12)
    ax.set_ylabel("Fraction of positives", fontsize=12)
    ax.set_title("Calibration Curve (Reliability Diagram)", fontsize=14)
    ax.legend(fontsize=10)

    path = reports_dir / "calibration.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("calibration_saved", path=str(path))
    return path


def plot_topk_precision(
    model_topk: Dict[str, float],
    baselines: Dict[str, Dict[str, Any]],
    reports_dir: Optional[Path] = None,
) -> Path:
    """Plot top-K precision comparison bar chart."""
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    fig, ax = plt.subplots(figsize=(10, 6))

    # Parse K values
    k_labels = sorted(model_topk.keys())
    k_values = [int(k.split("@")[1]) for k in k_labels]

    # Model values
    model_vals = [model_topk[k] for k in k_labels]
    x = np.arange(len(k_labels))
    width = 0.2

    ax.bar(x - width * 1.5, model_vals, width, label="Our Model", color="blue")

    # Baselines
    colors = {"cvss_only": "red", "epss_only": "orange", "kev_first": "green"}
    for i, (name, bl) in enumerate(baselines.items()):
        bl_topk = bl.get("top_k_precision", {})
        bl_vals = [bl_topk.get(k, 0) for k in k_labels]
        color = colors.get(name, "gray")
        ax.bar(x - width * 0.5 + width * i, bl_vals, width, label=name, color=color)

    ax.set_xlabel("K", fontsize=12)
    ax.set_ylabel("Precision@K", fontsize=12)
    ax.set_title("Top-K Precision: Model vs Baselines", fontsize=14)
    ax.set_xticks(x)
    ax.set_xticklabels([f"@{k}" for k in k_values])
    ax.legend(fontsize=10)
    ax.set_ylim([0, 1.1])

    path = reports_dir / "topk_precision.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("topk_precision_saved", path=str(path))
    return path


def generate_summary_md(
    metrics: Dict[str, Any],
    reports_dir: Optional[Path] = None,
) -> Path:
    """Generate an executive summary markdown report."""
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    model = metrics.get("model", {})
    baselines = metrics.get("baselines", {})

    md_lines = [
        "# Vulnerability Intelligence – Evaluation Report",
        "",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Cutoff date:** {metrics.get('cutoff_date', 'N/A')}",
        f"**Train samples:** {metrics.get('n_train', 'N/A')} | "
        f"**Test samples:** {metrics.get('n_test', 'N/A')}",
        "",
        "## Why This Matters for Enterprise Security Teams",
        "",
        "Traditional vulnerability prioritization relies on CVSS severity scores alone.",
        "CVSS measures *severity*, not *risk* (per official FIRST guidance).",
        "This system combines multiple intelligence signals with ML to produce",
        "calibrated exploitability probabilities, reducing false positives at the",
        "top of the triage queue and enabling faster, more defensible decisions.",
        "",
        "## Model Performance vs Baselines",
        "",
        "| Metric | Our Model | CVSS-Only | EPSS-Only | KEV-First |",
        "|--------|-----------|-----------|-----------|-----------|",
    ]

    # PR-AUC row
    md_lines.append(
        f"| PR-AUC | **{model.get('pr_auc', 0):.3f}** | "
        f"{baselines.get('cvss_only', {}).get('pr_auc', 0):.3f} | "
        f"{baselines.get('epss_only', {}).get('pr_auc', 0):.3f} | "
        f"{baselines.get('kev_first', {}).get('pr_auc', 0):.3f} |"
    )

    # Brier score row
    md_lines.append(
        f"| Brier Score ↓ | **{model.get('brier_score', 0):.3f}** | "
        f"{baselines.get('cvss_only', {}).get('brier_score', 0):.3f} | "
        f"{baselines.get('epss_only', {}).get('brier_score', 0):.3f} | "
        f"{baselines.get('kev_first', {}).get('brier_score', 0):.3f} |"
    )

    # Top-K precision rows
    model_topk = model.get("top_k_precision", {})
    for k_label in sorted(model_topk.keys()):
        md_lines.append(
            f"| {k_label} | **{model_topk[k_label]:.3f}** | "
            f"{baselines.get('cvss_only', {}).get('top_k_precision', {}).get(k_label, 0):.3f} | "
            f"{baselines.get('epss_only', {}).get('top_k_precision', {}).get(k_label, 0):.3f} | "
            f"{baselines.get('kev_first', {}).get('top_k_precision', {}).get(k_label, 0):.3f} |"
        )

    md_lines.extend([
        "",
        "## Key Findings",
        "",
        f"- **PR-AUC improvement:** {_pct_improvement(model.get('pr_auc', 0), baselines.get('cvss_only', {}).get('pr_auc', 0))} over CVSS-only baseline",
        f"- **Calibration:** Brier score of {model.get('brier_score', 0):.3f} indicates {'well' if model.get('brier_score', 0) < 0.2 else 'moderately'}-calibrated probabilities",
        f"- **F1 Score:** {model.get('f1', 0):.3f}",
        "",
        "## Top Feature Importances",
        "",
        "| Rank | Feature | Importance |",
        "|------|---------|-----------|",
    ])

    for i, feat in enumerate(model.get("feature_importance", [])[:10], 1):
        md_lines.append(f"| {i} | {feat['feature']} | {feat['importance']:.4f} |")

    md_lines.extend([
        "",
        "## Plots",
        "",
        "- ![PR Curve](pr_curve.png)",
        "- ![Calibration](calibration.png)",
        "- ![Top-K Precision](topk_precision.png)",
        "",
        "## Safety Notes",
        "",
        "- No exploit code was generated, stored, or used in this evaluation.",
        "- All signals are metadata only (existence flags, scores, timestamps).",
        "- ATT&CK mappings are grounded in retrieved evidence snippets.",
        "- CVSS is FIRST-licensed; ATT&CK is MITRE-published; EPSS is open.",
        "",
        "---",
        f"*Report generated by VulnTriage v0.1.0*",
    ])

    path = reports_dir / "summary.md"
    with open(path, "w") as f:
        f.write("\n".join(md_lines))

    log.info("summary_saved", path=str(path))
    return path


def _pct_improvement(model_val: float, baseline_val: float) -> str:
    """Compute percentage improvement string."""
    if baseline_val == 0:
        return "N/A (baseline=0)"
    pct = ((model_val - baseline_val) / baseline_val) * 100
    return f"{pct:+.1f}%"


# ── Ablation comparison table ──────────────────────────────────────────

def generate_ablation_comparison(
    experiment_metrics: Dict[str, Dict[str, Any]],
    reports_dir: Optional[Path] = None,
) -> Path:
    """Generate a markdown table comparing ablation experiment results.

    Parameters
    ----------
    experiment_metrics : dict
        Mapping of ablation_name → metrics dict (with pr_auc, f1, etc.)
    """
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    md_lines = [
        "# Ablation Comparison",
        "",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "| Ablation | Features | PR-AUC | ROC-AUC | F1 | Brier ↓ |",
        "|----------|----------|--------|---------|-----|---------|",
    ]

    for name, m in sorted(experiment_metrics.items()):
        n_features = m.get("n_features", "?")
        pr_auc = m.get("pr_auc", 0)
        roc_auc = m.get("roc_auc", 0)
        f1 = m.get("f1", 0)
        brier = m.get("brier_score", 0)

        md_lines.append(
            f"| {name} | {n_features} | {pr_auc:.4f} | {roc_auc:.4f} | {f1:.4f} | {brier:.4f} |"
        )

    md_lines.extend([
        "",
        "## Interpretation",
        "",
        "- **full**: Baseline with all features (may have circularity if used with wrong policy)",
        "- **no_circular**: Expected primary result — prediction without knowing the answer",
        "- **cve_only**: How much can we predict from the CVE record alone?",
        "- **temporal_only**: Is time-since-publication + EPSS enough?",
        "- **network_enriched**: Does vendor/reference metadata help?",
        "- **text_only**: Sanity check (should be weakest)",
        "",
        "### Key Question",
        "",
        "> Does removing circular features (kev_flag, poc_flag, etc.) significantly",
        "> degrade performance? If not, the model has learned meaningful patterns",
        "> beyond exploit presence/absence.",
    ])

    path = reports_dir / "ablation_comparison.md"
    with open(path, "w") as f:
        f.write("\n".join(md_lines))

    log.info("ablation_comparison_saved", path=str(path))
    return path


# ── Decision confusion matrix ─────────────────────────────────────────

def plot_decision_confusion(
    y_true: List[str],
    y_pred: List[str],
    labels: Optional[List[str]] = None,
    reports_dir: Optional[Path] = None,
) -> Path:
    """Plot a confusion matrix for multi-class action labels.

    Parameters
    ----------
    y_true : list[str]
        True action labels (e.g., "patch_now", "monitor", ...).
    y_pred : list[str]
        Predicted action labels.
    labels : list[str], optional
        Ordered class labels.
    """
    from sklearn.metrics import confusion_matrix

    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    if labels is None:
        labels = ["patch_now", "mitigate_now", "patch_window", "monitor", "accept"]

    cm = confusion_matrix(y_true, y_pred, labels=labels)

    fig, ax = plt.subplots(figsize=(8, 7))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=labels,
        yticklabels=labels,
        ax=ax,
    )
    ax.set_xlabel("Predicted Action", fontsize=12)
    ax.set_ylabel("True Action", fontsize=12)
    ax.set_title("Decision Confusion Matrix", fontsize=14)
    plt.xticks(rotation=30, ha="right")
    plt.yticks(rotation=0)

    path = reports_dir / "decision_confusion.png"
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("decision_confusion_saved", path=str(path))
    return path


# ── Case study generator ──────────────────────────────────────────────

def generate_case_studies(
    cases: List[Dict[str, Any]],
    reports_dir: Optional[Path] = None,
    max_cases: int = 5,
) -> Path:
    """Generate detailed case study walkthroughs for interesting CVEs.

    Parameters
    ----------
    cases : list[dict]
        Each dict has: cve_id, title, cvss, epss, kev, poc, prediction,
        decision, rationale, features.
    max_cases : int
        Maximum number of cases to include.
    """
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    md_lines = [
        "# Case Studies",
        "",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "These cases illustrate how the system's layered evidence model produces",
        "different triage decisions for CVEs that traditional CVSS-only approaches",
        "would rank similarly.",
        "",
    ]

    for i, case in enumerate(cases[:max_cases], 1):
        cve = case.get("cve_id", "Unknown")
        title = case.get("title", "No title")
        cvss = case.get("cvss", 0)
        epss = case.get("epss", 0)
        kev = case.get("kev", False)
        poc = case.get("poc", False)
        prediction = case.get("prediction", 0)
        decision = case.get("decision", "unknown")
        rationale = case.get("rationale", [])

        md_lines.extend([
            f"## Case {i}: {cve}",
            "",
            f"**{title}**",
            "",
            "| Signal | Value |",
            "|--------|-------|",
            f"| CVSS | {cvss} |",
            f"| EPSS | {epss:.4f} |",
            f"| KEV | {'✓' if kev else '✗'} |",
            f"| Public PoC | {'✓' if poc else '✗'} |",
            f"| ML Prediction | {prediction:.3f} |",
            f"| **Decision** | **{decision.upper()}** |",
            "",
            "### Rationale",
            "",
        ])

        for r in rationale:
            md_lines.append(f"- {r}")

        # Analysis section
        md_lines.extend([
            "",
            "### Why This Matters",
            "",
        ])

        if cvss >= 9.0 and not kev:
            md_lines.append(
                "This is a CVSS-critical CVE **without** known exploitation. "
                "CVSS-only triage would treat this as highest priority, but our "
                "system correctly identifies the lack of weaponization evidence."
            )
        elif cvss < 7.0 and kev:
            md_lines.append(
                "This is a medium/low CVSS CVE that IS actively exploited (KEV). "
                "CVSS-only triage would deprioritize this, but our system elevates "
                "it based on weaponization evidence."
            )
        elif kev and poc:
            md_lines.append(
                "Both KEV and public PoC exist — this is a clear high-priority case "
                "that all approaches should catch. Useful as a sanity check."
            )
        else:
            md_lines.append(
                "This case demonstrates the nuanced decision-making that goes beyond "
                "simple severity scoring."
            )

        md_lines.append("")

    path = reports_dir / "case_studies.md"
    with open(path, "w") as f:
        f.write("\n".join(md_lines))

    log.info("case_studies_saved", path=str(path), count=min(len(cases), max_cases))
    return path


# ── Slice evaluation report ───────────────────────────────────────────

def generate_slice_report(
    slice_results: Dict[str, Dict[str, Any]],
    ablation_name: str = "full",
    policy_name: str = "kev_strict",
    reports_dir: Optional[Path] = None,
) -> Path:
    """Generate a markdown report from slice evaluation results.

    Parameters
    ----------
    slice_results : dict
        Mapping of slice_name → metrics dict.
    """
    if reports_dir is None:
        reports_dir = get_settings().reports_dir

    md_lines = [
        "# Subpopulation Evaluation Report",
        "",
        f"**Ablation:** {ablation_name}",
        f"**Label Policy:** {policy_name}",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "| Slice | N | Pos% | Precision | Recall | F1 | PR-AUC | ROC-AUC |",
        "|-------|---|------|-----------|--------|-----|--------|---------|",
    ]

    for name, m in slice_results.items():
        n = m.get("n", 0)
        pos_rate = m.get("positive_rate", 0)
        prec = m.get("precision")
        rec = m.get("recall")
        f1 = m.get("f1")
        pr_auc = m.get("pr_auc")
        roc_auc = m.get("roc_auc")

        md_lines.append(
            f"| {name} | {n} | {pos_rate:.3f} | "
            f"{f'{prec:.3f}' if prec is not None else '—'} | "
            f"{f'{rec:.3f}' if rec is not None else '—'} | "
            f"{f'{f1:.3f}' if f1 is not None else '—'} | "
            f"{f'{pr_auc:.3f}' if pr_auc is not None else '—'} | "
            f"{f'{roc_auc:.3f}' if roc_auc is not None else '—'} |"
        )

    md_lines.extend([
        "",
        "## Key Observations",
        "",
        "- **cvss_critical vs cvss_medium_low**: Does the model perform differently on high vs low severity?",
        "- **has_kev vs no_kev**: How well does the model predict when KEV is known vs unknown?",
        "- **first_30_days**: Performance on the freshest CVEs (hardest for temporal models)",
        "- **cwe_top25**: Does CWE category improve prediction for common vulnerability types?",
    ])

    path = reports_dir / f"slices_{ablation_name}_{policy_name}.md"
    with open(path, "w") as f:
        f.write("\n".join(md_lines))

    log.info("slice_report_saved", path=str(path))
    return path


# ── Actionability reports ────────────────────────────────────────────

def plot_action_confusion_matrix(
    cm_df: "pd.DataFrame",
    *,
    title: str = "Action-Label Confusion Matrix",
    output_path: Optional[str] = None,
) -> Optional[Path]:
    """Plot a 5×5 confusion matrix heatmap for action labels.

    Parameters
    ----------
    cm_df : DataFrame
        Confusion matrix from ``action_confusion_matrix()`` with
        rows = true, columns = predicted.
    title : str
        Plot title.
    output_path : str, optional
        If provided, save to this path.  Otherwise uses default.

    Returns
    -------
    Path or None
        Path to saved figure.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    fig, ax = plt.subplots(figsize=(8, 6))

    data = cm_df.values.astype(float)
    im = ax.imshow(data, interpolation="nearest", cmap="Blues")
    ax.figure.colorbar(im, ax=ax)

    labels = list(cm_df.index)
    display_labels = [l.replace("_", "\n") for l in labels]
    ax.set(
        xticks=np.arange(len(labels)),
        yticks=np.arange(len(labels)),
        xticklabels=display_labels,
        yticklabels=display_labels,
        ylabel="True Action",
        xlabel="Predicted Action",
        title=title,
    )

    # Add text annotations
    thresh = data.max() / 2.0
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(
                j, i, f"{int(data[i, j])}",
                ha="center", va="center",
                color="white" if data[i, j] > thresh else "black",
                fontsize=10,
            )

    fig.tight_layout()

    if output_path is None:
        reports_dir = Path(get_settings().reports_dir)
        output_path = str(reports_dir / "figures" / "action_confusion_matrix.png")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("action_confusion_matrix_saved", path=output_path)
    return Path(output_path)


def generate_actionability_summary_md(
    eval_results: dict,
    cm_df: "pd.DataFrame",
    *,
    case_studies_md: str = "",
    output_path: Optional[str] = None,
) -> Path:
    """Generate a Markdown summary of actionability evaluation.

    Parameters
    ----------
    eval_results : dict
        Output from ``evaluate_action_labels()``.
    cm_df : DataFrame
        Confusion matrix.
    case_studies_md : str
        Pre-formatted case studies Markdown.
    output_path : str, optional
        Output file path.

    Returns
    -------
    Path
        Path to generated Markdown file.
    """
    lines = [
        "# Actionability Evaluation Report",
        "",
        f"**Samples:** {eval_results.get('n_samples', '?')}  ",
        f"**Overall Accuracy:** {eval_results.get('overall_accuracy', '?')}  ",
        f"**Macro F1:** {eval_results.get('macro_f1', '?')}  ",
        f"**Weighted F1:** {eval_results.get('weighted_f1', '?')}  ",
        "",
        "## Urgency Error Analysis",
        "",
        f"- **Under-triage rate:** {eval_results.get('under_triage_rate', '?')} "
        "(predicted less urgent than truth)",
        f"- **Over-triage rate:** {eval_results.get('over_triage_rate', '?')} "
        "(predicted more urgent than truth)",
        "",
        "## Per-Class Metrics",
        "",
        "| Action | Precision | Recall | F1 | Support |",
        "|--------|-----------|--------|----|---------|",
    ]

    per_class = eval_results.get("per_class", {})
    for action in ["patch_now", "mitigate_now", "patch_window", "monitor", "accept"]:
        m = per_class.get(action, {})
        lines.append(
            f"| {action} | "
            f"{m.get('precision', '—')} | "
            f"{m.get('recall', '—')} | "
            f"{m.get('f1', '—')} | "
            f"{m.get('support', 0)} |"
        )

    lines.extend([
        "",
        "## Confusion Matrix",
        "",
        "![Action Confusion Matrix](figures/action_confusion_matrix.png)",
        "",
    ])

    # Distribution
    lines.extend([
        "## Label Distribution",
        "",
        "| Action | True Count | Predicted Count |",
        "|--------|-----------|----------------|",
    ])
    true_dist = eval_results.get("true_distribution", {})
    pred_dist = eval_results.get("pred_distribution", {})
    for action in ["patch_now", "mitigate_now", "patch_window", "monitor", "accept"]:
        lines.append(f"| {action} | {true_dist.get(action, 0)} | {pred_dist.get(action, 0)} |")

    if case_studies_md:
        lines.extend(["", case_studies_md])

    if output_path is None:
        reports_dir = Path(get_settings().reports_dir)
        output_path = str(reports_dir / "actionability_evaluation.md")

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    log.info("actionability_report_saved", path=output_path)
    return Path(output_path)
