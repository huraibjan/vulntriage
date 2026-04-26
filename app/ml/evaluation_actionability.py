"""Actionability evaluation — 5-class action-label metrics for thesis.

Computes evaluation metrics specific to the actionability layer:
- 5×5 confusion matrix (PATCH_NOW, MITIGATE_NOW, PATCH_WINDOW, MONITOR, ACCEPT)
- Per-class precision, recall, F1
- Decision agreement rate (predicted vs. ground-truth action)
- SLA compliance simulation
- Case study generation (representative decision traces)

Usage
-----
::

    from app.ml.evaluation_actionability import (
        evaluate_action_labels,
        action_confusion_matrix,
        generate_case_studies,
    )

    results = evaluate_action_labels(y_true_actions, y_pred_actions)
    cm = action_confusion_matrix(y_true_actions, y_pred_actions)
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from app.core.logging import get_logger
from app.schemas.decision import Action, SLA_HOURS

log = get_logger(__name__)

# Ordered action labels (most urgent → least urgent)
ACTION_ORDER: List[str] = [
    "patch_now",
    "mitigate_now",
    "patch_window",
    "monitor",
    "accept",
]

ACTION_DISPLAY: Dict[str, str] = {
    "patch_now": "Patch Now",
    "mitigate_now": "Mitigate Now",
    "patch_window": "Patch Window",
    "monitor": "Monitor",
    "accept": "Accept",
}


def evaluate_action_labels(
    y_true: List[str],
    y_pred: List[str],
    *,
    confidence_scores: Optional[List[float]] = None,
) -> Dict[str, Any]:
    """Compute comprehensive metrics for action-label classification.

    Parameters
    ----------
    y_true : list[str]
        Ground-truth action labels (from decision engine or human review).
    y_pred : list[str]
        Predicted action labels.
    confidence_scores : list[float], optional
        Confidence scores for predicted decisions.

    Returns
    -------
    dict
        Comprehensive evaluation results.
    """
    assert len(y_true) == len(y_pred), "y_true and y_pred must have same length"

    n = len(y_true)
    results: Dict[str, Any] = {
        "n_samples": n,
        "n_classes": len(ACTION_ORDER),
    }

    # ── Overall accuracy ─────────────────────────────────────────────
    exact_match = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    results["overall_accuracy"] = round(exact_match / max(n, 1), 4)

    # ── Per-class metrics ────────────────────────────────────────────
    per_class: Dict[str, Dict[str, Any]] = {}
    for action in ACTION_ORDER:
        tp = sum(1 for t, p in zip(y_true, y_pred) if t == action and p == action)
        fp = sum(1 for t, p in zip(y_true, y_pred) if t != action and p == action)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t == action and p != action)
        tn = n - tp - fp - fn

        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-8)
        support = tp + fn

        per_class[action] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }

    results["per_class"] = per_class

    # ── Macro and weighted averages ──────────────────────────────────
    classes_with_support = [a for a in ACTION_ORDER if per_class[a]["support"] > 0]
    if classes_with_support:
        results["macro_precision"] = round(
            np.mean([per_class[a]["precision"] for a in classes_with_support]), 4
        )
        results["macro_recall"] = round(
            np.mean([per_class[a]["recall"] for a in classes_with_support]), 4
        )
        results["macro_f1"] = round(
            np.mean([per_class[a]["f1"] for a in classes_with_support]), 4
        )

        total_support = sum(per_class[a]["support"] for a in classes_with_support)
        results["weighted_f1"] = round(
            sum(per_class[a]["f1"] * per_class[a]["support"] / total_support
                for a in classes_with_support), 4
        )

    # ── Distribution ─────────────────────────────────────────────────
    results["true_distribution"] = dict(Counter(y_true))
    results["pred_distribution"] = dict(Counter(y_pred))

    # ── Urgency error analysis ───────────────────────────────────────
    # How often do we under-triage (predict less urgent than truth)?
    urgency_map = {a: i for i, a in enumerate(ACTION_ORDER)}
    under_triage = 0
    over_triage = 0
    for t, p in zip(y_true, y_pred):
        t_urg = urgency_map.get(t, 2)
        p_urg = urgency_map.get(p, 2)
        if p_urg > t_urg:  # predicted less urgent
            under_triage += 1
        elif p_urg < t_urg:  # predicted more urgent
            over_triage += 1

    results["under_triage_rate"] = round(under_triage / max(n, 1), 4)
    results["over_triage_rate"] = round(over_triage / max(n, 1), 4)
    results["urgency_error_analysis"] = {
        "under_triage_count": under_triage,
        "over_triage_count": over_triage,
        "exact_match_count": exact_match,
    }

    # ── Confidence analysis ──────────────────────────────────────────
    if confidence_scores is not None:
        correct_conf = [c for c, t, p in zip(confidence_scores, y_true, y_pred) if t == p]
        wrong_conf = [c for c, t, p in zip(confidence_scores, y_true, y_pred) if t != p]
        results["confidence_analysis"] = {
            "correct_mean": round(float(np.mean(correct_conf)), 4) if correct_conf else None,
            "wrong_mean": round(float(np.mean(wrong_conf)), 4) if wrong_conf else None,
            "correct_std": round(float(np.std(correct_conf)), 4) if correct_conf else None,
            "wrong_std": round(float(np.std(wrong_conf)), 4) if wrong_conf else None,
        }

    return results


def action_confusion_matrix(
    y_true: List[str],
    y_pred: List[str],
) -> pd.DataFrame:
    """Build a 5×5 confusion matrix for action labels.

    Returns
    -------
    DataFrame
        Rows = true label, columns = predicted label.
    """
    matrix = pd.DataFrame(
        0,
        index=ACTION_ORDER,
        columns=ACTION_ORDER,
    )

    for t, p in zip(y_true, y_pred):
        if t in ACTION_ORDER and p in ACTION_ORDER:
            matrix.loc[t, p] += 1

    return matrix


def sla_compliance_analysis(
    decisions_df: pd.DataFrame,
    *,
    action_col: str = "action",
    decided_at_col: str = "decided_at",
    resolved_at_col: str = "resolved_at",
) -> Dict[str, Any]:
    """Simulate SLA compliance from decision timestamps.

    Parameters
    ----------
    decisions_df : DataFrame
        Must contain action, decided_at, and resolved_at columns.

    Returns
    -------
    dict
        SLA compliance rates per action category.
    """
    if resolved_at_col not in decisions_df.columns:
        return {"note": "No resolution timestamps available for SLA analysis"}

    decisions_df = decisions_df.copy()
    decisions_df[decided_at_col] = pd.to_datetime(decisions_df[decided_at_col])
    decisions_df[resolved_at_col] = pd.to_datetime(decisions_df[resolved_at_col])

    results: Dict[str, Any] = {}

    for action in ACTION_ORDER:
        mask = decisions_df[action_col] == action
        subset = decisions_df[mask]
        if len(subset) == 0:
            continue

        sla_hours = SLA_HOURS.get(action, SLA_HOURS.get(Action(action), 720))
        resolution_hours = (
            (subset[resolved_at_col] - subset[decided_at_col])
            .dt.total_seconds() / 3600
        )

        compliant = (resolution_hours <= sla_hours).sum()
        results[action] = {
            "total": len(subset),
            "compliant": int(compliant),
            "compliance_rate": round(compliant / len(subset), 4),
            "sla_hours": sla_hours,
            "mean_resolution_hours": round(float(resolution_hours.mean()), 1),
            "median_resolution_hours": round(float(resolution_hours.median()), 1),
        }

    return results


def generate_case_studies(
    decisions_df: pd.DataFrame,
    *,
    n_per_action: int = 1,
    action_col: str = "action",
    confidence_col: str = "confidence",
) -> List[Dict[str, Any]]:
    """Select representative case studies for thesis presentation.

    Picks the highest-confidence decision for each action category
    to illustrate the decision engine's behavior.

    Parameters
    ----------
    decisions_df : DataFrame
        Decision results with evidence chains.
    n_per_action : int
        Number of case studies per action category.

    Returns
    -------
    list[dict]
        Case study records for narrative presentation.
    """
    cases: List[Dict[str, Any]] = []

    for action in ACTION_ORDER:
        mask = decisions_df[action_col] == action
        subset = decisions_df[mask]

        if len(subset) == 0:
            continue

        # Pick highest-confidence examples
        if confidence_col in subset.columns:
            subset = subset.sort_values(confidence_col, ascending=False)

        selected = subset.head(n_per_action)

        for _, row in selected.iterrows():
            case = {
                "action": action,
                "action_display": ACTION_DISPLAY.get(action, action),
            }
            # Include all available columns
            for col in row.index:
                val = row[col]
                if isinstance(val, (np.integer, np.floating)):
                    val = round(float(val), 4) if isinstance(val, np.floating) else int(val)
                case[col] = val
            cases.append(case)

    log.info("case_studies_generated", total=len(cases))
    return cases


def generate_case_studies_md(
    cases: List[Dict[str, Any]],
) -> str:
    """Format case studies as a Markdown section for the thesis.

    Returns
    -------
    str
        Markdown-formatted case study text.
    """
    lines = ["## Case Studies\n"]

    for i, case in enumerate(cases, 1):
        action = case.get("action_display", case.get("action", "?"))
        cve_id = case.get("cve_id", "Unknown")
        asset_name = case.get("asset_name", "Unknown Asset")
        confidence = case.get("confidence", "?")

        lines.append(f"### Case {i}: {cve_id} × {asset_name}\n")
        lines.append(f"**Decision:** {action}  ")
        lines.append(f"**Confidence:** {confidence}  \n")

        # Evidence summary
        evidence = case.get("evidence_chain_json") or case.get("evidence_summary")
        if evidence and isinstance(evidence, dict):
            lines.append("**Evidence Chain:**\n")
            for layer, details in evidence.items():
                lines.append(f"- **{layer.title()}**: {details}")
            lines.append("")

        # Rationale
        rationale = case.get("rationale")
        if rationale:
            if isinstance(rationale, list):
                lines.append("**Rationale:**\n")
                for r in rationale:
                    lines.append(f"- {r}")
            else:
                lines.append(f"**Rationale:** {rationale}")
            lines.append("")

        lines.append("---\n")

    return "\n".join(lines)
