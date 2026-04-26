"""Advanced stacking ensemble: combine N probability sources.

Upgrades over the original 2-source stacking:

1. **N-way stacking** – Combine tabular, text, EPSS, or any number of
   probability streams.
2. **Multiple meta-learners** – Logistic Regression (multiple C values)
   and a small GBM meta-learner are all tried; the best on held-out CV
   is selected.
3. **Probability calibration** – Platt / isotonic calibration applied
   after meta-learning.
4. **Comprehensive evaluation** – PR-AUC, ROC-AUC, Brier, P@K, and
   calibration diagnostics.

Architecture
------------
::

    [p_tabular, p_text, p_epss, …]   ← N probability streams
                │
        ┌───────▼───────┐
        │  Meta-learner │   (LR / GBM – selected by CV)
        └───────┬───────┘
                │
        ┌───────▼───────┐
        │  Calibrator   │   (Platt sigmoid / isotonic)
        └───────┬───────┘
                │
            p_final         ← calibrated exploit probability
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)


class StackingEnsemble:
    """N-way stacking ensemble with meta-learner selection and calibration.

    Usage::

        ens = StackingEnsemble()
        # p_sources: dict mapping name → probability array
        ens.fit(
            p_sources={"tabular": p_tab, "text": p_txt, "epss": p_epss},
            y_true=y_train,
        )
        p_final = ens.predict({"tabular": p_tab_test, "text": p_txt_test, "epss": p_epss_test})
    """

    def __init__(
        self,
        calibration_method: str = "sigmoid",
        random_state: int = 42,
    ) -> None:
        self.calibration_method = calibration_method
        self.random_state = random_state

        self._meta_model = None
        self._meta_name: Optional[str] = None
        self._calibrator = None
        self._scaler: Optional[StandardScaler] = None
        self._source_names: List[str] = []
        self._fit_metrics: Dict[str, Any] = {}

    # ── Building the meta-feature matrix ────────────────────────────────

    def _build_X(self, p_sources: Dict[str, np.ndarray]) -> np.ndarray:
        """Stack probability arrays into a meta-feature matrix.

        Also adds interaction features: pairwise products and max/mean.
        """
        names = sorted(p_sources.keys())
        arrays = [p_sources[n].ravel() for n in names]
        base = np.column_stack(arrays)

        # Interaction features: all pairwise products
        interactions = []
        for i in range(len(arrays)):
            for j in range(i + 1, len(arrays)):
                interactions.append(arrays[i] * arrays[j])

        # Aggregate features
        row_max = np.max(base, axis=1, keepdims=True)
        row_mean = np.mean(base, axis=1, keepdims=True)
        row_std = np.std(base, axis=1, keepdims=True)

        parts = [base, row_max, row_mean, row_std]
        if interactions:
            parts.append(np.column_stack(interactions))

        return np.hstack(parts)

    # ── Fit ─────────────────────────────────────────────────────────────

    def fit(
        self,
        p_sources: Dict[str, np.ndarray],
        y_true: np.ndarray,
    ) -> Dict[str, Any]:
        """Fit the best meta-learner + calibrator on training probabilities.

        Tries multiple meta-learners and picks the one with best
        cross-validated PR-AUC.
        """
        self._source_names = sorted(p_sources.keys())
        X_meta = self._build_X(p_sources)
        y = np.asarray(y_true).ravel()

        # Standardise meta-features
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X_meta)

        # Candidate meta-learners
        candidates = {
            "logistic": LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                C=1.0,
                random_state=self.random_state,
            ),
            "logistic_C10": LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                C=10.0,
                random_state=self.random_state,
            ),
            "logistic_C01": LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                C=0.1,
                random_state=self.random_state,
            ),
            "gbm_meta": GradientBoostingClassifier(
                n_estimators=50,
                max_depth=2,
                learning_rate=0.1,
                subsample=0.8,
                random_state=self.random_state,
            ),
        }

        # Cross-validate each candidate
        n_pos = int(y.sum())
        cv_folds = min(5, max(2, n_pos // 3))
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)

        best_name = None
        best_score = -1.0
        cv_results = {}

        for name, clf in candidates.items():
            try:
                scores = cross_val_score(
                    clf, X_scaled, y,
                    cv=cv,
                    scoring="average_precision",
                    n_jobs=1,
                )
                mean_score = float(scores.mean())
                cv_results[name] = {
                    "mean_pr_auc": round(mean_score, 4),
                    "std": round(float(scores.std()), 4),
                }
                if mean_score > best_score:
                    best_score = mean_score
                    best_name = name
            except Exception as e:
                log.warning("meta_cv_failed", name=name, error=str(e))
                cv_results[name] = {"error": str(e)}

        log.info("meta_selection", best=best_name, score=round(best_score, 4))

        # Refit best model on all training data
        self._meta_name = best_name
        self._meta_model = candidates[best_name]
        self._meta_model.fit(X_scaled, y)

        # Calibrate
        try:
            self._calibrator = CalibratedClassifierCV(
                self._meta_model,
                method=self.calibration_method,
                cv=min(cv_folds, 3),
            )
            self._calibrator.fit(X_scaled, y)
        except Exception as e:
            log.warning("calibration_failed", error=str(e))
            self._calibrator = None

        # Training metrics
        p_raw = self._meta_model.predict_proba(X_scaled)[:, 1]
        p_cal = self._calibrator.predict_proba(X_scaled)[:, 1] if self._calibrator else p_raw

        # Extract meta coefficients if logistic
        meta_coefs = None
        if hasattr(self._meta_model, "coef_"):
            meta_coefs = self._meta_model.coef_.tolist()

        self._fit_metrics = {
            "meta_learner": best_name,
            "cv_pr_auc": round(best_score, 4),
            "cv_results": cv_results,
            "train_pr_auc_raw": round(float(average_precision_score(y, p_raw)), 4),
            "train_pr_auc_cal": round(float(average_precision_score(y, p_cal)), 4),
            "train_brier_raw": round(float(brier_score_loss(y, p_raw)), 4),
            "train_brier_cal": round(float(brier_score_loss(y, p_cal)), 4),
            "meta_coefs": meta_coefs,
            "source_names": self._source_names,
            "n_meta_features": X_scaled.shape[1],
            "calibration_method": self.calibration_method,
        }

        return self._fit_metrics

    # ── Predict ─────────────────────────────────────────────────────────

    def predict(self, p_sources: Dict[str, np.ndarray]) -> np.ndarray:
        """Produce calibrated final probabilities."""
        if self._meta_model is None:
            raise RuntimeError("Must call fit() first")

        X_meta = self._build_X(p_sources)
        X_scaled = self._scaler.transform(X_meta)

        if self._calibrator is not None:
            return self._calibrator.predict_proba(X_scaled)[:, 1]
        return self._meta_model.predict_proba(X_scaled)[:, 1]

    def predict_single(self, p_sources: Dict[str, float]) -> float:
        """Predict for a single vulnerability."""
        arrays = {k: np.array([v]) for k, v in p_sources.items()}
        return float(self.predict(arrays)[0])

    # ── Evaluate ────────────────────────────────────────────────────────

    def evaluate(
        self,
        p_sources: Dict[str, np.ndarray],
        y_true: np.ndarray,
        *,
        top_k_values: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Comprehensive evaluation on test data."""
        if top_k_values is None:
            top_k_values = get_settings().top_k_list

        p_final = self.predict(p_sources)
        y = np.asarray(y_true).ravel()
        y_pred = (p_final >= 0.5).astype(int)

        metrics: Dict[str, Any] = {
            "meta_learner": self._meta_name,
            "source_names": self._source_names,
            "brier_score": round(float(brier_score_loss(y, p_final)), 4),
            "f1": round(float(f1_score(y, y_pred, zero_division=0)), 4),
        }

        try:
            metrics["pr_auc"] = round(float(average_precision_score(y, p_final)), 4)
        except ValueError:
            metrics["pr_auc"] = 0.0

        try:
            metrics["roc_auc"] = round(float(roc_auc_score(y, p_final)), 4)
        except ValueError:
            metrics["roc_auc"] = 0.0

        # Top-K
        ranked = np.argsort(-p_final)
        total_pos = int(y.sum())
        top_k_precision = {}
        top_k_recall = {}
        for k in top_k_values:
            k_actual = min(k, len(y))
            hits = int(y[ranked[:k_actual]].sum())
            top_k_precision[f"precision@{k}"] = round(hits / k_actual, 4) if k_actual > 0 else 0.0
            top_k_recall[f"recall@{k}"] = round(hits / total_pos, 4) if total_pos > 0 else 0.0
        metrics["top_k_precision"] = top_k_precision
        metrics["top_k_recall"] = top_k_recall

        # Calibration curve
        try:
            prob_true, prob_pred = calibration_curve(y, p_final, n_bins=10, strategy="quantile")
            metrics["calibration_curve"] = {
                "prob_true": prob_true.tolist(),
                "prob_pred": prob_pred.tolist(),
            }
        except ValueError:
            metrics["calibration_curve"] = None

        return metrics

    # ── Backward compatibility: 2-source interface ──────────────────────

    def fit_two(
        self,
        p_stage1: np.ndarray,
        p_stage2: np.ndarray,
        y_true: np.ndarray,
    ) -> Dict[str, Any]:
        """Legacy 2-source fit (tabular + text)."""
        return self.fit(
            p_sources={"tabular": p_stage1, "text": p_stage2},
            y_true=y_true,
        )

    def predict_two(self, p_stage1: np.ndarray, p_stage2: np.ndarray) -> np.ndarray:
        """Legacy 2-source predict."""
        return self.predict({"tabular": p_stage1, "text": p_stage2})

    # ── Persistence ─────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> Path:
        """Save the stacking ensemble to disk."""
        if path is None:
            path = get_settings().models_dir / "stacking_ensemble.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)

        joblib.dump({
            "meta_model": self._meta_model,
            "meta_name": self._meta_name,
            "calibrator": self._calibrator,
            "scaler": self._scaler,
            "calibration_method": self.calibration_method,
            "source_names": self._source_names,
            "fit_metrics": self._fit_metrics,
        }, path)
        log.info("stacking_saved", path=str(path))
        return path

    def load(self, path: Optional[Path] = None) -> "StackingEnsemble":
        """Load a saved stacking ensemble."""
        if path is None:
            path = get_settings().models_dir / "stacking_ensemble.joblib"

        data = joblib.load(path)
        self._meta_model = data["meta_model"]
        self._meta_name = data.get("meta_name", "logistic")
        self._calibrator = data.get("calibrator")
        self._scaler = data.get("scaler")
        self.calibration_method = data.get("calibration_method", "sigmoid")
        self._source_names = data.get("source_names", ["tabular", "text"])
        self._fit_metrics = data.get("fit_metrics", {})
        log.info("stacking_loaded", path=str(path))
        return self
