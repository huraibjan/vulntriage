"""Stacking ensemble: combine Stage 1 (tabular) + Stage 2 (text) probabilities.

Uses scikit-learn CalibratedClassifierCV for probability calibration
to ensure the final output is well-calibrated for enterprise decision making.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss

from app.core.logging import get_logger
from app.core.settings import get_settings

log = get_logger(__name__)


class StackingEnsemble:
    """Combine tabular and text model probabilities with calibration.

    The stacking layer is a lightweight logistic regression that learns
    the optimal weighting of Stage 1 and Stage 2 outputs.
    """

    def __init__(self, calibration_method: str = "sigmoid") -> None:
        """
        Args:
            calibration_method: 'sigmoid' (Platt) or 'isotonic'
        """
        self.calibration_method = calibration_method
        self._meta_model: Optional[LogisticRegression] = None
        self._calibrator: Optional[CalibratedClassifierCV] = None

    def fit(
        self,
        p_stage1: np.ndarray,
        p_stage2: np.ndarray,
        y_true: np.ndarray,
    ) -> Dict[str, Any]:
        """Fit the stacking meta-learner + calibrator.

        Args:
            p_stage1: Probabilities from tabular model (n_samples,)
            p_stage2: Probabilities from text model (n_samples,)
            y_true:   Ground truth labels (n_samples,)

        Returns:
            Training metrics dict.
        """
        X_meta = np.column_stack([p_stage1, p_stage2])

        # Fit meta learner
        self._meta_model = LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        )
        self._meta_model.fit(X_meta, y_true)

        # Calibrate
        self._calibrator = CalibratedClassifierCV(
            self._meta_model,
            method=self.calibration_method,
            cv=min(3, max(2, len(y_true) // 5)),
        )
        self._calibrator.fit(X_meta, y_true)

        # Training metrics
        p_final = self._calibrator.predict_proba(X_meta)[:, 1]
        metrics = {
            "calibration_method": self.calibration_method,
            "train_brier": float(brier_score_loss(y_true, p_final)),
            "train_pr_auc": float(average_precision_score(y_true, p_final)),
            "meta_coefs": self._meta_model.coef_.tolist(),
        }

        log.info("stacking_trained", **metrics)
        return metrics

    def predict(
        self,
        p_stage1: np.ndarray,
        p_stage2: np.ndarray,
    ) -> np.ndarray:
        """Produce calibrated final probabilities.

        Args:
            p_stage1: Tabular model probabilities
            p_stage2: Text model probabilities

        Returns:
            Calibrated probability array (n_samples,)
        """
        if self._calibrator is None:
            # Fallback: simple average
            log.warning("stacking_not_fitted", msg="Using simple average")
            return (p_stage1 + p_stage2) / 2.0

        X_meta = np.column_stack([p_stage1, p_stage2])
        return self._calibrator.predict_proba(X_meta)[:, 1]

    def predict_single(self, p1: float, p2: float) -> float:
        """Predict for a single vulnerability."""
        p1_arr = np.array([p1])
        p2_arr = np.array([p2])
        return float(self.predict(p1_arr, p2_arr)[0])

    def evaluate(
        self,
        p_stage1: np.ndarray,
        p_stage2: np.ndarray,
        y_true: np.ndarray,
    ) -> Dict[str, Any]:
        """Evaluate the stacking ensemble on test data."""
        p_final = self.predict(p_stage1, p_stage2)

        metrics: Dict[str, Any] = {
            "brier_score": float(brier_score_loss(y_true, p_final)),
        }

        try:
            metrics["pr_auc"] = float(average_precision_score(y_true, p_final))
        except ValueError:
            metrics["pr_auc"] = 0.0

        # Calibration curve data (for plotting)
        try:
            prob_true, prob_pred = calibration_curve(y_true, p_final, n_bins=5)
            metrics["calibration_curve"] = {
                "prob_true": prob_true.tolist(),
                "prob_pred": prob_pred.tolist(),
            }
        except ValueError:
            metrics["calibration_curve"] = {"prob_true": [], "prob_pred": []}

        return metrics

    def save(self, path: Optional[Path] = None) -> Path:
        """Save the stacking ensemble to disk."""
        if path is None:
            path = get_settings().models_dir / "stacking_ensemble.joblib"
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "meta_model": self._meta_model,
            "calibrator": self._calibrator,
            "calibration_method": self.calibration_method,
        }, path)
        log.info("stacking_saved", path=str(path))
        return path

    def load(self, path: Optional[Path] = None) -> None:
        """Load a saved stacking ensemble."""
        if path is None:
            path = get_settings().models_dir / "stacking_ensemble.joblib"
        data = joblib.load(path)
        self._meta_model = data["meta_model"]
        self._calibrator = data["calibrator"]
        self.calibration_method = data["calibration_method"]
        log.info("stacking_loaded", path=str(path))
