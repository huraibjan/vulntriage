"""Regression tests: the leakage-safe model is the universal default, and the
retrospective leaky (circular) model cannot be selected silently.

These guard the fix from Phase 4 (IEEE revision-2): inference must never default
to `xgb_kev_strict_full.joblib`, which includes exploit-signal features and reads
the KEV label off its own input.
"""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from app.ml.tabular import train as T


def test_default_model_is_leakage_safe():
    assert T.DEFAULT_MODEL == T.LEAKAGE_SAFE_MODEL == "xgb_tuned_tabular_v2.joblib"
    assert T.RETROSPECTIVE_LEAKY_MODEL == "xgb_kev_strict_full.joblib"
    assert T.DEFAULT_MODEL != T.RETROSPECTIVE_LEAKY_MODEL


def test_load_model_default_path_resolves_to_leakage_safe(tmp_path):
    """load_model() with no args must target the leakage-safe file, never leaky."""
    captured = {}

    def fake_joblib_load(path):
        captured["path"] = Path(path)
        return object()

    with mock.patch.object(T, "joblib") as mj, \
            mock.patch.object(T, "get_settings") as gs:
        gs.return_value.models_dir = tmp_path
        mj.load.side_effect = fake_joblib_load
        T.load_model()
    assert captured["path"].name == "xgb_tuned_tabular_v2.joblib"


def test_load_leaky_model_refused_without_flag(tmp_path):
    leaky = tmp_path / T.RETROSPECTIVE_LEAKY_MODEL
    with mock.patch.object(T, "get_settings") as gs:
        gs.return_value.models_dir = tmp_path
        with pytest.raises(ValueError, match="retrospective LEAKY model"):
            T.load_model(leaky)                       # no allow flag → refused


def test_load_leaky_model_allowed_with_explicit_flag(tmp_path):
    leaky = tmp_path / T.RETROSPECTIVE_LEAKY_MODEL
    with mock.patch.object(T, "joblib") as mj, \
            mock.patch.object(T, "get_settings") as gs:
        gs.return_value.models_dir = tmp_path
        mj.load.return_value = object()
        # must not raise when the diagnostic flag is passed
        T.load_model(leaky, allow_retrospective_leaky=True)


def test_metadata_flags_leakage_mode():
    safe = T.model_metadata(Path("x/xgb_tuned_tabular_v2.joblib"))
    leaky = T.model_metadata(Path("x/xgb_kev_strict_full.joblib"))
    assert safe["leakage_safe"] is True and safe["model_mode"] == "leakage_safe"
    assert leaky["leakage_safe"] is False and leaky["model_mode"] == "retrospective_leaky"
    assert "CIRCULAR" in leaky["feature_policy"]
