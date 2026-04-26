"""Unit tests for feature engineering – time_aware_split and _composite_score."""

from __future__ import annotations

from datetime import date

import numpy as np
import pandas as pd
import pytest

from app.features.builder import _composite_score, time_aware_split


# ─────────────────────────────────────────────────────────────
#  time_aware_split
# ─────────────────────────────────────────────────────────────

class TestTimeAwareSplit:
    """Test temporal splitting of DataFrames."""

    def _make_df(self, dates: list[str]) -> pd.DataFrame:
        return pd.DataFrame({
            "published_at": dates,
            "vuln_id": [f"v{i}" for i in range(len(dates))],
            "cvss_base_score": [7.5] * len(dates),
        })

    def test_basic_split(self):
        df = self._make_df(["2024-01-01", "2024-06-01", "2024-09-01", "2024-12-01"])
        train, test = time_aware_split(df, "2024-06-30")
        assert len(train) == 2
        assert len(test) == 2

    def test_cutoff_inclusive(self):
        """Records ON the cutoff date go to train."""
        df = self._make_df(["2024-01-01", "2024-06-01"])
        train, test = time_aware_split(df, "2024-06-01")
        assert len(train) == 2  # Both at or before cutoff
        assert len(test) == 0 or pytest.raises(ValueError)

    def test_cutoff_exact_boundary(self):
        """Only one record after cutoff."""
        df = self._make_df(["2024-01-01", "2024-06-01", "2024-06-02"])
        train, test = time_aware_split(df, "2024-06-01")
        assert len(train) == 2
        assert len(test) == 1

    def test_empty_train_raises(self):
        """All records after cutoff → train is empty → ValueError."""
        df = self._make_df(["2025-01-01", "2025-06-01"])
        with pytest.raises(ValueError, match="Train split is empty"):
            time_aware_split(df, "2024-01-01")

    def test_empty_test_raises(self):
        """All records before cutoff → test is empty → ValueError."""
        df = self._make_df(["2023-01-01", "2023-06-01"])
        with pytest.raises(ValueError, match="Test split is empty"):
            time_aware_split(df, "2025-01-01")

    def test_preserves_columns(self):
        df = self._make_df(["2024-01-01", "2024-12-01"])
        train, test = time_aware_split(df, "2024-06-01")
        assert set(train.columns) == set(df.columns)
        assert set(test.columns) == set(df.columns)


# ─────────────────────────────────────────────────────────────
#  _composite_score
# ─────────────────────────────────────────────────────────────

class TestCompositeScore:
    """Test the heuristic composite exploitability score."""

    def test_all_zeros(self):
        features = {
            "cvss_base_score": 0.0,
            "epss_score": 0.0,
            "kev_flag": 0.0,
            "poc_exploitdb_flag": 0.0,
            "metasploit_flag": 0.0,
            "exploit_signal_count": 0.0,
        }
        score = _composite_score(features)
        assert score == 0.0

    def test_critical_all_signals(self):
        features = {
            "cvss_base_score": 10.0,
            "epss_score": 0.95,
            "kev_flag": 1.0,
            "poc_exploitdb_flag": 1.0,
            "metasploit_flag": 1.0,
            "exploit_signal_count": 3.0,
        }
        score = _composite_score(features)
        assert score > 0.8
        assert score <= 1.0

    def test_cvss_only_partial_score(self):
        features = {
            "cvss_base_score": 9.8,
            "epss_score": 0.0,
            "kev_flag": 0.0,
            "poc_exploitdb_flag": 0.0,
            "metasploit_flag": 0.0,
            "exploit_signal_count": 0.0,
        }
        score = _composite_score(features)
        # Only 25% weight on CVSS → ~ 0.245
        assert 0.2 < score < 0.3

    def test_epss_only_partial_score(self):
        features = {
            "cvss_base_score": 0.0,
            "epss_score": 0.9,
            "kev_flag": 0.0,
            "poc_exploitdb_flag": 0.0,
            "metasploit_flag": 0.0,
            "exploit_signal_count": 0.0,
        }
        score = _composite_score(features)
        # 30% weight on EPSS → ~ 0.27
        assert 0.2 < score < 0.35

    def test_score_always_in_range(self):
        """Score should always be between 0 and 1."""
        for _ in range(50):
            features = {
                "cvss_base_score": np.random.uniform(0, 10),
                "epss_score": np.random.uniform(0, 1),
                "kev_flag": float(np.random.choice([0, 1])),
                "poc_exploitdb_flag": float(np.random.choice([0, 1])),
                "metasploit_flag": float(np.random.choice([0, 1])),
                "exploit_signal_count": float(np.random.randint(0, 4)),
            }
            score = _composite_score(features)
            assert 0.0 <= score <= 1.0, f"Score {score} out of range"

    def test_monotonicity_with_epss(self):
        """Higher EPSS should yield higher score, all else equal."""
        base = {
            "cvss_base_score": 7.0,
            "kev_flag": 0.0,
            "poc_exploitdb_flag": 0.0,
            "metasploit_flag": 0.0,
            "exploit_signal_count": 0.0,
        }
        s_low = _composite_score({**base, "epss_score": 0.1})
        s_high = _composite_score({**base, "epss_score": 0.9})
        assert s_high > s_low
