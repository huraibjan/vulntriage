"""Run the offline self-checks of the post-paper experiment scripts under pytest."""

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.mark.parametrize("module, func", [
    ("experiments.ctid_attack_eval", "selftest"),
    ("experiments.lev_baseline", "self_test"),
])
def test_experiment_selftest(module, func):
    getattr(importlib.import_module(module), func)()
