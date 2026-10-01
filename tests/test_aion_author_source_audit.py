"""Read-only checks of differences in the author's two filtering paths."""

import ast
from pathlib import Path

import numpy as np
import pytest


def original_mmf():
    source = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/SA_Aggregator.py"
    if not source.exists():
        pytest.skip("author source required")
    tree = ast.parse(source.read_text())
    role = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SA_AggregatorAgent")
    method = next(n for n in role.body if isinstance(n, ast.FunctionDef) and n.name == "MMF")
    module = ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[]))
    namespace = {"np": np}
    exec(compile(module, str(source), "exec"), namespace)
    return namespace["MMF"]


def test_original_asr_mmf_default_first_round_bootstraps_without_norm_history():
    method = original_mmf()
    updates = {i: np.ones(3) * 0.1 for i in range(20)}
    selected, bound = method(None, updates, [], 0.1, 0.05, 0.2, 1)
    assert bound == np.linalg.norm(updates[0])
    assert len(selected) == 16


def test_original_asr_mmf_uses_thirty_percent_and_inclusive_threshold():
    method = original_mmf()
    updates = {i: np.ones(3) * (i + 1) * 0.1 for i in range(20)}
    selected, bound = method(None, updates, [], 0.1, 0.05, 0.2, 1)
    assert bound == np.linalg.norm(updates[6])
    assert selected == list(range(7))


def test_original_asr_mmf_fourth_round_uses_same_old_mask_norm_in_ratio():
    method = original_mmf()
    updates = {i: np.ones(3) * 0.1 for i in range(20)}
    _, bound = method(None, updates, [1.0, 2.0], 0.1, 0.05, 0.2, 4)
    assert bound == (2.0 + 0.05) / (1.0 + 0.05) * 0.2


def test_original_large_ring_norm_can_ignore_maximum_learning_perturbation():
    """Public synthetic keys: correct integer recovery does not fix MMF scale.

    This is one concrete transcript, not a claim for all seeds or gradients.
    """
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    source = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not source.exists():
        pytest.skip("author source required")
    hprf = OriginalAionHPRF.from_directory(source)
    masked = {i: np.asarray(hprf.hprf(101 * (i + 1), 1, 8), dtype=np.float64)
              for i in range(10)}
    # Source learning settings: max_abs=100, decimals=6, padding=100.
    changed = {i: row.copy() for i, row in masked.items()}
    changed[0] += 100 * 10**6 * 100
    method = original_mmf()
    baseline, _ = method(None, masked, [], 0.1, 0.05, 0.2, 1)
    attacked, _ = method(None, changed, [], 0.1, 0.05, 0.2, 1)
    assert baseline == attacked
    delta = abs(np.linalg.norm(changed[0]) - np.linalg.norm(masked[0]))
    assert delta / np.linalg.norm(masked[0]) < 1e-8
