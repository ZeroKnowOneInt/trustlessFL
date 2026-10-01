"""Central artifact-style MGF used only in the plaintext Flower control run."""

import copy

import numpy as np
import pytest

from experiments.run_fmnist_official import (verify_mgf_trace,
                                            verify_oracle_selection_agreement)
from trustlessfl.fmnist_artifact_mgf import ArtifactMGF, SHPRG_Q


def test_artifact_mgf_rejects_boosted_classifier_update_and_is_repeatable():
    values = np.zeros((10, 4), dtype=np.float32)
    values[:9, 2:] = [0.01, -0.02]
    values[9, 2:] = [20.0, 20.0]
    first = ArtifactMGF(dimension=4, selection_slice=slice(2, 4), seed=7)
    second = ArtifactMGF(dimension=4, selection_slice=slice(2, 4), seed=7)
    for round_id in range(1, 5):
        aggregate, trace = first.aggregate(values, round_id)
        other, other_trace = second.aggregate(values, round_id)
        np.testing.assert_array_equal(aggregate, other)
        assert trace == other_trace
        assert 9 not in trace["selected_indices"]
        assert trace["selected_count"] >= 2
        np.testing.assert_allclose(aggregate[2:], [0.01, -0.02], atol=1e-7)
    assert first.previous_norms == second.previous_norms


def test_official_mgf_trace_rechecks_selection_and_saved_model():
    values = np.zeros((10, 4), dtype=np.float32)
    values[:9, 2:] = [0.01, -0.02]
    values[9, 2:] = [20.0, 20.0]
    selector = ArtifactMGF(dimension=4, selection_slice=slice(2, 4), seed=7)
    cohort = [f"client-{i}" for i in range(10)]
    history = [np.zeros(4)]
    traces = []
    for round_id in range(1, 5):
        aggregate, trace = selector.aggregate(values, round_id)
        history.append(history[-1] + aggregate)
        traces.append({"round": round_id, "cohort": cohort,
                       "selected": [cohort[i] for i in trace.pop("selected_indices")], **trace})
    models = np.asarray(history)
    expected = {round_id: set(cohort) for round_id in range(1, 5)}
    verify_mgf_trace(traces, models, expected, selection_slice=slice(2, 4))
    for field, replacement in (("selected", ["client-9"]), ("bound", 0.0),
                               ("global_weight_l2", 10.0)):
        changed = copy.deepcopy(traces)
        changed[3][field] = replacement
        with pytest.raises(ValueError):
            verify_mgf_trace(changed, models, expected, selection_slice=slice(2, 4))
    altered_models = models.copy()
    altered_models[4, 2] += 1.0
    with pytest.raises(ValueError, match="saved model"):
        verify_mgf_trace(traces, altered_models, expected, selection_slice=slice(2, 4))


def test_artifact_mgf_two_phase_selection_matches_plaintext_control():
    values = np.zeros((10, 4), dtype=np.float32)
    values[:9, 2:] = [0.01, -0.02]
    values[9, 2:] = [20.0, 20.0]
    coupled = ArtifactMGF(dimension=4, selection_slice=slice(2, 4), seed=7)
    separated = ArtifactMGF(dimension=4, selection_slice=slice(2, 4), seed=7)
    for round_id in range(1, 5):
        expected_mean, expected_trace = coupled.aggregate(values, round_id)
        amplitude = separated.mask_weight * separated.previous_linf
        seeds = [separated.random.randint(0, SHPRG_Q - 1) for _ in range(len(values))]
        masks = np.stack([separated._mask(seed, amplitude) for seed in seeds]).astype(np.float32)
        masked = values[:, 2:] + masks
        mask_linf = float(np.max(np.sum(masks, axis=0, dtype=np.float64)))
        selected, trace = separated.select_masked(masked, mask_linf, round_id)
        mean = np.mean(values[selected], axis=0, dtype=np.float32).astype(np.float64)
        trace.update(separated.observe_aggregate(mean, mask_linf, trace["bound"], round_id))
        np.testing.assert_array_equal(mean, expected_mean)
        assert trace == expected_trace


def test_official_oracle_control_rejects_later_round_selection_divergence():
    oracle = [{"selected": ["client-1", "client-2"]},
              {"selected": ["client-3", "client-4"]}]
    clear = copy.deepcopy(oracle)
    assert verify_oracle_selection_agreement(oracle, clear, 2) == [True, True]
    clear[1]["selected"] = ["client-3", "client-5"]
    with pytest.raises(AssertionError, match="rounds \\[2\\]"):
        verify_oracle_selection_agreement(oracle, clear, 2)
    with pytest.raises(ValueError, match="round count"):
        verify_oracle_selection_agreement(oracle, clear[:1], 2)
