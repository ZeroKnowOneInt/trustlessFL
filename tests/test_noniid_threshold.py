import numpy as np
import pytest

from experiments.run_noniid_threshold import balanced_partition, policy, choose


@pytest.mark.parametrize('alpha', [None, .5, .1])
def test_partition_exact_coverage_equal_size_and_reproducibility(alpha):
    labels = np.repeat(np.arange(10), 60)
    result = balanced_partition(labels, 42, alpha)
    assert result.shape == (4, 150)
    assert np.array_equal(np.sort(result.ravel()), np.arange(600))
    assert np.array_equal(result, balanced_partition(labels, 42, alpha))
    assert not np.array_equal(result, balanced_partition(labels, 43, alpha))


def test_iid_partition_preserves_existing_experiment_order():
    labels = np.repeat(np.arange(10), 60)
    assert np.array_equal(balanced_partition(labels, 42, None),
                          np.random.default_rng(42).permutation(600).reshape(4, 150))


def test_static_policy_exact_real_radius_and_ring_capacity():
    for radius in (1., 2.5, 5., 10.):
        p = policy(radius)
        assert p.squared_threshold == (p.scale*radius)**2
        assert 2*p.coordinate_cap < p.modulus
        p.validate_ring(64)


def test_selection_tie_prefers_existing_policy_and_deduplicates_native_runs():
    summary = [{'distribution': 'strong', 'radius': r, 'mean_accuracy_percent': 80., 'rejected': 0}
               for r in (1., 2.5, 5., 10.)]
    assert choose(summary)['native_radii'] == [5.]
    summary[0]['mean_accuracy_percent'] = 81.
    assert choose(summary)['native_radii'] == [5., 1.]
