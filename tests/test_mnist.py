"""Offline workload tests; real-data runs live under experiments/."""

import numpy as np
import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl.mnist import DIMENSION, MnistTrainer, evaluate, features, partition_indices


@pytest.mark.parametrize("split", ["iid", "label-skew"])
def test_partitions_are_equal_disjoint_exhaustive_and_repeatable(split):
    labels = np.tile(np.arange(10, dtype=np.uint8), 80)
    partitions = partition_indices(labels, 4, split, 42)
    assert all(len(p) == 200 for p in partitions)
    np.testing.assert_array_equal(np.sort(np.concatenate(partitions)), np.arange(len(labels)))
    for a, b in zip(partitions, partition_indices(labels, 4, split, 42)):
        np.testing.assert_array_equal(a, b)
    if split == "label-skew":
        assert all(len(np.unique(labels[p])) <= 4 for p in partitions)


def test_features_and_zero_model():
    images = np.full((10, 28, 28), 255, dtype=np.uint8)
    x = features(images)
    assert x.shape == (10, 785)
    assert (x == 1).all()
    metrics = evaluate(np.zeros(DIMENSION), images, np.arange(10))
    assert metrics["accuracy"] == 0.1
    assert metrics["cross_entropy"] == pytest.approx(np.log(10))
    with pytest.raises(ProtocolError):
        features(images.astype(float))


def test_training_learns_without_mutation_and_is_deterministic(tmp_path):
    images = np.zeros((20, 28, 28), dtype=np.uint8)
    images[:10, 0, 0] = 255
    images[10:, 0, 1] = 255
    labels = np.repeat(np.array([0, 1], dtype=np.uint8), 10)
    path = tmp_path / "shard.npz"
    np.savez(path, x=images, y=labels)
    trainer = MnistTrainer(str(path), batch_size=5)
    weights = np.zeros(DIMENSION)
    delta = trainer(weights, 0, 0.1, 1)
    assert (weights == 0).all()
    np.testing.assert_array_equal(delta, trainer(weights, 0, 0.1, 1))
    assert evaluate(delta, images, labels)["cross_entropy"] < np.log(10)
    assert delta.shape == (DIMENSION,)
    assert np.isfinite(delta).all()


def test_invalid_trainer_config():
    with pytest.raises(ProtocolError):
        MnistTrainer("unused", batch_size=0)
