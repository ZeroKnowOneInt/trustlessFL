"""Flower Fashion-MNIST workload checks; torch is an optional experiment dependency."""

import hashlib
import random

import numpy as np
import pytest

from experiments.export_fmnist_run import PUBLIC_KEYS, export
from trustlessfl.crypto import canonical
from trustlessfl.crypto import ProtocolError
from trustlessfl.fmnist import (DIMENSION, FmnistTrainer, artifact_dirichlet_partition,
                               artifact_poison_indices, attack_success_rate, evaluate,
                               load_vector, make_model, parameter_vector,
                               tensor_images, trigger_images, MEAN, TRIGGER)
from trustlessfl.numeric import _column, artifact_mask


def test_bad_training_settings():
    with pytest.raises(ProtocolError):
        FmnistTrainer("shard", "reference", batch_size=0)


def test_artifact_style_partition_is_disjoint_and_repeatable():
    labels = np.tile(np.arange(10, dtype=np.uint8), 60)
    first = artifact_dirichlet_partition(labels, 8)
    second = artifact_dirichlet_partition(labels, 8)
    assert len(first) == 8
    assert len(np.unique(np.concatenate(first))) == sum(map(len, first))
    assert sum(map(len, first)) <= len(labels)
    for a, b in zip(first, second):
        np.testing.assert_array_equal(a, b)


def test_artifact_partition_uses_first_seen_classes_and_clean_sample_rng_prelude():
    labels = np.tile(np.asarray([9, 0, 3, 2, 7, 5, 1, 6, 4, 8], dtype=np.uint8), 200)
    artifact = artifact_dirichlet_partition(labels, 180, adversaries=20)
    legacy = artifact_dirichlet_partition(labels, 180, adversaries=20,
                                          rng_policy="legacy")
    assert hashlib.sha256(artifact[0].astype("<i8").tobytes()).hexdigest() == (
        "6a402171b1e1aa8cc611a540bac0fddeddec32b33c300cb68825b216ad533b5f")
    assert hashlib.sha256(legacy[0].astype("<i8").tobytes()).hexdigest() == (
        "83ea73d5c5090bcbf4f584dced99df48ffac902f199b83e1822f567676520a39")
    assert len(np.unique(np.concatenate(artifact))) == sum(map(len, artifact))


def test_artifact_public_matrix_cache_covers_fmnist_dimension():
    task = "fmnist-cache-regression"
    artifact_mask(17, task, 1, DIMENSION)
    before = _column.cache_info()
    artifact_mask(19, task, 1, DIMENSION)
    after = _column.cache_info()
    assert after.hits - before.hits == DIMENSION
    assert after.misses == before.misses


def test_attack_round_rng_continues_after_dirichlet_partition():
    labels = np.tile(np.asarray([9, 0, 3, 2, 7, 5, 1, 6, 4, 8], dtype=np.uint8), 200)
    rng = np.random.RandomState(0)
    artifact_dirichlet_partition(labels, 180, adversaries=20, numpy_rng=rng)
    attack_rounds = (np.flatnonzero(rng.uniform(size=10) >= 0.5) + 1).tolist()
    assert attack_rounds == [1, 6, 7]
    assert attack_rounds != (np.flatnonzero(
        np.random.RandomState(0).uniform(size=10) >= 0.5) + 1).tolist()

    paper_rng = np.random.RandomState(0)
    artifact_dirichlet_partition(labels, 500, adversaries=20, numpy_rng=paper_rng)
    assert (np.flatnonzero(paper_rng.uniform(size=10) >= 0.5) + 1).tolist() == [1, 2, 5, 6, 7, 10]


def test_official_verifier_rejects_reseeded_attack_rounds(tmp_path):
    from experiments.run_fmnist_official import verify

    (tmp_path / "provenance.json").write_bytes(canonical({
        "seed": 0, "population": 500, "dirichlet_alpha": 0.5,
        "rounds": 10, "attack_probability": 0.5, "attack_clients": 20,
        "attack_round_rng_policy": "post-partition", "attack_rounds": [5, 7, 10],
    }))
    with pytest.raises(ValueError, match="post-partition NumPy RNG"):
        verify(tmp_path)


def test_official_all_phase_requires_flower_cli_before_staging(tmp_path, monkeypatch):
    import sys
    from experiments import run_fmnist_official

    monkeypatch.setattr(run_fmnist_official.shutil, "which", lambda _: None)
    monkeypatch.setattr(sys, "argv", ["run_fmnist_official", "--phase", "all",
                                  "--output", str(tmp_path / "new-run")])
    with pytest.raises(FileNotFoundError, match="before staging"):
        run_fmnist_official.main()
    assert not (tmp_path / "new-run").exists()


def test_artifact_poison_pool_rounds_to_batch_and_excludes_target():
    labels = np.tile(np.arange(10, dtype=np.uint8), 100)
    indices = artifact_poison_indices(labels)
    assert len(indices) == 512
    assert np.all(labels[indices] != 2)
    np.testing.assert_array_equal(indices, artifact_poison_indices(labels))


def test_artifact_poison_pool_continues_python_rng_after_partition():
    train = np.tile(np.asarray([9, 0, 3, 2, 7, 5, 1, 6, 4, 8], dtype=np.uint8), 200)
    test = np.tile(np.arange(10, dtype=np.uint8), 100)
    rng = random.Random(0)
    artifact_dirichlet_partition(train, 180, adversaries=20, python_rng=rng)
    actual = artifact_poison_indices(test, python_rng=rng)

    replay = random.Random(0)
    replay.sample(range(20, 180), 150)
    for label in dict.fromkeys(train.tolist()):
        values = np.flatnonzero(train == label).tolist()
        replay.shuffle(values)
    eligible = np.flatnonzero(test != 2).tolist()
    expected = []
    while len(expected) < 500:
        expected.extend(replay.sample(eligible, 64))
    np.testing.assert_array_equal(actual, expected)
    assert not np.array_equal(actual, artifact_poison_indices(test, seed=0))


def test_public_result_export_rejects_noncanonical_or_extra_fields(tmp_path):
    row = {key: 0 for key in PUBLIC_KEYS}
    row.update(rounds=1, curve=[{}, {}], events=[])
    source = tmp_path / "source.json"
    source.write_bytes(canonical(row))
    exported = export(source, tmp_path / "exported")
    assert exported["result_file"] == "results.json"
    assert (tmp_path / "exported" / "results.json").read_bytes() == source.read_bytes()
    source.write_bytes(canonical({**row, "private_key": "secret"}))
    with pytest.raises(ValueError):
        export(source, tmp_path / "blocked")


def test_reference_model_matches_artifact_shape():
    pytest.importorskip("torch")
    model = make_model()
    assert parameter_vector(model).shape == (DIMENSION,)
    vector = parameter_vector(model)
    load_vector(model, vector)
    np.testing.assert_array_equal(parameter_vector(model), vector)


def test_trainer_deterministic_and_keeps_reference_private(tmp_path):
    pytest.importorskip("torch")
    reference = tmp_path / "reference.npz"
    np.savez(reference, weights=np.zeros(DIMENSION, dtype=np.float32))
    images = np.zeros((8, 28, 28), dtype=np.uint8)
    images[:4, 7:14, 7:14] = 255
    labels = np.array([0] * 4 + [1] * 4, dtype=np.uint8)
    training = tmp_path / "shard.npz"
    np.savez(training, x=images, y=labels)
    trainer = FmnistTrainer(training, reference, epochs=1, batch_size=4)
    offset = np.zeros(DIMENSION)
    delta = trainer(offset, 0, 0.001, 1)
    assert delta.shape == (DIMENSION,) and np.isfinite(delta).all()
    assert np.any(delta != 0) and np.all(offset == 0)
    np.testing.assert_array_equal(delta, trainer(offset, 0, 0.001, 1))
    assert trainer.meta["optimizer_steps"] == 2
    result = evaluate(delta, np.zeros(DIMENSION), images, labels)
    assert 0 <= result["accuracy"] <= 1
    assert result["test_error_rate"] == pytest.approx(1 - result["accuracy"])


def test_artifact_style_attack_runs_in_client_trainer(tmp_path):
    pytest.importorskip("torch")
    reference = tmp_path / "reference.npz"
    np.savez(reference, weights=np.zeros(DIMENSION, dtype=np.float32))
    images = np.zeros((8, 28, 28), dtype=np.uint8)
    labels = np.array([0, 1, 3, 4, 5, 6, 7, 8], dtype=np.uint8)
    clean = tmp_path / "clean.npz"
    poison = tmp_path / "poison.npz"
    np.savez(clean, x=images, y=labels)
    np.savez(poison, x=images, y=labels)
    attack = {"rounds": [1], "clean_path": str(clean), "poison_path": str(poison),
              "steps": 2, "boost": 20.0, "poison_batch": 2}
    trainer = FmnistTrainer(clean, reference, epochs=1, batch_size=4, attack=attack)
    zero = np.zeros(DIMENSION)
    first = trainer(zero, 0, 0.001, 1)
    np.testing.assert_array_equal(first, trainer(zero, 0, 0.001, 1))
    assert trainer.meta["attack"] == "artifact-style-MR"
    assert np.isfinite(first).all() and np.any(first != 0)
    assert trainer(zero, 0, 0.001, 2).shape == (DIMENSION,)
    transformed = trigger_images(tensor_images(images[:1], "cpu"))
    assert all(float(transformed[0, 0, row, column]) == pytest.approx(MEAN * 30)
               for row, column in TRIGGER)
    assert 0 <= attack_success_rate(zero, np.zeros(DIMENSION), images) <= 1
