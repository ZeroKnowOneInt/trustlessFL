"""Author batch semantics, with explicitly isolated (not shared-global) RNG."""

import ast
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
torch = pytest.importorskip("torch")
from torch.utils.data import DataLoader, SubsetRandomSampler, TensorDataset

from trustlessfl.crypto import ProtocolError
from trustlessfl.fmnist import (DIMENSION, FmnistTrainer, load_vector, make_model,
                               parameter_vector, tensor_images)


AUTHOR = Path(__file__).resolve().parents[2] / "Aion/input_validation/FL_Backdoor_CV/roles/client.py"


def inputs(tmp_path):
    images = np.stack([np.full((28, 28), i * 20, dtype=np.uint8) for i in range(8)])
    labels = np.array([0, 1, 3, 4, 5, 6, 7, 8], dtype=np.uint8)
    training, reference = tmp_path / "data.npz", tmp_path / "reference.npz"
    weights = np.random.default_rng(9).normal(0, 0.01, DIMENSION).astype(np.float32)
    np.savez(training, x=images, y=labels)
    np.savez(reference, weights=weights)
    return training, reference, images, labels, weights


def test_author_loader_matches_actual_benign_local_train(tmp_path):
    if not AUTHOR.exists():
        pytest.skip("author artifact required")
    training, reference, images, labels, weights = inputs(tmp_path)
    tree = ast.parse(AUTHOR.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Client")
    fn = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "local_train")
    module = ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[]))
    namespace = {"torch": torch, "optim": torch.optim,
        "args": SimpleNamespace(is_poison=False, aggregation_rule="aion",
                                 local_lr=0.001, device="cpu", dataset="fmnist")}
    exec(compile(module, str(AUTHOR), "exec"), namespace)
    generator = torch.Generator().manual_seed(int(np.random.SeedSequence([1, 0, 1]).generate_state(1)[0]))
    loader = DataLoader(TensorDataset(tensor_images(images, "cpu"), torch.from_numpy(labels).long()),
        batch_size=3, sampler=SubsetRandomSampler(range(8), generator=generator), generator=generator)
    client = SimpleNamespace(malicious=False, local_data=loader)
    helper = SimpleNamespace(params={"momentum": 0.9, "decay": 0.0005,
                                    "retrain_no_times": 2, "dataset": "fmnist"})
    model = make_model()
    load_vector(model, weights)
    before = parameter_vector(model)
    expected = namespace["local_train"](client, model, helper, 301)
    trainer = FmnistTrainer(training, reference, seed=1, epochs=2, batch_size=3,
                            sampling_policy="author-loader")
    actual = trainer(np.zeros(DIMENSION), 0, 0.001, 1)
    np.testing.assert_array_equal(actual, parameter_vector(expected) - before)
    np.testing.assert_array_equal(actual, trainer(np.zeros(DIMENSION), 0, 0.001, 1))
    assert trainer.meta["optimizer_steps"] == 6
    assert trainer.meta["sampling_policy"] == "author-loader"


def test_author_attack_first_batches_have_no_repeated_poison_rows(tmp_path, monkeypatch):
    import trustlessfl.fmnist as fmnist
    training, reference, _, _, _ = inputs(tmp_path)
    batches = []
    original = fmnist.make_model
    def capture_model():
        model = original()
        model.register_forward_pre_hook(lambda _, args: batches.append(args[0].detach().clone()))
        return model
    monkeypatch.setattr(fmnist, "make_model", capture_model)
    attack = {"rounds": [1], "clean_path": str(training), "poison_path": str(training),
              "steps": 3, "boost": 20.0, "poison_batch": 3}
    trainer = FmnistTrainer(training, reference, batch_size=6, attack=attack,
                            sampling_policy="author-loader")
    delta = trainer(np.zeros(DIMENSION), 0, 0.001, 1)
    assert len(batches) == 3 and np.isfinite(delta).all()
    for batch in batches:
        assert batch.shape[0] == 6
        assert len(torch.unique(batch[:3, 0, 10, 10])) == 3
        assert len(torch.unique(batch[3:, 0, 10, 10])) == 3
    np.testing.assert_array_equal(delta, trainer(np.zeros(DIMENSION), 0, 0.001, 1))


def test_unknown_sampling_policy_is_rejected(tmp_path):
    with pytest.raises(ProtocolError, match="sampling policy"):
        FmnistTrainer(tmp_path / "unused", tmp_path / "unused", sampling_policy="global")


def test_plain_flower_handler_passes_sampling_policy(tmp_path, monkeypatch):
    import json
    from dataclasses import asdict
    from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
    import trustlessfl.aion_runtime as runtime
    from trustlessfl.protocol import Parameters
    training, reference, _, _, _ = inputs(tmp_path)
    p = Parameters("author-training-handler", ("client-0", "client-1"),
                   ("a0", "a1", "a2", "a3"), dimension=DIMENSION)
    node = {"fmnist-shard": str(training), "fmnist-reference": str(reference),
            "fmnist-epochs": 1, "fmnist-batch-size": 3,
            "fmnist-sampling-policy": "author-loader"}
    monkeypatch.setattr(runtime, "settings", lambda *a: (node, {"parameters": asdict(p)}))
    context = Context(run_id=1, node_id=1, node_config={"partition-id": 0},
                      state=RecordDict(), run_config={})
    message = Message(RecordDict({"model": ArrayRecord([np.zeros(DIMENSION)]),
                       "config": ConfigRecord({"case": "unit", "round": 1})}),
                      dst_node_id=1, message_type="train")
    reply = runtime.plaintext(message, context)
    assert json.loads(reply.content["config"]["meta"])["sampling_policy"] == "author-loader"
