import json

import numpy as np
import pytest
from flwr.app import Context, Message, RecordDict

torch = pytest.importorskip("torch")

from trustlessfl.aion_runtime import settings, secure
from trustlessfl.client_app import payload, records
from trustlessfl.crypto import ProtocolError
from trustlessfl.demo import provision
from trustlessfl.endpoint_aion import EndpointTrainer, flatten, initial_arrays, model_arrays
from trustlessfl.protocol import Parameters


def test_offset_initialization_and_deterministic_local_adam(tmp_path):
    torch.set_num_threads(1)
    initial = initial_arrays(3, 42)
    offset = np.zeros(len(flatten(initial)))
    for a, b in zip(initial, model_arrays(offset, 3, 42)):
        np.testing.assert_array_equal(a, b)
    rng = np.random.default_rng(9)
    path = tmp_path / "train.npz"
    np.savez(path, x=rng.normal(size=(45, 3)), y=np.arange(45) % 9)
    trainer = EndpointTrainer(path, 42, epochs=3, batch_size=17, device="cpu")
    first = trainer(offset, 0, .01, 1)
    assert trainer.meta["optimizer_steps"] == 9
    # A fresh instance has exactly the same trajectory: no worker-global Adam state.
    np.testing.assert_array_equal(first, EndpointTrainer(path, 42, 3, 17, "cpu")(offset, 0, .01, 1))
    assert np.any(first != trainer(offset, 0, .01, 2))
    np.testing.assert_array_equal(offset, 0)
    with pytest.raises(ValueError):
        model_arrays(np.zeros(2), 3, 42)


def test_runtime_provisioning_and_enrollment_retry(tmp_path):
    p = Parameters("runtime-test", tuple(f"c{i}" for i in range(8)), tuple(f"a{i}" for i in range(4)))
    _, nodes = provision(tmp_path / "keys", p)
    catalog = {"case": {str(i - 1): node for i, node in nodes.items()}}
    (tmp_path / "catalog.json").write_text(json.dumps(catalog))
    def context(partition):
        return Context(1, 100 + partition, {"partition-id": partition, "num-partitions": 12},
                       RecordDict(), {"provision-dir": str(tmp_path)})
    message = Message(records({"action": "enroll", "runtime-case": "case"}), dst_node_id=100, message_type="query.aion")
    first = secure(message, context(0))
    assert not first.has_error()
    assert payload(first) == payload(secure(message, context(0)))
    assert payload(first)["sender"] == "c0"
    aggregator_request = Message(records({"action": "enroll", "runtime-case": "case"}), dst_node_id=108, message_type="query.aion")
    assert secure(aggregator_request, context(8)).has_error()
    with pytest.raises(ProtocolError):
        settings(context(12), "case")
    with pytest.raises(ProtocolError):
        settings(context(0), "arbitrary-file-path")


def test_runtime_roster_size_is_not_fixed_at_twelve(tmp_path):
    p = Parameters("runtime-six", ("c0", "c1"), tuple(f"a{i}" for i in range(4)))
    _, nodes = provision(tmp_path / "keys", p)
    (tmp_path / "catalog.json").write_text(json.dumps({
        "case": {str(i - 1): node for i, node in nodes.items()}}))
    context = Context(1, 10, {"partition-id": 0, "num-partitions": 6},
                      RecordDict(), {"provision-dir": str(tmp_path)})
    node, manifest = settings(context, "case")
    assert node == nodes[1] and len(manifest["registry"]) == 6
    context.node_config["num-partitions"] = 12
    with pytest.raises(ProtocolError):
        settings(context, "case")


def test_local_adam_matches_direct_pytorch_with_nonzero_offset(tmp_path):
    from trustlessfl.endpoint_public import PublicMLP, arrays, restore
    torch.set_num_threads(1)
    rng = np.random.default_rng(4)
    x, y = rng.normal(size=(27, 3)), np.arange(27) % 9
    path = tmp_path / "train.npz"
    np.savez(path, x=x, y=y)
    offset = rng.normal(scale=.01, size=len(flatten(initial_arrays(3, 42))))
    model = PublicMLP(3)
    restore(model, model_arrays(offset, 3, 42))
    before = flatten(arrays(model))
    optimizer = torch.optim.Adam(model.parameters(), lr=.01, foreach=False)
    generator = torch.Generator().manual_seed(int(np.random.SeedSequence([42, 2, 3]).generate_state(1)[0]))
    xx, yy = torch.tensor(x, dtype=torch.float32), torch.tensor(y, dtype=torch.int64)
    for _ in range(3):
        indices = torch.randperm(len(y), generator=generator)
        for start in range(0, len(y), 11):
            batch = indices[start:start + 11]
            optimizer.zero_grad(set_to_none=True)
            torch.nn.functional.cross_entropy(model(xx[batch]), yy[batch]).backward()
            optimizer.step()
    actual = EndpointTrainer(path, 42, 3, 11, "cpu")(offset, 2, .01, 3)
    np.testing.assert_array_equal(actual, flatten(arrays(model)) - before)


def test_aggregator_cannot_receive_endpoint_shard(tmp_path):
    from trustlessfl.client_app import handle
    p = Parameters("bad-role", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    _, nodes = provision(tmp_path / "keys", p)
    node = {**nodes[3], "endpoint-shard": "must-not-be-read"}
    context = Context(1, 3, node, RecordDict(), {})
    request = Message(records({"action": "hello"}), dst_node_id=3, message_type="query.aion")
    assert handle(request, context).has_error()
