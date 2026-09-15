import numpy as np
import pytest
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.common.serde import message_from_proto, message_to_proto

from trustlessfl.endpoint import MLP, train_delta
from trustlessfl.endpoint_flower import average_deltas, ordered_replies, partition, train


def test_client_serialization_and_context_state(tmp_path):
    rng = np.random.default_rng(7)
    x, y = rng.normal(size=(18, 3)), np.arange(18) % 9
    np.savez(tmp_path / "client-3-train.npz", x=x, y=y)
    context = Context(run_id=1, node_id=4, node_config={"partition-id": 3, "num-partitions": 8},
                      state=RecordDict(), run_config={"data-dir": str(tmp_path)})
    model = MLP(3)
    weights = model.initialize(42)
    config = ConfigRecord({"case": "test", "round": 1, "seed": 42, "mu": .1,
                           "learning-rate": .1, "epochs": 3, "batch-size": 8, "attackers": [3]})
    message = Message(RecordDict({"config": config, "model": ArrayRecord([weights])}),
                      dst_node_id=4, message_type="train")
    for count in (1, 2):
        reply = train(message_from_proto(message_to_proto(message)), context)
        restored = message_from_proto(message_to_proto(reply))
        expected = train_delta(model, weights, x, (y + 1) % 9, seed=42, client=3,
                               round_id=1, learning_rate=.1, mu=.1, epochs=3, batch_size=8)
        np.testing.assert_array_equal(restored.content["delta"].to_numpy_ndarrays()[0], expected)
        assert restored.content["meta"]["calls"] == count
    np.testing.assert_array_equal(y, np.arange(18) % 9)


def replies():
    output = []
    for i in range(8):
        request = Message(RecordDict(), dst_node_id=i + 1, message_type="train")
        output.append(Message(RecordDict({"delta": ArrayRecord([np.full(3, i, dtype=np.float64)]),
                                          "meta": ConfigRecord({"partition": i, "case": "test", "round": 1, "calls": 1})}),
                              reply_to=request))
    return output


def test_reply_order_and_equal_client_average():
    ordered = ordered_replies(reversed(replies()), {i: i + 1 for i in range(8)},
                              case="test", round_id=1, calls=1)
    np.testing.assert_array_equal(average_deltas(ordered, 3), np.full(3, 3.5))


def test_missing_duplicate_or_lost_state_rejected():
    mapping = {i: i + 1 for i in range(8)}
    with pytest.raises(RuntimeError):
        ordered_replies(replies()[:-1], mapping)
    with pytest.raises(ValueError):
        ordered_replies(replies() + replies()[:1], mapping)
    with pytest.raises(ValueError):
        ordered_replies(replies(), mapping, case="test", round_id=1, calls=2)


def test_partition_count_checked():
    context = Context(run_id=1, node_id=4, node_config={"partition-id": 3, "num-partitions": 4},
                      state=RecordDict(), run_config={})
    with pytest.raises(ValueError):
        partition(context)


def test_client_selects_cuda_backend_and_serializes_metadata(tmp_path, monkeypatch):
    from trustlessfl import endpoint_torch

    x, y = np.ones((10, 3)), np.arange(10) % 9
    np.savez(tmp_path / "client-0-train.npz", x=x, y=y)
    context = Context(run_id=1, node_id=4, node_config={"partition-id": 0, "num-partitions": 8},
                      state=RecordDict(), run_config={"data-dir": str(tmp_path), "backend": "torch-cuda"})
    model = MLP(3)
    config = ConfigRecord({"case": "test", "round": 1, "seed": 42, "mu": .1,
                           "learning-rate": .1, "epochs": 3, "batch-size": 8, "attackers": []})
    message = Message(RecordDict({"config": config, "model": ArrayRecord([model.initialize(42)])}),
                      dst_node_id=4, message_type="train")
    def fake_gpu(model, weights, xx, yy, **kwargs):
        np.testing.assert_array_equal(yy, y)
        assert kwargs["mu"] == .1
        return np.zeros(model.dimension), {"device": "cuda:0", "peak-allocated-bytes": 1024}
    monkeypatch.setattr(endpoint_torch, "train_delta_torch", fake_gpu)
    restored = message_from_proto(message_to_proto(train(message, context)))
    assert restored.content["meta"]["device"] == "cuda:0"
    assert restored.content["meta"]["peak-allocated-bytes"] == 1024
    context.run_config["backend"] = "invalid"
    with pytest.raises(ValueError, match="Unknown training backend"):
        train(message, context)
