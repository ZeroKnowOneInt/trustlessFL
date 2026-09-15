import json

import numpy as np
import pytest
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.common.serde import message_from_proto, message_to_proto

from trustlessfl.endpoint import MLP, train_delta
from trustlessfl.endpoint_central_flower import train, evaluate_client, one_reply


def fixture(tmp_path):
    rng = np.random.default_rng(4)
    x, y, owner = rng.normal(size=(72, 3)), np.arange(72) % 9, np.repeat(np.arange(8), 9)
    for split in ("train", "validation", "test"):
        np.savez(tmp_path / f"{split}.npz", x=x, y=y, client=owner)
    context = Context(run_id=1, node_id=9, node_config={"partition-id": 0, "num-partitions": 1},
        state=RecordDict(), run_config={"data-dir": str(tmp_path), "learning-rate": .1,
                                      "epochs-per-step": 3, "batch-size": 16})
    model = MLP(3)
    request = Message(RecordDict({"model": ArrayRecord([model.initialize(42)]),
        "config": ConfigRecord({"seed": 42, "step": 1})}), dst_node_id=9, message_type="train")
    return x, y, context, model, request


def test_central_training_only_reads_train_and_preserves_state(tmp_path):
    x, y, context, model, request = fixture(tmp_path)
    (tmp_path / "validation.npz").unlink()
    (tmp_path / "test.npz").unlink()
    expected = train_delta(model, model.initialize(42), x, y, seed=42, client=0, round_id=1,
                           learning_rate=.1, epochs=3, batch_size=16)
    for calls in (1, 2):
        reply = message_from_proto(message_to_proto(train(request, context)))
        np.testing.assert_array_equal(reply.content["delta"].to_numpy_ndarrays()[0], expected)
        assert reply.content["meta"]["calls"] == calls


def test_central_evaluation_counts_all_samples(tmp_path):
    x, y, context, model, request = fixture(tmp_path)
    reply = evaluate_client(request, context)
    metrics = json.loads(reply.content["metrics"]["json"])
    assert set(metrics) == {"train", "validation", "test"}
    for item in metrics.values():
        assert sum(item["pooled"]["support"]) == len(y)
        np.testing.assert_array_equal(item["pooled"]["confusion_matrix"],
            np.sum([m["confusion_matrix"] for m in item["clients"]], axis=0))


def test_central_rejects_wrong_node_and_missing_replies(tmp_path):
    _, _, context, _, request = fixture(tmp_path)
    reply = train(request, context)
    assert one_reply([reply], 9) is reply
    for replies, node in (([], 9), ([reply, reply], 9), ([reply], 10)):
        with pytest.raises(ValueError):
            one_reply(replies, node)
    context.node_config["num-partitions"] = 8
    with pytest.raises(ValueError):
        train(request, context)
