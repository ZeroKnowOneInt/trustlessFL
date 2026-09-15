"""Endpoint workload on official Flower Message APIs; no AION or custom Grid."""

import json
import os
from pathlib import Path
import time

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import Grid, ServerApp

from .endpoint import MLP, confusion_metrics, evaluate, train_delta

client_app = ClientApp()
server_app = ServerApp()


def partition(context):
    index = int(context.node_config["partition-id"])
    if int(context.node_config["num-partitions"]) != 8 or not 0 <= index < 8:
        raise ValueError("This fixture requires eight client partitions")
    return index


def metadata(context, **extra):
    return ConfigRecord({"partition": partition(context), "pid": os.getpid(), **extra})


@client_app.query("identity")
def identity(message: Message, context: Context):
    return Message(RecordDict({"meta": metadata(context)}), reply_to=message)


def load_data(context, split):
    root = Path(str(context.run_config["data-dir"]))
    with np.load(root / f"client-{partition(context)}-{split}.npz", allow_pickle=False) as data:
        return data["x"], data["y"]


@client_app.train()
def train(message: Message, context: Context):
    index = partition(context)
    config = message.content["config"]
    weights = message.content["model"].to_numpy_ndarrays()[0]
    x, y = load_data(context, "train")
    if index in config["attackers"]:
        y = (y + 1) % 9
    kwargs = dict(seed=int(config["seed"]), client=index,
                  round_id=int(config["round"]), learning_rate=float(config["learning-rate"]),
                  epochs=int(config["epochs"]), batch_size=int(config["batch-size"]), mu=float(config["mu"]))
    backend = str(context.run_config.get("backend", "numpy"))
    if backend == "numpy":
        delta = train_delta(MLP(x.shape[1]), weights, x, y, **kwargs)
        training_info = {"backend": "numpy", "device": "cpu", "dtype": "float64"}
    elif backend == "torch-cuda":
        from .endpoint_torch import train_delta_torch
        delta, training_info = train_delta_torch(MLP(x.shape[1]), weights, x, y, **kwargs)
    else:
        raise ValueError(f"Unknown training backend: {backend}")
    if "endpoint" not in context.state:
        context.state["endpoint"] = ConfigRecord({"train-calls": 0})
    state = context.state["endpoint"]
    state["train-calls"] += 1
    return Message(RecordDict({"delta": ArrayRecord([delta]),
                              "meta": metadata(context, case=str(config["case"]),
                                               round=int(config["round"]), calls=state["train-calls"],
                                               **training_info)}),
                   reply_to=message)


@client_app.evaluate()
def evaluate_client(message: Message, context: Context):
    x, y = load_data(context, "test")
    weights = message.content["model"].to_numpy_ndarrays()[0]
    result = evaluate(MLP(x.shape[1]), weights, x, y)
    return Message(RecordDict({"confusion": ArrayRecord([np.asarray(result["confusion_matrix"], dtype=np.int64)]),
                              "meta": metadata(context, loss_sum=result["cross_entropy"] * len(y))}),
                   reply_to=message)


def ordered_replies(replies, mapping, *, case=None, round_id=None, calls=None):
    result = {}
    for reply in replies:
        if reply.has_error():
            raise RuntimeError(f"Client error: {reply.error.reason}")
        meta = reply.content["meta"]
        index = int(meta["partition"])
        if index in result or mapping.get(index) != reply.metadata.src_node_id:
            raise ValueError("Duplicate or mismatched client identity")
        if case is not None and (meta["case"] != case or meta["round"] != round_id or meta["calls"] != calls):
            raise ValueError("Wrong case, round or lost node-local state")
        result[index] = reply
    if set(result) != set(range(8)):
        raise RuntimeError("Incomplete fixed-cohort replies")
    return [result[i] for i in range(8)]


def average_deltas(replies, dimension):
    deltas = [reply.content["delta"].to_numpy_ndarrays()[0] for reply in replies]
    if any(d.shape != (dimension,) or d.dtype != np.float64 or not np.isfinite(d).all() for d in deltas):
        raise ValueError("Invalid delta")
    return np.mean(deltas, axis=0)


@server_app.main()
def main(grid: Grid, context: Context):
    config = context.run_config
    output = Path(str(config["output-dir"])) / f"run-{context.run_id}"
    output.mkdir(parents=True, exist_ok=False)
    timeout = float(config["timeout"])
    nodes = list(grid.get_node_ids())
    if len(nodes) != 8:
        raise ValueError("Expected eight virtual SuperNodes")
    replies = list(grid.send_and_receive([Message(RecordDict(), dst_node_id=node,
                                                  message_type="query.identity") for node in nodes], timeout=timeout))
    mapping = {}
    for reply in replies:
        if reply.has_error():
            raise RuntimeError("Identity query failed")
        index = int(reply.content["meta"]["partition"])
        if index in mapping:
            raise ValueError("Duplicate partition")
        mapping[index] = reply.metadata.src_node_id
    if set(mapping) != set(range(8)) or set(mapping.values()) != set(nodes):
        raise ValueError("Invalid partition mapping")
    seed, rounds = int(config["seed"]), int(config["rounds"])
    manifest = json.loads((Path(str(config["data-dir"])) / "manifest.json").read_text())
    model = MLP(manifest["inputs"])
    rng = np.random.default_rng(np.random.SeedSequence([seed, 2]))
    malicious = sorted(int(i) for i in rng.choice(8, 2, replace=False))
    cases = [(f"mu-{mu:g}-{'poison' if attackers else 'clean'}", mu, attackers)
             for attackers in ([], malicious) for mu in (0.0, 0.1)]
    all_results, train_calls = [], 0
    for name, mu, attackers in cases:
        weights, history = model.initialize(seed), []
        models = [weights.copy()]
        for round_id in range(rounds + 1):
            start = time.perf_counter()
            training_meta = []
            if round_id:
                request = ConfigRecord({"case": name, "round": round_id, "seed": seed,
                                        "mu": mu, "attackers": attackers,
                                        "learning-rate": float(config["learning-rate"]),
                                        "epochs": int(config["epochs"]), "batch-size": int(config["batch-size"])})
                content = RecordDict({"model": ArrayRecord([weights]), "config": request})
                replies = grid.send_and_receive([Message(content, dst_node_id=mapping[i], message_type="train")
                                                 for i in range(8)], timeout=timeout)
                train_calls += 1
                ordered = ordered_replies(replies, mapping, case=name, round_id=round_id, calls=train_calls)
                weights = weights + average_deltas(ordered, model.dimension)
                models.append(weights.copy())
                training_meta = [dict(reply.content["meta"]) for reply in ordered]
            train_seconds = time.perf_counter() - start
            content = RecordDict({"model": ArrayRecord([weights])})
            replies = grid.send_and_receive([Message(content, dst_node_id=mapping[i], message_type="evaluate")
                                             for i in range(8)], timeout=timeout)
            ordered = ordered_replies(replies, mapping)
            cm = np.sum([r.content["confusion"].to_numpy_ndarrays()[0] for r in ordered], axis=0)
            metrics = confusion_metrics(cm)
            metrics["cross_entropy"] = sum(r.content["meta"]["loss_sum"] for r in ordered) / cm.sum()
            history.append({"round": round_id, "test": metrics, "training_seconds": train_seconds,
                            "training_meta": training_meta})
            print(f"FLOWER_ENDPOINT {name} round={round_id} F1={metrics['macro_f1']:.6f}", flush=True)
        np.savez_compressed(output / f"{name}-models.npz", models=np.stack(models))
        all_results.append({"case": name, "mu": mu, "attackers": attackers, "history": history})
    result = {"run_id": context.run_id, "runtime": "Official Flower Simulation Runtime / Ray",
              "security": "None: plaintext learning", "partition_to_node": mapping, "seed": seed,
              "config": dict(config), "cases": all_results}
    with (output / "results.json").open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
    context.state["endpoint-result"] = ConfigRecord({"output": str(output)})
