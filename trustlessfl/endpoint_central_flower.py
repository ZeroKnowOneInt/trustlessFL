"""Public-data centralized diagnostic on one official Flower virtual node."""

import json
import os
from pathlib import Path
import time

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import Grid, ServerApp

from .endpoint import MLP, evaluate, train_delta

client_app = ClientApp()
server_app = ServerApp()


def load_split(root, split):
    with np.load(Path(root) / f"{split}.npz", allow_pickle=False) as data:
        return data["x"], data["y"], data["client"]


def split_metrics(model, weights, x, y, owner):
    pooled = evaluate(model, weights, x, y)
    clients = [evaluate(model, weights, x[owner == i], y[owner == i]) for i in range(8)]
    pooled["device_macro_f1_min"] = float(min(m["supported_macro_f1"] for m in clients))
    pooled["device_macro_f1_mean"] = float(np.mean([m["supported_macro_f1"] for m in clients]))
    return {"pooled": pooled, "clients": clients}


def check_node(context):
    if context.node_config != {"partition-id": 0, "num-partitions": 1}:
        raise ValueError("Centralized diagnostic requires partition 0 of 1")


@client_app.train()
def train(message: Message, context: Context):
    check_node(context)
    cfg = message.content["config"]
    weights = message.content["model"].to_numpy_ndarrays()[0]
    x, y, _ = load_split(str(context.run_config["data-dir"]), "train")
    delta = train_delta(MLP(x.shape[1]), weights, x, y, seed=int(cfg["seed"]), client=0,
                        round_id=int(cfg["step"]), learning_rate=float(context.run_config["learning-rate"]),
                        epochs=int(context.run_config["epochs-per-step"]),
                        batch_size=int(context.run_config["batch-size"]), mu=0.0)
    if "central" not in context.state:
        context.state["central"] = ConfigRecord({"calls": 0})
    context.state["central"]["calls"] += 1
    return Message(RecordDict({"delta": ArrayRecord([delta]), "meta": ConfigRecord({
        "seed": int(cfg["seed"]), "step": int(cfg["step"]), "pid": os.getpid(),
        "calls": context.state["central"]["calls"], "device": "cpu"})}), reply_to=message)


@client_app.evaluate()
def evaluate_client(message: Message, context: Context):
    check_node(context)
    weights = message.content["model"].to_numpy_ndarrays()[0]
    metrics = {}
    for split in ("train", "validation", "test"):
        x, y, owner = load_split(str(context.run_config["data-dir"]), split)
        metrics[split] = split_metrics(MLP(x.shape[1]), weights, x, y, owner)
    return Message(RecordDict({"metrics": ConfigRecord({"json": json.dumps(metrics, allow_nan=False)})}),
                   reply_to=message)


def one_reply(replies, node):
    replies = list(replies)
    if len(replies) != 1 or replies[0].metadata.src_node_id != node:
        raise ValueError("Expected exactly one reply from the centralized worker")
    if replies[0].has_error():
        raise RuntimeError(replies[0].error.reason)
    return replies[0]


@server_app.main()
def main(grid: Grid, context: Context):
    cfg = context.run_config
    nodes = list(grid.get_node_ids())
    if len(nodes) != 1:
        raise ValueError("Expected one centralized virtual node")
    node = nodes[0]
    output = Path(str(cfg["output-dir"])) / f"run-{context.run_id}"
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads((Path(str(cfg["data-dir"])) / "manifest.json").read_text())
    model = MLP(manifest["inputs"])
    results, calls = [], 0
    for seed in [int(s) for s in str(cfg["seeds"]).split(",")]:
        weights = model.initialize(seed)
        models, history = [weights.copy()], []
        for step in range(int(cfg["steps"]) + 1):
            meta = {}
            started = time.perf_counter()
            if step:
                request = Message(RecordDict({"model": ArrayRecord([weights]),
                    "config": ConfigRecord({"seed": seed, "step": step})}), dst_node_id=node, message_type="train")
                reply = one_reply(grid.send_and_receive([request], timeout=float(cfg["timeout"])), node)
                calls += 1
                meta = dict(reply.content["meta"])
                if (meta["seed"], meta["step"], meta["calls"]) != (seed, step, calls):
                    raise ValueError("Wrong seed/step or lost client state")
                delta = reply.content["delta"].to_numpy_ndarrays()[0]
                if delta.shape != weights.shape or delta.dtype != np.float64 or not np.isfinite(delta).all():
                    raise ValueError("Invalid delta")
                weights = weights + delta
                models.append(weights.copy())
            training_seconds = time.perf_counter() - started
            request = Message(RecordDict({"model": ArrayRecord([weights])}), dst_node_id=node, message_type="evaluate")
            reply = one_reply(grid.send_and_receive([request], timeout=float(cfg["timeout"])), node)
            metrics = json.loads(reply.content["metrics"]["json"])
            history.append({"step": step, "epochs": step * int(cfg["epochs-per-step"]),
                            "training_seconds": training_seconds, "training_meta": meta, "metrics": metrics})
            print(f"CENTRAL_ENDPOINT seed={seed} epochs={history[-1]['epochs']} "
                  f"train-F1={metrics['train']['pooled']['macro_f1']:.6f} "
                  f"val-F1={metrics['validation']['pooled']['macro_f1']:.6f}", flush=True)
        np.savez_compressed(output / f"seed-{seed}-models.npz", models=np.stack(models))
        results.append({"seed": seed, "history": history})
    with (output / "results.json").open("x") as stream:
        json.dump({"run_id": context.run_id, "config": dict(cfg), "cases": results,
                   "security": "None; public pooled train data, centralized diagnostic",
                   "runtime": "Official Flower Simulation Runtime / Ray"}, stream, indent=2, allow_nan=False)
