"""Official Flower FMNIST learning + plaintext no-wrap audit. No MPC or privacy."""
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import time

import numpy as np
from flwr.app import ArrayRecord, ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp
from flwr.serverapp import Grid, ServerApp

from .fmnist import DIMENSION, FmnistTrainer, evaluate, reference_vector
from .fmnist_no_wrap_math import audit_updates, quantize
from .paper_dmc import round_even
from .static_bound import static_learning_policy

client_app = ClientApp()
server_app = ServerApp()
CASES = ("fedavg", "quantized", "no-wrap-static")


def configure_torch(device):
    import torch
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.benchmark = False
    if device.startswith("cuda") and not torch.cuda.is_available():
        raise RuntimeError("CUDA requested but unavailable; no fallback")


def partition(context):
    i = int(context.node_config["partition-id"])
    if int(context.node_config["num-partitions"]) != 4 or not 0 <= i < 4:
        raise ValueError("expected four fixed client partitions")
    return i


def vector_hash(vector):
    return hashlib.sha256(vector.tobytes()).hexdigest()


@client_app.query("identity")
def identity(message: Message, context: Context):
    return Message(RecordDict({"meta": ConfigRecord({"partition": partition(context)})}), reply_to=message)


@client_app.train()
def train(message: Message, context: Context):
    cfg = context.run_config
    device = str(cfg["device"])
    configure_torch(device)
    i = partition(context)
    root = Path(str(cfg["data-dir"]))
    request = message.content["config"]
    weights = message.content["model"].to_numpy_ndarrays()[0]
    trainer = FmnistTrainer(root/f"client-{i}.npz", root/"reference.npz", seed=int(cfg["seed"]),
                           epochs=int(cfg["epochs"]), batch_size=int(cfg["batch-size"]), device=device)
    started = time.perf_counter()
    delta = trainer(weights, i, float(cfg["learning-rate"]), int(request["round"]))
    if "no-wrap" not in context.state:
        context.state["no-wrap"] = ConfigRecord({"calls": 0})
    context.state["no-wrap"]["calls"] += 1
    meta = {**trainer.meta, "partition": i, "pid": os.getpid(), "case": str(request["case"]),
            "calls": context.state["no-wrap"]["calls"], "input_model_sha256": vector_hash(weights),
            "delta_sha256": vector_hash(delta), "dtype": "torch.float32", "train_seconds": time.perf_counter()-started}
    return Message(RecordDict({"delta": ArrayRecord([delta]), "meta": ConfigRecord(meta)}), reply_to=message)


def ordered(replies, mapping, *, case=None, round_id=None, calls=None, model_hash=None):
    found = {}
    for reply in replies:
        if reply.has_error():
            raise RuntimeError("Flower client failed; inspect local runtime log")
        meta = reply.content["meta"]
        i = int(meta["partition"])
        if i in found or mapping.get(i) != reply.metadata.src_node_id:
            raise ValueError("duplicate or mismatched partition identity")
        if case is not None and (meta["case"] != case or meta["round"] != round_id
                or meta["calls"] != calls or meta["input_model_sha256"] != model_hash):
            raise ValueError("wrong case/round/model or lost client-local state")
        found[i] = reply
    if set(found) != set(range(4)):
        raise ValueError("incomplete fixed-cohort replies")
    return [found[i] for i in range(4)]


@server_app.main()
def main(grid: Grid, context: Context):
    cfg = context.run_config
    device = str(cfg["device"])
    configure_torch(device)
    output = Path(str(cfg["output-dir"]))/f"run-{context.run_id}"
    output.mkdir(parents=True, exist_ok=False)
    root = Path(str(cfg["data-dir"]))
    with np.load(root/"test.npz", allow_pickle=False) as data:
        test_x, test_y = data["x"], data["y"]
    reference = reference_vector(root/"reference.npz")
    nodes = list(grid.get_node_ids())
    if len(nodes) != 4:
        raise ValueError("expected four Flower SuperNodes")
    timeout = float(cfg["timeout"])
    replies = list(grid.send_and_receive([Message(RecordDict(), dst_node_id=n, message_type="query.identity")
                                          for n in nodes], timeout=timeout))
    mapping = {}
    for reply in replies:
        if reply.has_error():
            raise RuntimeError("identity query failed")
        i = int(reply.content["meta"]["partition"])
        if i in mapping:
            raise ValueError("duplicate partition identity")
        mapping[i] = reply.metadata.src_node_id
    if set(mapping) != set(range(4)) or set(mapping.values()) != set(nodes):
        raise ValueError("invalid Flower partition mapping")
    policy = static_learning_policy(cfg, dimension=DIMENSION, clients=4)
    S, B = policy.scale, policy.coordinate_cap
    results, calls = [], 0
    for case in CASES:
        weights = np.zeros(DIMENSION, dtype=np.float64)
        models = [weights.copy()]
        sums, counts, steps = [np.zeros(DIMENSION, dtype=np.int64)], [0], [np.zeros(DIMENSION)]
        history = []
        for r in range(int(cfg["rounds"])+1):
            started = time.perf_counter()
            row = {"round": r}
            if r:
                threshold = policy.squared_bound if case == "no-wrap-static" else policy.norm_cap
                content = RecordDict({"model": ArrayRecord([weights]),
                                      "config": ConfigRecord({"round": r, "case": case})})
                replies = grid.send_and_receive([Message(content, dst_node_id=mapping[i], message_type="train")
                                                 for i in range(4)], timeout=timeout)
                calls += 1
                ordered_replies = ordered(replies, mapping, case=case, round_id=r, calls=calls, model_hash=vector_hash(weights))
                deltas = [reply.content["delta"].to_numpy_ndarrays()[0] for reply in ordered_replies]
                if any(v.shape != (DIMENSION,) or v.dtype != np.float64 or not np.isfinite(v).all() for v in deltas):
                    raise ValueError("invalid local training delta")
                integers = [quantize(v, S, B) for v in deltas]
                # Each profile consumes these same frozen local updates and threshold.
                recovered, audit = audit_updates(integers, scale=S, cap=B, threshold=threshold,
                    seed=f"{cfg['seed']}:{case}:{r}")
                row.update(audit)
                row.update({"squared_bound": threshold, "status": recovered["status"],
                            "training_meta": [dict(reply.content["meta"]) for reply in ordered_replies],
                            "max_coordinate_quantization_error": max(float(np.max(np.abs(v-np.asarray(u)/S)))
                                for v, u in zip(deltas, integers, strict=True))})
                row["accepted_count"] = 4-audit["excluded_normal_clients"]
                before = weights.copy()
                if recovered["status"] == "ok":
                    integer_mean = tuple(round_even(Fraction(v, recovered["count"])) for v in recovered["sum"])
                    row["integer_mean_squared_norm"] = sum(v*v for v in integer_mean)
                    sums.append(np.asarray(recovered["sum"], dtype=np.int64))
                    counts.append(recovered["count"])
                    if case == "fedavg":
                        weights = weights + np.mean(deltas, axis=0)
                    else:
                        weights = weights + np.asarray(recovered["sum"], dtype=np.float64)/(S*recovered["count"])
                else:
                    sums.append(np.zeros(DIMENSION, dtype=np.int64))
                    counts.append(0)
                row["applied_count"] = counts[-1]
                steps.append(weights-before)
                models.append(weights.copy())
            row.update(evaluate(weights, reference, test_x, test_y, device=device))
            row["wall_seconds"] = time.perf_counter()-started
            history.append(row)
            print(f"FMNIST_NO_WRAP case={case} round={r} accuracy={row['accuracy']:.4f} "
                  f"accepted={row.get('accepted_count', '-')} T={row.get('squared_bound', '-')}", flush=True)
        np.savez_compressed(output/f"{case}-models.npz", models=np.stack(models), integer_sums=np.stack(sums),
                            applied_counts=np.asarray(counts), applied_steps=np.stack(steps))
        results.append({"case": case, "history": history})
    result = {"run_id": context.run_id, "runtime": "Official Flower Simulation Runtime / Ray",
              "security": "NONE: public FMNIST plaintext reference, not MPC or secure Aion",
              "config": dict(cfg), "partition_to_node": mapping, "cases": results,
              "aggregation": "equal client weights; four equal-sized IID shards",
              "threshold_mode": "static", "squared_threshold": policy.squared_bound,
              "controlled_hprf_matrix": "[1,2]; original adapter p/q, not author artifact matrix",
              "comparison": "same seed/data/init/batch schedule across trajectories; same frozen updates across all mask profiles within each round"}
    (output/"results.json").write_text(json.dumps(result, indent=2, allow_nan=False))
