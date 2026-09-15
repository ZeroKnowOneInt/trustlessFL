"""Full MNIST on the existing process-isolated Flower/AION-ASR path.

Download the official archive separately; this runner checks its pinned SHA256.
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import tempfile
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from flwr.app import Context, RecordDict

from experiments.run_aion import Case, ObservedGrid
from trustlessfl.crypto import canonical
from trustlessfl.demo import provision
from trustlessfl.mnist import DIMENSION, MnistTrainer, evaluate, load_shard, partition_indices
from trustlessfl.protocol import Parameters
from trustlessfl.server_app import app

DATA_URL = "https://storage.googleapis.com/tensorflow/tf-keras-datasets/mnist.npz"
DATA_SHA256 = "731c5ac602752760c8e48fbffcf8c3b850d9dc2a2aedcf2cc48468fc17b673d1"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ProgressGrid(ObservedGrid):
    def send_and_receive(self, messages, *, timeout=None):
        yield from super().send_and_receive(messages, timeout=timeout)
        if self.events and self.events[-1]["action"] == "commit":
            print(f"  secure round {self.last_committed_round}/{self.case.rounds} committed", flush=True)


def baseline(p: Parameters, trainers: list[MnistTrainer], rounds: int, quantized: bool):
    models = [np.zeros(p.dimension)]
    start = time.perf_counter()
    for round_id in range(1, rounds + 1):
        updates = [trainer(models[-1], i, p.learning_rate, round_id) for i, trainer in enumerate(trainers)]
        if quantized:
            mean = np.sum([p.codec.encode(u) for u in updates], axis=0) / (len(updates) * p.codec.scale)
        else:
            mean = np.mean(updates, axis=0)
        models.append(models[-1] + mean)
    return models, time.perf_counter() - start


def run_split(args, split: str, data: dict) -> dict:
    indices = partition_indices(data["y_train"], 4, split, args.seed)
    p = Parameters(uuid.uuid4().hex, tuple(f"client-{i}" for i in range(4)),
                   tuple(f"aggregator-{i}" for i in range(4)),
                   dimension=DIMENSION, learning_rate=args.learning_rate)
    case = Case(f"mnist-{split}", dimension=DIMENSION, rounds=args.rounds,
                learning_rate=args.learning_rate)
    with tempfile.TemporaryDirectory(prefix="aion-mnist-") as temporary:
        directory = Path(temporary)
        manifest, nodes = provision(directory / "identities", p)
        trainers = []
        for i, selected in enumerate(indices):
            # Each client receives only its own shard path; aggregators receive none.
            shard = directory / "identities" / f"client-{i}" / "mnist.npz"
            np.savez(shard, x=data["x_train"][selected], y=data["y_train"][selected])
            nodes[i + 1].update({"mnist-shard": str(shard), "mnist-seed": args.seed,
                                 "mnist-batch-size": args.batch_size})
            trainers.append(MnistTrainer(str(shard), args.seed, args.batch_size))
        print(f"{split}: clear fixed-point baseline", flush=True)
        fixed, fixed_seconds = baseline(p, trainers, args.rounds, True)
        print(f"{split}: clear floating-point baseline", flush=True)
        floating, float_seconds = baseline(p, trainers, args.rounds, False)
        # Benchmark observer has public data for baselines, not the server protocol.
        load_shard.cache_clear()
        context = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(), run_config={
            "aion-manifest": str(manifest), "research-mode": True,
            "num-server-rounds": args.rounds, "timeout": 120.0})
        print(f"{split}: Flower server + 4 silo + 4 aggregator processes", flush=True)
        start = time.perf_counter()
        with ProgressGrid(nodes, case, p) as grid:
            app(grid, context)
        secure_seconds = time.perf_counter() - start
        history = json.loads(context.state["aion-result"]["history"])
        secure = [np.asarray(item["body"]["model"]) for item in history]
        events = grid.events
    curve = []
    for round_id, weights in enumerate(secure):
        curve.append({"round": round_id,
                      "secure_test": evaluate(weights, data["x_test"], data["y_test"]),
                      "fixed_test": evaluate(fixed[round_id], data["x_test"], data["y_test"]),
                      "float_test": evaluate(floating[round_id], data["x_test"], data["y_test"]),
                      "max_abs_error_fixed": float(np.max(np.abs(weights - fixed[round_id]))),
                      "max_abs_error_float": float(np.max(np.abs(weights - floating[round_id])))})
    np.savez(args.output / f"{split}-models.npz", secure=np.stack(secure),
             fixed=np.stack(fixed), floating=np.stack(floating))
    result = {
        "split": split, "seed": args.seed, "parameters": asdict(p),
        "rounds": args.rounds, "batch_size": args.batch_size, "local_epochs": 1,
        "train_samples": len(data["y_train"]), "test_samples": len(data["y_test"]),
        "client_label_counts": [np.bincount(data["y_train"][v], minlength=10).tolist() for v in indices],
        "partition_sha256": [hashlib.sha256(v.astype("<i8").tobytes()).hexdigest() for v in indices],
        "secure_wall_seconds": secure_seconds,
        "fixed_baseline_sequential_compute_seconds": fixed_seconds,
        "float_baseline_sequential_compute_seconds": float_seconds,
        "json_payload_bytes": sum(e["request_payload_bytes"] + e["reply_payload_bytes"] for e in events),
        "max_abs_error_fixed": max(r["max_abs_error_fixed"] for r in curve),
        "max_abs_error_float": max(r["max_abs_error_float"] for r in curve),
        "final_train": evaluate(secure[-1], data["x_train"], data["y_train"]),
        "curve": curve, "events": events,
    }
    (args.output / f"{split}.json").write_bytes(canonical(result))
    print(f"{split}: test accuracy={curve[-1]['secure_test']['accuracy']:.4%}; "
          f"fixed error={result['max_abs_error_fixed']}; wall={secure_seconds:.2f}s", flush=True)
    if result["max_abs_error_fixed"] != 0:
        raise RuntimeError("secure aggregation differs from the fixed-point baseline")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path(".cache/mnist/mnist.npz"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--learning-rate", type=float, default=0.1)
    parser.add_argument("--splits", nargs="+", choices=["iid", "label-skew"], default=["iid", "label-skew"])
    args = parser.parse_args()
    if args.rounds < 1 or args.batch_size < 1 or args.seed < 0 or not 0 < args.learning_rate <= 1:
        parser.error("invalid training parameters")
    if len(set(args.splits)) != len(args.splits):
        parser.error("duplicate splits")
    if not args.data.is_file() or sha256(args.data) != DATA_SHA256:
        parser.error(f"download verified MNIST from {DATA_URL} to {args.data}")
    with np.load(args.data, allow_pickle=False) as archive:
        data = {k: archive[k] for k in ("x_train", "y_train", "x_test", "y_test")}
    for key, shape in {"x_train": (60000, 28, 28), "y_train": (60000,),
                       "x_test": (10000, 28, 28), "y_test": (10000,)}.items():
        if data[key].shape != shape or data[key].dtype != np.uint8:
            parser.error(f"invalid MNIST array: {key}")
    args.output.mkdir(parents=True, exist_ok=False)
    sources = sorted(Path("trustlessfl").glob("*.py")) + [Path(__file__), Path("experiments/run_aion.py")]
    summary = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_url": DATA_URL, "dataset_sha256": DATA_SHA256,
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "logical_cpus": os.cpu_count(),
                        "packages": {n: importlib.metadata.version(n) for n in ("flwr", "numpy", "cryptography")},
                        "threads": {n: os.environ.get(n) for n in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")}},
        "source_sha256": {str(path): sha256(path) for path in sources},
        "notes": ["Research AION-ASR surrogate, not full paper or production security",
                  "Full MNIST, no test data used in training; fixed hyperparameters, no tuning",
                  "Softmax regression, no CNN, no augmentation, zero initial model",
                  "One run per split; no confidence intervals or malicious actors in this experiment",
                  "Local multiprocessing pipes and Flower serialization, not SuperLink/TLS",
                  "Secure wall includes startup, local data loading, training, protocol, shutdown; excludes provisioning and evaluation",
                  "Clear baselines run sequentially without transport; timing is NOT an isolated encryption overhead comparison",
                  "JSON payload bytes exclude protobuf/network overhead"],
        "runs": [],
    }
    (args.output / "results.json").write_bytes(canonical(summary))
    for split in args.splits:
        summary["runs"].append(run_split(args, split, data))
        (args.output / "results.json").write_bytes(canonical(summary))
    summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (args.output / "results.json").write_bytes(canonical(summary))


if __name__ == "__main__":
    main()
