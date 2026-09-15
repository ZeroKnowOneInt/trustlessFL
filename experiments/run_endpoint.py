"""Plaintext FedAvg/FedProx learning experiment on pinned crowdsensing V2 CSVs."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import time

import numpy as np

from experiments.download_endpoint import FILES, RECORD, verify
from trustlessfl.endpoint import LABELS, MLP, confusion_metrics, evaluate, group_split, train_delta


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def prepare(directory):
    arrays, file_info, schema = [], [], None
    for i, (_, size, md5) in enumerate(FILES):
        path = directory / f"{i}.csv"
        sha = verify(path, size, md5)
        with path.open() as stream:
            header = next(csv.reader(stream))
        if (schema is not None and header != schema) or header[-1] != "label" or len(set(header)) != len(header):
            raise ValueError("Inconsistent feature schema")
        schema = header
        values = np.loadtxt(path, delimiter=",", skiprows=1)
        if values.ndim != 2 or values.shape[1] != len(header) or not np.isfinite(values).all():
            raise ValueError("Malformed/non-finite feature CSV")
        y = values[:, -1]
        if not np.equal(y, y.astype(int)).all() or y.min() < 0 or y.max() > 8:
            raise ValueError("Unknown labels")
        arrays.append(values)
        file_info.append({"file": path.name, "sha256": sha, "rows": len(y),
                          "label_counts": np.bincount(y.astype(int), minlength=9).tolist()})
    device = np.concatenate([np.full(len(a), i, dtype=np.int64) for i, a in enumerate(arrays)])
    values = np.concatenate(arrays)
    x, y = np.ascontiguousarray(values[:, :-1]), values[:, -1].astype(np.int64)
    part, group, duplicates = group_split(x, y, device)
    split_stats = []
    for client in range(8):
        for code, name in enumerate(("train", "validation", "test")):
            selected = (device == client) & (part == code)
            if not selected.any():
                raise ValueError("Empty client split")
            split_stats.append({"client": client, "split": name, "rows": int(selected.sum()),
                                "label_counts": np.bincount(y[selected], minlength=9).tolist()})
    audit = {"record": RECORD, "version": "V2", "license": "CC BY 4.0", "files": file_info,
             "rows": len(y), "inputs": x.shape[1], "features": schema[:-1], "labels": LABELS,
             "label_mapping_source": "https://github.com/Cyber-Tracer/iot-feature-engineering/blob/bf04ddfa010c3de5a003bd087497b9f9184e58e9/py_dataset/sys_func.py#L25",
             "label_mapping_status": "Matches linked source encoder; CSV has no embedded semantic metadata",
             "client_mapping": "Official device/0.csv through 7.csv preserved; physical device-ID mapping unverified",
             "evaluation_scope": "Released-feature, non-temporal split; upstream preprocessing leakage possible",
             "paper_discrepancy": "Observed 31 input features and 171053 rows, versus paper 32 and 342106",
             "split_seed": 42, "duplicates": duplicates, "split_stats": split_stats,
             "feature_min": x.min(axis=0).tolist(), "feature_max": x.max(axis=0).tolist()}
    return x, y, device, part, group, audit


def simulate(model, x, y, device, part, *, seed, mu, learning_rate, rounds,
             epochs, batch_size, attackers, evaluation_parts):
    train = []
    for client in range(8):
        chosen = (device == client) & (part == 0)
        labels = y[chosen].copy()
        if client in attackers:
            labels = (labels + 1) % 9
        train.append((x[chosen], labels))
    weights = model.initialize(seed)
    history, start = [], time.perf_counter()
    for round_id in range(rounds + 1):
        round_start = time.perf_counter()
        norms = []
        if round_id:
            deltas = [train_delta(model, weights, xx, yy, seed=seed, client=i,
                                  round_id=round_id, learning_rate=learning_rate,
                                  epochs=epochs, batch_size=batch_size, mu=mu)
                      for i, (xx, yy) in enumerate(train)]
            norms = [float(np.linalg.norm(delta)) for delta in deltas]
            # Exactly the equal-client objective used in the existing AION path.
            weights = weights + np.mean(deltas, axis=0)
        train_seconds = time.perf_counter() - round_start
        metrics = {}
        for code in evaluation_parts:
            client_metrics = [evaluate(model, weights, x[(device == i) & (part == code)],
                                       y[(device == i) & (part == code)]) for i in range(8)]
            cm = np.sum([m["confusion_matrix"] for m in client_metrics], axis=0)
            pooled = confusion_metrics(cm)
            pooled["device_macro_f1_mean"] = float(np.mean([m["supported_macro_f1"] for m in client_metrics]))
            pooled["device_macro_f1_min"] = float(np.min([m["supported_macro_f1"] for m in client_metrics]))
            pooled["cross_entropy"] = float(sum(m["cross_entropy"] * sum(m["support"]) for m in client_metrics) / cm.sum())
            metrics[{1: "validation", 2: "test"}[code]] = {"pooled": pooled, "clients": client_metrics}
        history.append({"round": round_id, "training_seconds": train_seconds,
                        "local_delta_norms": norms, "metrics": metrics})
        if round_id:
            val = metrics["validation"]["pooled"]["macro_f1"]
            print(f"seed={seed} mu={mu} attackers={attackers} round={round_id} val-F1={val:.4f}", flush=True)
    return {"seed": seed, "mu": mu, "attackers": attackers, "learning_rate": learning_rate,
            "seconds": time.perf_counter() - start, "history": history,
            "model_sha256": hashlib.sha256(weights.tobytes()).hexdigest()}, weights


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path(".cache/endpoint/v2"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", type=int, nargs="+", default=[42])
    parser.add_argument("--mus", type=float, nargs="+", default=[0.0, 0.01, 0.1])
    parser.add_argument("--learning-rates", type=float, nargs="+", default=[0.01, 0.1])
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=128)
    args = parser.parse_args()
    if (min(args.rounds, args.epochs, args.batch_size) < 1 or min(args.seeds) < 0
            or any(not np.isfinite(mu) or mu < 0 for mu in args.mus)
            or 0.0 not in args.mus
            or any(not np.isfinite(lr) or lr <= 0 for lr in args.learning_rates)
            or any(len(v) != len(set(v)) for v in (args.mus, args.seeds, args.learning_rates))):
        parser.error("Invalid or duplicate hyperparameters; mu=0 baseline required")
    # Fail rather than overwrite any earlier run.
    args.output.mkdir(parents=True, exist_ok=False)
    x, y, device, part, group, audit = prepare(args.data)
    write_json(args.output / "data-audit.json", audit)
    np.savez_compressed(args.output / "split.npz", split=part, feature_group=group, client=device)
    model = MLP(x.shape[1])
    config = {**vars(args), "model": {"inputs": model.inputs, "hidden": 128, "classes": 9,
                                     "parameters": model.dimension},
              "aggregation": "equal-client float64 average", "security": "None; plaintext learning simulator",
              "attack": "2/8 clients, fixed cyclic train label flip, rounds 1..R",
              "python": platform.python_version(), "numpy": np.__version__,
              "platform": platform.platform(), "threads": {key: os.environ.get(key) for key in
                  ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")},
              "sources": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                          (Path(__file__), Path("trustlessfl/endpoint.py"), Path("experiments/download_endpoint.py"))}}
    config = {k: str(v) if isinstance(v, Path) else v for k, v in config.items()}
    write_json(args.output / "config.json", config)
    common = dict(model=model, x=x, y=y, device=device, part=part, rounds=args.rounds,
                  epochs=args.epochs, batch_size=args.batch_size)
    tuning = []
    for lr in args.learning_rates:
        result, _ = simulate(**common, seed=42, mu=0, learning_rate=lr,
                             attackers=[], evaluation_parts=[1])
        tuning.append(result)
    # Last-round validation only; never use test data for the choice.
    chosen = max(tuning, key=lambda r: r["history"][-1]["metrics"]["validation"]["pooled"]["macro_f1"])
    lr = chosen["learning_rate"]
    write_json(args.output / "tuning.json", {"criterion": "clean mu=0 seed42 last-round validation macro-F1",
                                            "selected_learning_rate": lr, "runs": tuning})
    summary = []
    for seed in args.seeds:
        rng = np.random.default_rng(np.random.SeedSequence([seed, 2]))
        attacked = sorted(int(i) for i in rng.choice(8, 2, replace=False))
        for attackers in ([], attacked):
            for mu in args.mus:
                name = f"seed-{seed}-mu-{mu:g}-{'poison' if attackers else 'clean'}"
                result, weights = simulate(**common, seed=seed, mu=mu, learning_rate=lr,
                                           attackers=attackers, evaluation_parts=[1, 2])
                write_json(args.output / f"{name}.json", result)
                np.savez_compressed(args.output / f"{name}-model.npz", weights=weights)
                last = result["history"][-1]["metrics"]["test"]["pooled"]
                summary.append({"run": name, "seed": seed, "mu": mu, "poison": bool(attackers),
                                "attackers": attackers, "seconds": result["seconds"],
                                **{key: last[key] for key in ("macro_f1", "accuracy", "normal_false_positive_rate",
                                  "malware_false_negative_rate", "device_macro_f1_mean", "device_macro_f1_min")}})
    write_json(args.output / "summary.json", summary)
    with (args.output / "summary.csv").open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=summary[0].keys())
        writer.writeheader()
        writer.writerows(summary)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
