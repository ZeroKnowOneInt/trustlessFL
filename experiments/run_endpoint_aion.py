"""AION on official Flower Runtime, plus separately staged clear FL controls."""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import tomllib
import uuid

import numpy as np
import tomli_w

from experiments.run_endpoint import prepare, write_json
from experiments.run_endpoint_flower import run
from trustlessfl.demo import provision
from trustlessfl.protocol import Parameters

SOURCES = ("__init__.py", "aion_runtime.py", "client_app.py", "workflow.py", "protocol.py", "crypto.py",
           "numeric.py", "task.py", "endpoint.py", "endpoint_public.py", "endpoint_aion.py", "endpoint_torch.py")


def stage(output, data, seeds, rounds, workload, backend):
    if not seeds or len(set(seeds)) != len(seeds) or min(seeds) < 0 or rounds < 1:
        raise ValueError("Invalid seeds/rounds")
    output.mkdir(parents=True, exist_ok=False)
    files = {}
    if workload == "endpoint":
        x, y, owner, part, group, audit = prepare(data)
        write_json(output / "data-audit.json", audit)
        np.savez_compressed(output / "split.npz", split=part, group=group, client=owner)
        shards = output / "shards"
        shards.mkdir()
        for i in range(8):
            selected = (owner == i) & (part == 0)
            path = shards / f"client-{i}.npz"
            np.savez_compressed(path, x=x[selected], y=y[selected], index=np.flatnonzero(selected))
            files[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        selected = part == 2
        path = output / "test.npz"
        np.savez_compressed(path, x=x[selected], y=y[selected], owner=owner[selected], index=np.flatnonzero(selected))
        files[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        from trustlessfl.endpoint_aion import flatten, initial_arrays
        dimension = len(flatten(initial_arrays(x.shape[1], seeds[0])))
    else:
        dimension = 3
    modes = ("aion", "quantized", "float") if workload == "endpoint" else ("aion",)
    scenarios = ("clean",) if workload == "endpoint" else ("clean", "retry", "missing-aggregator", "client-dropout", "tampered-model")
    for mode in modes:
        directory = output / mode
        directory.mkdir()
        app, keys = directory / "app", directory / "provision"
        (app / "trustlessfl").mkdir(parents=True)
        keys.mkdir(mode=0o700)
        catalog = {}
        for seed in seeds:
            for scenario in scenarios:
                case = f"seed-{seed}--{scenario}"
                p = Parameters(uuid.uuid4().hex, tuple(f"client-{i}" for i in range(8)),
                    tuple(f"aggregator-{i}" for i in range(4)), dimension=dimension, decimals=6,
                    max_abs=100.0, learning_rate=.01 if workload == "endpoint" else .1)
                _, nodes = provision(keys / case, p)
                if workload == "endpoint":
                    for i in range(8):
                        nodes[i + 1].update({"endpoint-shard": str(shards / f"client-{i}.npz"),
                            "endpoint-seed": seed, "endpoint-epochs": 3, "endpoint-batch-size": 500,
                            "endpoint-device": "cuda:0" if backend == "torch-cuda" else "cpu"})
                catalog[case] = {str(i - 1): n for i, n in nodes.items()}
        write_json(keys / "catalog.json", catalog)
        for name in SOURCES:
            shutil.copyfile(Path("trustlessfl") / name, app / "trustlessfl" / name)
        cfg = tomllib.loads(Path("configs/endpoint/flower-pyproject.toml").read_text())
        cfg["project"].update(name=f"trustlessfl-aion-{mode}", description="Research AION FL on official Flower Runtime")
        cfg["project"]["dependencies"] += ["torch==2.8.0+cu128", "cryptography>=46.0.0"]
        cfg["tool"]["flwr"]["app"]["components"] = {"serverapp": "trustlessfl.aion_runtime:server_app",
            "clientapp": "trustlessfl.aion_runtime:client_app" if mode == "aion" else "trustlessfl.aion_runtime:plain_app"}
        cfg["tool"]["flwr"]["app"]["config"] = {"provision-dir": str(keys), "output-dir": str(directory / "runtime-results"),
            "rounds": rounds, "num-clients": 12, "mode": mode, "workload": workload, "backend": backend, "timeout": 300.0}
        with (app / "pyproject.toml").open("x") as stream:
            stream.write(tomli_w.dumps(cfg))
    sources = [Path("trustlessfl") / name for name in SOURCES] + [Path(__file__), Path("experiments/run_endpoint.py"),
        Path("experiments/run_endpoint_flower.py"), Path("trustlessfl/demo.py"), Path("uv.lock"),
        Path("configs/endpoint/flower-pyproject.toml")]
    write_json(output / "provenance.json", {"workload": workload, "backend": backend, "seeds": seeds,
        "rounds": rounds, "modes": modes, "scenarios": scenarios, "dimension": dimension,
        "versions": {name: importlib.metadata.version(name) for name in ("flwr", "ray", "numpy", "torch", "cryptography")},
        "sources": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}, "data_files": files,
        "model": "31->30->30->9; float32 local Adam lr=.01; batch500; 3 epochs; reset moments each round",
        "initialization": "PublicMLP default seeded CPU initialization; wire model is float64 offset from initialization",
        "aggregation": "Equal client weights; fixed point decimals=6; no clipping; reject |delta|>100",
        "selection": "Fixed final round; no validation or test model selection",
        "verification": "Every AION/clear-quantized round offset EXACT; integer totals recovered within 1e-5 integer units; final confusion EXACT",
        "security": "Research masking surrogate, not production privacy; 12 logical identities share OS user/worker; no poisoning defense",
        "runtime": "Official flwr run/SuperLink/Ray; independent FAB per mode; no plaintext handler in AION ClientApp"})


def result_for(output, mode):
    paths = list((output / mode / "runtime-results").glob("run-*/results.json"))
    if len(paths) != 1:
        raise ValueError("Expected one completed runtime result per mode")
    return paths[0], json.loads(paths[0].read_text())


def verify_run(output):
    provenance = json.loads((output / "provenance.json").read_text())
    for filename, sha in provenance["data_files"].items():
        if hashlib.sha256(Path(filename).read_bytes()).hexdigest() != sha:
            raise ValueError("Data changed after staging")
    paths, results = {}, {}
    for mode in provenance["modes"]:
        paths[mode], results[mode] = result_for(output, mode)
    aion = results["aion"]
    expected_cases = [f"seed-{seed}--{scenario}" for seed in provenance["seeds"] for scenario in provenance["scenarios"]]
    for result in results.values():
        if [c["case"] for c in result["cases"]] != expected_cases:
            raise ValueError("Incomplete/duplicate cases")
    checks, metrics = [], []
    catalog = json.loads((output / "aion/provision/catalog.json").read_text())
    for row in aion["cases"]:
        case, nodes = row["case"], catalog[row["case"]]
        p = Parameters.from_dict(json.loads(Path(nodes["0"]["aion-manifest"]).read_text())["parameters"])
        if row["scenario"] in ("client-dropout", "tampered-model"):
            passed = row["status"] == "expected-abort" and not any(t["action"] == "share" for t in row["trace"])
            checks.append({"case": case, "passed": passed, "no_share_release": passed})
            continue
        with np.load(paths["aion"].parent / f"{case}-models.npz", allow_pickle=False) as data:
            actual = data["offsets"]
        if actual.shape != (provenance["rounds"] + 1, p.dimension) or not np.isfinite(actual).all():
            raise ValueError("Invalid model history")
        if provenance["workload"] == "synthetic":
            from trustlessfl.task import local_delta
            expected = [np.zeros(p.dimension)]
            for _ in range(provenance["rounds"]):
                totals = [sum(v) for v in zip(*(p.codec.encode(local_delta(expected[-1], i, p.learning_rate)) for i in range(8)))]
                expected.append(np.asarray([w + v / (8 * p.codec.scale) for w, v in zip(expected[-1], totals)]))
            exact = np.array_equal(actual, expected)
            checks.append({"case": case, "passed": exact, "clear_oracle_exact": exact})
            continue
        with np.load(paths["quantized"].parent / f"{case}-models.npz", allow_pickle=False) as data:
            clear = data["offsets"]
        control = next(c for c in results["quantized"]["cases"] if c["case"] == case)
        integer_error = float(np.max(np.abs(np.diff(actual, axis=0) * (p.codec.scale * 8) - np.asarray(control["integer_totals"]))))
        errors = np.max(np.abs(actual - clear), axis=1).tolist()
        state_meta, state_ok = [], True
        for index, node in nodes.items():
            folder = Path(node["aion-identity"]).parent
            state_paths = list(folder.glob("state-*.json"))
            if len(state_paths) != 1:
                raise ValueError("Missing/ambiguous persistent state")
            state = json.loads(state_paths[0].read_text())
            state_ok &= state_paths[0].stat().st_mode & 0o777 == 0o600
            if int(index) < 8:
                state_ok &= state["last_round"] == provenance["rounds"] and "shares" not in state
                values = state["training_meta"]
                state_ok &= set(values) == {str(r) for r in range(1, provenance["rounds"] + 1)}
                state_meta += list(values.values())
            else:
                state_ok &= "training_meta" not in state and "endpoint-shard" not in node
                state_ok &= state["last_model"]["model"] == actual[-1].tolist()
                state_ok &= len(state["shares"]) == 8
        expected_device = "cuda:0" if provenance["backend"] == "torch-cuda" else "cpu"
        all_meta = state_meta + control["training_meta"] + next(c for c in results["float"]["cases"] if c["case"] == case)["training_meta"]
        device_ok = all(m["device"] == expected_device and m["dtype"] == "torch.float32" for m in all_meta)
        device_ok &= len(all_meta) == 3 * 8 * provenance["rounds"]
        from trustlessfl.endpoint_aion import model_arrays
        from trustlessfl.endpoint_public import evaluate_arrays
        seed = int(case.split("--")[0].removeprefix("seed-"))
        with np.load(output / "test.npz", allow_pickle=False) as data:
            xx, yy, owner = data["x"], data["y"], data["owner"]
        case_metrics = {"case": case, "seed": seed, "modes": {}}
        for mode in provenance["modes"]:
            with np.load(paths[mode].parent / f"{case}-models.npz", allow_pickle=False) as data:
                offsets = data["offsets"]
            values = model_arrays(offsets[-1], xx.shape[1], seed)
            pooled = evaluate_arrays(values, xx, yy)
            client_metrics = [evaluate_arrays(values, xx[owner == i], yy[owner == i]) for i in range(8)]
            mode_row = next(c for c in results[mode]["cases"] if c["case"] == case)
            case_metrics["modes"][mode] = {"test": pooled, "clients": client_metrics, "seconds": mode_row["seconds"],
                "final_offset_max_error_vs_aion": float(np.max(np.abs(offsets[-1] - actual[-1])))}
        cm_exact = case_metrics["modes"]["aion"]["test"]["confusion_matrix"] == case_metrics["modes"]["quantized"]["test"]["confusion_matrix"]
        certificates_ok = all(len(set(c["signers"]) & set(p.aggregators)) >= p.quorum for c in row["certificates"])
        passed = max(errors) == 0 and integer_error <= 1e-5 and state_ok and device_ok and cm_exact and certificates_ok
        checks.append({"case": case, "passed": bool(passed), "max_abs_error_by_round": errors,
            "integer_recovery_max_error": integer_error, "state_ok": bool(state_ok), "device_ok": bool(device_ok),
            "confusion_exact": cm_exact, "certificate_quorums": certificates_ok,
            "aion_worker_pids": sorted({m["pid"] for m in state_meta}), "aion_training_meta": state_meta})
        metrics.append(case_metrics)
    summary = {}
    for mode in provenance["modes"]:
        if metrics:
            summary[mode] = {key: {"mean": float(np.mean([m["modes"][mode]["test"][key] for m in metrics])),
                "sample_std": float(np.std([m["modes"][mode]["test"][key] for m in metrics], ddof=1)) if len(metrics) > 1 else None}
                for key in ("macro_f1", "accuracy", "normal_false_positive_rate", "malware_false_negative_rate")}
    verification = {"passed": all(c["passed"] for c in checks), "checks": checks,
                    "run_ids": {k: r["run_id"] for k, r in results.items()}, "metrics": metrics, "summary": summary}
    path = output / "verification.json"
    if path.exists():
        path = output / f"verification-{uuid.uuid4().hex[:8]}.json"
    write_json(path, verification)
    print(json.dumps({"passed": verification["passed"], "run_ids": verification["run_ids"], "summary": summary}, indent=2))
    if not verification["passed"]:
        raise AssertionError("AION verification failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data", type=Path, default=Path(".cache/endpoint/v2"))
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--workload", choices=("synthetic", "endpoint"), default="endpoint")
    parser.add_argument("--backend", choices=("numpy", "torch-cuda"), default="torch-cuda")
    parser.add_argument("--phase", choices=("all", "prepare", "run", "verify"), default="all")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.phase in ("all", "prepare"):
        stage(output, args.data.resolve(), args.seeds, args.rounds, args.workload, args.backend)
    if args.phase in ("all", "run"):
        for mode in json.loads((output / "provenance.json").read_text())["modes"]:
            run(output / mode)
    if args.phase in ("all", "run", "verify"):
        verify_run(output)


if __name__ == "__main__":
    main()
