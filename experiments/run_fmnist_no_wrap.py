"""Stage/run/verify a local official Flower plaintext FMNIST no-wrap comparison."""
import argparse
from fractions import Fraction
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import sys
import tomllib
import uuid

import numpy as np
import tomli_w

from experiments.prepare_fashion_mnist import prepare
from experiments.run_fmnist_flower import read_dataset
from experiments.run_endpoint_flower import run as flower_run
from trustlessfl.fmnist import DIMENSION, make_model, parameter_vector
from trustlessfl.fmnist_no_wrap_app import CASES
from trustlessfl.paper_dmc import round_even

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, body):
    with path.open("x") as stream:
        json.dump(body, stream, indent=2, allow_nan=False)


def stage(output, args):
    if not 1 <= args.rounds <= 100 or not 0 < args.learning_rate <= 1:
        raise ValueError("invalid rounds or learning rate")
    prepare(args.data_root, download=True)
    data = read_dataset(args.data_root/"FashionMNIST/raw")
    output.mkdir(parents=True, exist_ok=False)
    shards = output/"shards"
    shards.mkdir()
    indices = np.random.default_rng(args.seed).permutation(len(data["train_y"]))
    records = []
    for i, selection in enumerate(np.array_split(indices, 4)):
        path = shards/f"client-{i}.npz"
        np.savez_compressed(path, x=data["train_x"][selection], y=data["train_y"][selection])
        records.append({"client": i, "rows": len(selection), "sha256": sha(path),
                        "index_sha256": hashlib.sha256(selection.tobytes()).hexdigest(),
                        "class_counts": np.bincount(data["train_y"][selection], minlength=10).tolist()})
    np.savez_compressed(shards/"test.npz", x=data["test_x"], y=data["test_y"])
    import torch
    torch.manual_seed(args.seed)
    reference = parameter_vector(make_model())
    np.savez_compressed(shards/"reference.npz", weights=reference)
    app = output/"app"
    shutil.copytree(ROOT/"trustlessfl", app/"trustlessfl", ignore=shutil.ignore_patterns("__pycache__"))
    config = tomllib.loads((ROOT/"configs/endpoint/flower-pyproject.toml").read_text())
    config["project"].update(name="trustlessfl-fmnist-no-wrap-local",
                              description="Local plaintext FMNIST no-wrap arithmetic experiment")
    config["project"]["dependencies"].append(f"torch=={importlib.metadata.version('torch')}")
    config["tool"]["flwr"]["app"]["components"] = {
        "serverapp": "trustlessfl.fmnist_no_wrap_app:server_app",
        "clientapp": "trustlessfl.fmnist_no_wrap_app:client_app"}
    S, B = 10000, 20000  # frozen before observing trial updates; real coordinate cap 2
    cfg = {"data-dir": str(shards), "output-dir": str(output/"runtime-results"),
           "num-clients": 4, "seed": args.seed, "rounds": args.rounds,
           "epochs": 1, "batch-size": 64, "learning-rate": args.learning_rate,
           "timeout": 600.0, "runtime-cli-timeout": 1800,
           "backend": "torch-cuda" if args.device.startswith("cuda") else "numpy",
           "device": args.device, "simulation-workers": 1,
           "scale": S, "coordinate-cap": B,
           "threshold-mode": "static", "squared-threshold": 25*S*S, "minimum-accepted": 2}
    config["tool"]["flwr"]["app"]["config"] = cfg
    (app/"pyproject.toml").write_text(tomli_w.dumps(config))
    write(shards/"manifest.json", {"partition": "seeded IID permutation, equal sizes; all 60000 rows",
        "records": records, "test_rows": len(data["test_y"]), "test_sha256": sha(shards/"test.npz"),
        "reference_sha256": sha(shards/"reference.npz"), "initialization": "fresh torch seed; no pretrained checkpoint"})
    sources = ["trustlessfl/fmnist_no_wrap_app.py", "trustlessfl/fmnist_no_wrap_math.py",
               "trustlessfl/fmnist.py", "trustlessfl/private_bound.py", "trustlessfl/paper_dmc.py",
               "trustlessfl/aion_original_hprf.py", "trustlessfl/static_bound.py", "experiments/run_fmnist_no_wrap.py",
               "experiments/run_endpoint_flower.py"]
    write(output/"provenance.json", {"sources": {p: sha(ROOT/p) for p in sources},
        "versions": {p: importlib.metadata.version(p) for p in ("flwr", "torch", "ray", "numpy")},
        "config": cfg, "security": "NONE: plaintext public-data arithmetic reference, no MPC",
        "calibration": "Frozen static L2 radius 5 for all rounds. Not calibrated for poisoning defense.",
        "normalization": "Existing artifact workload: mean .1307, std .3081",
        "hub": "No publishing or root project/publisher/deployment configuration changes"})
    print(json.dumps({"prepared": str(output), "config": cfg}, indent=2), flush=True)


def verify(output, *, allow_historical_dynamic=False):
    candidates = list((output/"runtime-results").glob("run-*/results.json"))
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one completed Flower result")
    path = candidates[0]
    body = json.loads(path.read_text())
    cfg = body["config"]
    provenance = json.loads((output/"provenance.json").read_text())
    if cfg != provenance["config"]:
        raise AssertionError("runtime configuration differs from frozen provenance")
    for relative, expected_sha in provenance["sources"].items():
        if relative.startswith("trustlessfl/") and sha(output/"app"/relative) != expected_sha:
            raise AssertionError("staged application source differs from frozen provenance")
    root = Path(cfg["data-dir"])
    manifest = json.loads((root/"manifest.json").read_text())
    for record in manifest["records"]:
        if sha(root/f"client-{record['client']}.npz") != record["sha256"]:
            raise AssertionError("training shard changed")
    if sha(root/"test.npz") != manifest["test_sha256"] or sha(root/"reference.npz") != manifest["reference_sha256"]:
        raise AssertionError("evaluation data or initial model changed")
    mode = cfg.get("threshold-mode", "dynamic")
    if mode == "dynamic" and not allow_historical_dynamic:
        raise RuntimeError("historical dynamic result: use --allow-historical-dynamic only for read-only verification")
    no_wrap_case = "no-wrap-static" if mode == "static" else "no-wrap-dynamic"
    expected_cases = ["fedavg", "quantized", no_wrap_case]
    if mode not in ("static", "dynamic") or [c["case"] for c in body["cases"]] != expected_cases:
        raise AssertionError("missing experiment case or unsupported threshold mode")
    if mode == "static":
        from trustlessfl.static_bound import static_learning_policy
        static_learning_policy(cfg, dimension=DIMENSION, clients=4)
    initial_delta_hashes = []
    summaries, models = [], {}
    total_profiles, aliases = 0, 0
    for case_index, case in enumerate(body["cases"]):
        name = case["case"]
        history = case["history"]
        if [r["round"] for r in history] != list(range(cfg["rounds"]+1)):
            raise AssertionError("missing round")
        with np.load(path.parent/f"{name}-models.npz", allow_pickle=False) as archive:
            model = archive["models"]
            sums, counts = archive["integer_sums"], archive["applied_counts"]
            steps = archive["applied_steps"]
        if model.shape != (cfg["rounds"]+1, DIMENSION) or not np.isfinite(model).all():
            raise AssertionError("invalid aggregate models")
        if not np.array_equal(model[0], np.zeros(DIMENSION)):
            raise AssertionError("initial offset differs")
        first = sorted(history[1]["training_meta"], key=lambda m:m["partition"])
        initial_delta_hashes.append([m["delta_sha256"] for m in first])
        public_history = []
        for r, row in enumerate(history[1:], 1):
            meta = row["training_meta"]
            if len(meta) != 4 or {m["partition"] for m in meta} != set(range(4)):
                raise AssertionError("missing client training reply")
            if any(m["calls"] != case_index*cfg["rounds"]+r or m["round"] != r
                   or m["case"] != name or m["device"] != cfg["device"] or m["optimizer_steps"] != 235 for m in meta):
                raise AssertionError("training workload/state/device differs")
            if row["max_coordinate_quantization_error"] > .5/cfg["scale"]+1e-12:
                raise AssertionError("quantization error exceeds declared bound")
            if len(row["profiles"]) != 4 or any(p["coordinate_recovery_error"] != 0
                    or p["sum_error"] != 0 or not p["selected_count_matches"] for p in row["profiles"]):
                raise AssertionError("no-wrap reference differs from integer oracle")
            if name == "no-wrap-static":
                if row["squared_bound"] != cfg["squared-threshold"]:
                    raise AssertionError("static threshold changed across rounds")
            if name == "no-wrap-dynamic":
                if len(public_history) < 2:
                    expected_bound = cfg["boot-bound"]
                else:
                    previous, latest = public_history[-2:]
                    ratio = Fraction(latest[1]+1, previous[1]+1)
                    ratio = min(Fraction(4), max(Fraction(1, 4), ratio))
                    expected_bound = min(cfg["maximum-bound"], max(cfg["minimum-bound"], round_even(latest[2]*ratio)))
                if row["squared_bound"] != expected_bound:
                    raise AssertionError("dynamic threshold differs from public-output replay")
                if counts[r]:
                    Q = sum(round_even(Fraction(int(v), int(counts[r])))**2 for v in sums[r])
                    if Q != row["integer_mean_squared_norm"]:
                        raise AssertionError("dynamic history norm differs from public aggregate")
                    public_history.append((r, Q, row["squared_bound"]))
            aliases += row["profiles"][0]["old_centered_modular_alias_coordinates"]
            total_profiles += len(row["profiles"])
            increment = (sums[r].astype(np.float64)/(cfg["scale"]*counts[r])
                         if counts[r] else np.zeros(DIMENSION)) if name != "fedavg" else steps[r]
            if not np.array_equal(model[r], model[r-1]+increment):
                raise AssertionError("model update differs from declared aggregate output")
        excluded = sum(r["excluded_normal_clients"] for r in history[1:])
        summaries.append({"case": name, "accuracy_by_round": [r["accuracy"] for r in history],
            "final_accuracy": history[-1]["accuracy"], "excluded_normal_client_rounds": excluded,
            "total_normal_client_rounds": 4*cfg["rounds"], "normal_exclusion_rate": excluded/(4*cfg["rounds"]),
            "aborted_rounds": sum(r["status"] == "abort" for r in history[1:]),
            "boundary_squared_real": [r["squared_bound"]/cfg["scale"]**2 for r in history[1:]],
            "max_coordinate_quantization_error": max(r["max_coordinate_quantization_error"] for r in history[1:]),
            "applied_counts": counts.tolist(), "round_seconds": [r["wall_seconds"] for r in history]})
        models[name] = model
    if any(h != initial_delta_hashes[0] for h in initial_delta_hashes[1:]):
        raise AssertionError("identical initial model/seed did not produce identical first-round updates")
    if aliases == 0:
        raise AssertionError("small-M audit did not exercise modular aliases")
    verification = {"passed": True, "runtime": body["runtime"], "security": body["security"],
        "verification_source_sha256": sha(Path(__file__)), "staged_application_source_matches": True,
        "cases": summaries, "profile_round_checks": total_profiles, "training_replies": 12*cfg["rounds"],
        "first_round_updates_identical_across_cases": True, "threshold_mode": mode,
        "threshold_history_verified": True, "static_threshold_constant": mode == "static",
        "M1_old_modular_alias_coordinates_total": aliases,
        "max_model_difference_quantized_vs_no_wrap": float(np.max(np.abs(models['quantized']-models[no_wrap_case]))),
        "max_model_difference_float_vs_quantized": float(np.max(np.abs(models['fedavg']-models['quantized']))),
        "initialization": manifest["initialization"],
        "scope": "Arithmetic comparisons against independent integer oracle at runtime; not sequential retraining or a cryptographic/privacy test"}
    if mode == "dynamic":
        verification["dynamic_public_history_replay_matches"] = True
        verification["max_model_difference_quantized_vs_dynamic"] = verification["max_model_difference_quantized_vs_no_wrap"]
    target = output/"verification.json"
    if target.exists():
        target = output/f"verification-{uuid.uuid4().hex[:8]}.json"
    write(target, verification)
    print(json.dumps(verification, indent=2), flush=True)
    return verification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, default=ROOT/".cache/fashion-mnist")
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--learning-rate", type=float, default=.01)
    parser.add_argument("--device", choices=("cuda:0", "cpu"), default="cuda:0")
    parser.add_argument("--phase", choices=("prepare", "run", "verify"), default="run")
    parser.add_argument("--allow-historical-dynamic", action="store_true", help="read-only verification of archived dynamic results")
    args = parser.parse_args()
    if args.allow_historical_dynamic and args.phase != "verify":
        parser.error("historical dynamic mode is only available for verification")
    output = args.output.resolve()
    if args.phase == "prepare":
        stage(output, args)
    elif args.phase == "run":
        staged = json.loads((output/"provenance.json").read_text())["config"]
        if staged.get("threshold-mode") != "static":
            raise RuntimeError("the active runner refuses historical dynamic training; prepare a new static experiment")
        os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]
        flower_run(output)
        verify(output)
    else:
        verify(output, allow_historical_dynamic=args.allow_historical_dynamic)


if __name__ == "__main__":
    main()
