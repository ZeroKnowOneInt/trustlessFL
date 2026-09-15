"""Run the unchanged Endpoint MLP on pooled training data through Flower."""

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
from trustlessfl.endpoint import MLP, train_delta
from trustlessfl.endpoint_central_flower import load_split, split_metrics


def stage(output, data, seeds, steps):
    if steps < 1 or not seeds or min(seeds) < 0 or len(set(seeds)) != len(seeds):
        raise ValueError("Invalid seeds/steps")
    output.mkdir(parents=True, exist_ok=False)
    shards, app = output / "shards", output / "app"
    shards.mkdir()
    (app / "trustlessfl").mkdir(parents=True)
    x, y, owner, part, group, audit = prepare(data)
    write_json(output / "data-audit.json", audit)
    np.savez_compressed(output / "split.npz", split=part, group=group, client=owner)
    files = {}
    for code, split in enumerate(("train", "validation", "test")):
        selected = part == code
        path = shards / f"{split}.npz"
        np.savez_compressed(path, x=x[selected], y=y[selected], client=owner[selected])
        files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(shards / "manifest.json", {"inputs": x.shape[1], "files": files})
    sources = [Path("trustlessfl") / name for name in
               ("__init__.py", "endpoint.py", "endpoint_central_flower.py")]
    for path in sources:
        shutil.copyfile(path, app / "trustlessfl" / path.name)
    cfg = tomllib.loads(Path("configs/endpoint/flower-pyproject.toml").read_text())
    cfg["project"]["name"] = "trustlessfl-endpoint-central"
    cfg["project"]["description"] = "Public-data centralized Endpoint diagnostic"
    cfg["tool"]["flwr"]["app"]["components"] = {
        "clientapp": "trustlessfl.endpoint_central_flower:client_app",
        "serverapp": "trustlessfl.endpoint_central_flower:server_app"}
    cfg["tool"]["flwr"]["app"]["config"] = {"data-dir": str(shards),
        "output-dir": str(output / "runtime-results"), "num-clients": 1, "backend": "numpy",
        "seeds": ",".join(map(str, seeds)), "steps": steps, "epochs-per-step": 3,
        "batch-size": 128, "learning-rate": .1, "timeout": 120.0}
    with (app / "pyproject.toml").open("x") as stream:
        stream.write(tomli_w.dumps(cfg))
    sources += [Path(__file__), Path("experiments/run_endpoint.py"), Path("experiments/run_endpoint_flower.py"),
                Path("configs/endpoint/flower-pyproject.toml"), Path("uv.lock")]
    write_json(output / "provenance.json", {"versions": {p: importlib.metadata.version(p) for p in ("flwr", "ray", "numpy")},
        "sources": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "model_atol": 0.0, "purpose": "Fixed-setting centralized diagnostic, not a paper reproduction",
        "comparison": "Every 3 epochs checkpoint and all split confusion matrices must match NumPy exactly",
        "selection": "No tuning; fixed final epoch, no test-based model selection",
        "sample_exposures": steps * 3, "security": "None"})


def verify_run(output):
    candidates = list((output / "runtime-results").glob("run-*/results.json"))
    if len(candidates) != 1:
        raise ValueError("Expected exactly one completed centralized run")
    result_file = candidates[0]
    result = json.loads(result_file.read_text())
    cfg = result["config"]
    manifest = json.loads((Path(cfg["data-dir"]) / "manifest.json").read_text())
    for name, sha in manifest["files"].items():
        if hashlib.sha256((Path(cfg["data-dir"]) / name).read_bytes()).hexdigest() != sha:
            raise ValueError("Modified shard")
    splits = {split: load_split(cfg["data-dir"], split) for split in ("train", "validation", "test")}
    model, checks = MLP(manifest["inputs"]), []
    seeds = [int(s) for s in cfg["seeds"].split(",")]
    if [c["seed"] for c in result["cases"]] != seeds:
        raise ValueError("Missing/duplicate seed")
    for case in result["cases"]:
        seed = case["seed"]
        with np.load(result_file.parent / f"seed-{seed}-models.npz", allow_pickle=False) as checkpoint:
            actual = checkpoint["models"]
        if (actual.shape != (cfg["steps"] + 1, model.dimension) or actual.dtype != np.float64
                or not np.isfinite(actual).all() or len(case["history"]) != cfg["steps"] + 1):
            raise ValueError("Invalid history/checkpoint")
        weights, errors, metrics_ok = model.initialize(seed), [], True
        for step, history in enumerate(case["history"]):
            if history["step"] != step:
                raise ValueError("Wrong step")
            if step:
                x, y, _ = splits["train"]
                weights = weights + train_delta(model, weights, x, y, seed=seed, client=0, round_id=step,
                    learning_rate=cfg["learning-rate"], epochs=cfg["epochs-per-step"], batch_size=cfg["batch-size"])
            errors.append(float(np.max(np.abs(weights - actual[step]))))
            for split, (x, y, owner) in splits.items():
                expected = split_metrics(model, weights, x, y, owner)
                metrics_ok &= expected == history["metrics"][split]
        checks.append({"seed": seed, "model_errors": errors, "metrics_exact": bool(metrics_ok),
                       "passed": all(e == 0 for e in errors) and bool(metrics_ok),
                       "final": case["history"][-1]["metrics"]})
    path = output / "verification.json"
    if path.exists():
        path = output / f"verification-{uuid.uuid4().hex[:8]}.json"
    passed = all(c["passed"] for c in checks)
    write_json(path, {"run_id": result["run_id"], "passed": passed, "cases": checks})
    if not passed:
        raise AssertionError("Centralized Flower result differs from reference")
    print(json.dumps({"passed": passed, "run_id": result["run_id"], "cases": [
        {"seed": c["seed"], **{split: c["final"][split]["pooled"]["macro_f1"] for split in splits}} for c in checks]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data", type=Path, default=Path(".cache/endpoint/v2"))
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--steps", type=int, default=10)
    parser.add_argument("--phase", choices=("all", "prepare", "run", "verify"), default="all")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.phase in ("all", "prepare"):
        stage(output, args.data.resolve(), args.seeds, args.steps)
    if args.phase in ("all", "run"):
        run(output)
    if args.phase in ("all", "run", "verify"):
        verify_run(output)


if __name__ == "__main__":
    main()
