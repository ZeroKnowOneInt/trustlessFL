"""Public MLP/Adam recipe, with independent and notebook-style evaluation separated."""

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

PROFILES = ("group-holdout", "row-reference")
COMMIT = "bf04ddfa010c3de5a003bd087497b9f9184e58e9"


def profile_indices(part, seed=42):
    # ShuffleSplit/test_size=.2 semantics, with a fixed seed absent from the notebook.
    indices = np.random.RandomState(seed).permutation(len(part))
    n_val = int(np.ceil(.2 * len(part)))
    return {"group-holdout": {"train": np.flatnonzero(part == 0), "validation": np.flatnonzero(part == 1),
                              "evaluation": np.flatnonzero(part == 2)},
            "row-reference": {"train": indices[n_val:], "validation": indices[:n_val],
                              "evaluation": indices[:n_val]}}


def stage(output, data, seeds, profiles, max_epochs):
    if (not seeds or min(seeds) < 0 or len(set(seeds)) != len(seeds) or max_epochs < 1
            or not profiles or not set(profiles) <= set(PROFILES) or len(set(profiles)) != len(profiles)):
        raise ValueError("Invalid run settings")
    output.mkdir(parents=True, exist_ok=False)
    shards, app = output / "shards", output / "app"
    shards.mkdir()
    (app / "trustlessfl").mkdir(parents=True)
    x, y, owner, part, group, audit = prepare(data)
    write_json(output / "data-audit.json", audit)
    np.savez_compressed(output / "split.npz", split=part, group=group, client=owner)
    indices = profile_indices(part)
    files, overlaps = {}, {}
    for profile in profiles:
        directory = shards / profile
        directory.mkdir()
        for split, selected in indices[profile].items():
            path = directory / f"{split}.npz"
            np.savez_compressed(path, x=x[selected], y=y[selected], index=selected)
            files[f"{profile}/{split}.npz"] = hashlib.sha256(path.read_bytes()).hexdigest()
        training = indices[profile]["train"]
        evaluation = indices[profile]["evaluation"]
        overlaps[profile] = {"rows": {k: len(v) for k, v in indices[profile].items()},
            "train_evaluation_row_overlap": len(np.intersect1d(training, evaluation)),
            "train_evaluation_feature_groups_shared": len(np.intersect1d(group[training], group[evaluation])),
            "evaluation_rows_with_features_seen_in_train": int(np.isin(group[evaluation], group[training]).sum()),
            "evaluation_reuses_validation": profile == "row-reference"}
    write_json(shards / "manifest.json", {"inputs": x.shape[1], "files": files, "overlap_audit": overlaps})
    sources = [Path("trustlessfl") / name for name in
               ("__init__.py", "endpoint.py", "endpoint_torch.py", "endpoint_public.py", "endpoint_public_flower.py")]
    for path in sources:
        shutil.copyfile(path, app / "trustlessfl" / path.name)
    cfg = tomllib.loads(Path("configs/endpoint/flower-pyproject.toml").read_text())
    cfg["project"]["name"] = "trustlessfl-endpoint-public"
    cfg["project"]["description"] = "Public MLP/Adam configuration port; not paper reproduction"
    cfg["project"]["dependencies"].append("torch==2.8.0+cu128")
    cfg["tool"]["flwr"]["app"]["components"] = {
        "clientapp": "trustlessfl.endpoint_public_flower:client_app", "serverapp": "trustlessfl.endpoint_public_flower:server_app"}
    cfg["tool"]["flwr"]["app"]["config"] = {"data-dir": str(shards), "output-dir": str(output / "runtime-results"),
        "num-clients": 1, "backend": "torch-cuda", "device": "cuda:0", "seeds": ",".join(map(str, seeds)),
        "profiles": ",".join(profiles), "max-epochs": max_epochs, "batch-size": 500,
        "learning-rate": .01, "patience": 5, "timeout": 600.0}
    with (app / "pyproject.toml").open("x") as stream:
        stream.write(tomli_w.dumps(cfg))
    sources += [Path(__file__), Path("experiments/run_endpoint.py"), Path("experiments/run_endpoint_flower.py"),
                Path("configs/endpoint/flower-pyproject.toml"), Path("uv.lock")]
    upstream_root = Path(".cache/endpoint/source-audit-2026-09-13")
    upstream_manifest = json.loads((upstream_root / "manifest.json").read_text())
    if upstream_manifest["commit"] != COMMIT:
        raise ValueError("Wrong upstream commit")
    upstream = [item for item in upstream_manifest["files"] if item["path"] in
                ("training/mlp.py", "training/training30.ipynb", "training/training300.ipynb")]
    for item in upstream:
        if hashlib.sha256((upstream_root / item["path"]).read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError("Upstream source changed")
    write_json(output / "provenance.json", {"versions": {p: importlib.metadata.version(p) for p in ("flwr", "ray", "numpy", "torch")},
        "sources": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}, "upstream": upstream,
        "upstream_commit": COMMIT, "model": "31->30->30->9; two ReLUs; log_softmax then CrossEntropyLoss",
        "optimizer": "Adam lr=.01 betas=(.9,.999) eps=1e-8 weight_decay=0 foreach=False; persistent across epochs",
        "selection": "Epoch-level validation macro recall (macro accuracy); strict improvement, patience=5, min_delta=0; first best checkpoint",
        "deviations": ["PyTorch port on Flower; original Lightning callbacks/batch metric logging not executed",
            "Explicit epoch-level macro accuracy instead of Lightning Validation/Accuracy batch-logging semantics",
            "Fixed initialization/shuffle seeds and row-split seed=42", "V2 has 31 inputs,171053 rows; upstream notebook inputs differ",
            "Existing released normalization retained; no extra scaling or feature selection",
            "Single GPU, no DataLoader subprocesses; explicit randperm; no original notebook RNG sequence guarantee",
            "Independent group-holdout profile is intentionally different from upstream row split"],
        "verification": "CUDA float32 metadata, best-checkpoint selection, CPU checkpoint confusion equality and loss atol=1e-5",
        "security": "None; centralized public-data diagnostic", "overlap_audit": overlaps})


def verify_run(output):
    from trustlessfl.endpoint_public import PublicMLP, arrays, evaluate_arrays
    import torch
    candidates = list((output / "runtime-results").glob("run-*/results.json"))
    if len(candidates) != 1:
        raise ValueError("Expected one completed run")
    result_path = candidates[0]
    result = json.loads(result_path.read_text())
    cfg = result["config"]
    manifest = json.loads((Path(cfg["data-dir"]) / "manifest.json").read_text())
    for name, sha in manifest["files"].items():
        if hashlib.sha256((Path(cfg["data-dir"]) / name).read_bytes()).hexdigest() != sha:
            raise ValueError("Modified shard")
    expected = [(profile, int(seed)) for profile in cfg["profiles"].split(",") for seed in cfg["seeds"].split(",")]
    if [(c["profile"], c["seed"]) for c in result["cases"]] != expected:
        raise ValueError("Missing/repeated case")
    checks = []
    for case in result["cases"]:
        name = f"{case['profile']}-seed-{case['seed']}"
        checkpoints = {}
        for kind in ("initial", "best"):
            with np.load(result_path.parent / f"{name}-{kind}.npz", allow_pickle=False) as data:
                checkpoints[kind] = [data[f"arr_{i}"] for i in range(6)]
        torch.manual_seed(case["seed"])
        initial_ok = all(np.array_equal(a, b) for a, b in zip(arrays(PublicMLP(manifest["inputs"])), checkpoints["initial"]))
        scores = [h["monitor"] for h in case["history"]]
        best_epoch = int(np.argmax(scores)) + 1
        epoch_ok = [h["epoch"] for h in case["history"]] == list(range(1, case["stopped_epoch"] + 1))
        selection_ok = case["best_epoch"] == best_epoch and epoch_ok and case["stopped_epoch"] <= cfg["max-epochs"]
        loss_errors, cm_ok = [], True
        for split, recorded in (("validation", case["history"][best_epoch - 1]["validation"]), ("evaluation", case["evaluation"])):
            with np.load(Path(cfg["data-dir"]) / case["profile"] / f"{split}.npz", allow_pickle=False) as data:
                metrics = evaluate_arrays(checkpoints["best"], data["x"], data["y"], batch_size=cfg["batch-size"])
            cm_ok &= metrics["confusion_matrix"] == recorded["confusion_matrix"]
            loss_errors.append(abs(metrics["cross_entropy"] - recorded["cross_entropy"]))
        gpu_ok = case["meta"]["device"] == "cuda:0" and case["meta"]["dtype"] == "torch.float32"
        passed = initial_ok and selection_ok and cm_ok and max(loss_errors) <= 1e-5 and gpu_ok
        checks.append({"case": name, "passed": bool(passed), "initial_exact": initial_ok, "selection_ok": selection_ok,
                       "confusion_exact": cm_ok, "loss_errors": loss_errors, "gpu_ok": gpu_ok})
    passed = all(c["passed"] for c in checks)
    path = output / "verification.json"
    if path.exists():
        path = output / f"verification-{uuid.uuid4().hex[:8]}.json"
    write_json(path, {"passed": passed, "checks": checks, "run_id": result["run_id"]})
    if not passed:
        raise AssertionError("Checkpoint verification failed; see verification.json")
    print(json.dumps({"passed": passed, "run_id": result["run_id"], "cases": [
        {"profile": c["profile"], "seed": c["seed"], "best_epoch": c["best_epoch"],
         "stopped_epoch": c["stopped_epoch"], "macro_f1": c["evaluation"]["macro_f1"],
         "evaluation_kind": c["evaluation_kind"]} for c in result["cases"]]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data", type=Path, default=Path(".cache/endpoint/v2"))
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--profiles", nargs="+", choices=PROFILES, default=list(PROFILES))
    parser.add_argument("--max-epochs", type=int, default=150)
    parser.add_argument("--phase", choices=("all", "prepare", "run", "verify"), default="all")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.phase in ("all", "prepare"):
        stage(output, args.data.resolve(), args.seeds, args.profiles, args.max_epochs)
    if args.phase in ("all", "run"):
        run(output)
    if args.phase in ("all", "run", "verify"):
        verify_run(output)


if __name__ == "__main__":
    main()
