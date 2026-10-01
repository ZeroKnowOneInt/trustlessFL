"""Stage and run an Endpoint FAB via flwr run and the official Ray runtime."""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import tomllib
import uuid

import numpy as np
import tomli_w

from experiments.run_endpoint import prepare, write_json
from trustlessfl.endpoint import MLP, evaluate, train_delta


def absolute_pythonpath(value: str, cwd: Path) -> str:
    """Keep import paths stable when the Flower CLI switches to the FAB directory."""
    return os.pathsep.join(str((cwd / entry).resolve()) for entry in value.split(os.pathsep))


def require_completed_run(status):
    """CLI/list success is not application success; use the actual run state.

    Each attempt has its own FLWR_HOME and newly started SuperLink, so exactly
    one terminal completed run is expected. Do not log status-details, which
    can include application exception values.
    """
    runs = status.get("runs") if isinstance(status, dict) else None
    if (not isinstance(status, dict) or status.get("success") is not True) or (
            not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict)):
        raise RuntimeError("Official Flower run status is missing or not uniquely identified")
    if runs[0].get("status") != "finished:completed":
        raise RuntimeError("Official Flower application did not finish successfully; inspect run-status.json")
    return runs[0]


def stage(output, data, rounds, backend="numpy"):
    if backend not in ("numpy", "torch-cuda") or rounds < 1:
        raise ValueError("Invalid backend or rounds")
    output.mkdir(parents=True, exist_ok=False)
    shards, app = output / "shards", output / "app"
    shards.mkdir()
    (app / "trustlessfl").mkdir(parents=True)
    x, y, device, part, group, audit = prepare(data)
    write_json(output / "data-audit.json", audit)
    np.savez_compressed(output / "split.npz", split=part, group=group, client=device)
    files = {}
    for i in range(8):
        for code, split in ((0, "train"), (2, "test")):
            selected = (device == i) & (part == code)
            path = shards / f"client-{i}-{split}.npz"
            np.savez_compressed(path, x=x[selected], y=y[selected])
            files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(shards / "manifest.json", {"inputs": x.shape[1], "files": files})
    for name in ("__init__.py", "endpoint.py", "endpoint_flower.py", "endpoint_torch.py"):
        shutil.copyfile(Path("trustlessfl") / name, app / "trustlessfl" / name)
    config = tomllib.loads(Path("configs/endpoint/flower-pyproject.toml").read_text())
    config["tool"]["flwr"]["app"]["config"].update({
        "data-dir": str(shards), "output-dir": str(output / "runtime-results"), "rounds": rounds,
        "backend": backend, "timeout": 300.0 if backend == "torch-cuda" else 120.0})
    if backend == "torch-cuda":
        config["project"]["dependencies"].append("torch==2.8.0+cu128")
    with (app / "pyproject.toml").open("x") as stream:
        stream.write(tomli_w.dumps(config))
    write_json(output / "provenance.json", {
        "versions": {p: importlib.metadata.version(p) for p in
                     (("flwr", "ray", "numpy", "torch") if backend == "torch-cuda" else ("flwr", "ray", "numpy"))},
        "sources": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                    (Path(__file__), Path("trustlessfl/endpoint.py"), Path("trustlessfl/endpoint_flower.py"),
                     Path("trustlessfl/endpoint_torch.py"), Path("pyproject.toml"), Path("uv.lock"),
                     Path("experiments/run_endpoint.py"), Path("configs/endpoint/flower-pyproject.toml"))},
        "backend": backend,
        "model_atol": 1e-8 if backend == "torch-cuda" else 0.0,
        "comparison": "Every round: finite float64 models within absolute tolerance; exact confusion matrices; "
                      "cross-entropy difference <= 1e-8. CUDA additionally requires all 96 training replies "
                      "(for 3 rounds) on cuda:0, float64, one worker PID; no CPU fallback.",
        "security": "None; public-data plaintext simulation; not an AION run"})


def run(output):
    superlink = shutil.which("flower-superlink")
    flwr = shutil.which("flwr")
    if not superlink or not flwr:
        raise FileNotFoundError("Flower CLI and flower-superlink must be on PATH")
    config = tomllib.loads((output / "app" / "pyproject.toml").read_text())["tool"]["flwr"]["app"]["config"]
    gpu = config.get("backend", "numpy") == "torch-cuda"
    attempt = output / f"attempt-{uuid.uuid4().hex[:8]}"
    attempt.mkdir()
    flower_dir = attempt / "flower-home"
    flower_dir.mkdir()
    env = os.environ.copy()
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = absolute_pythonpath(env["PYTHONPATH"], Path.cwd())
    env.update({"FLWR_HOME": str(flower_dir), "FLWR_TELEMETRY_ENABLED": "0", "FLWR_DISABLE_UPDATE_CHECK": "1",
                "RAY_USAGE_STATS_ENABLED": "0", "OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1",
                "MKL_NUM_THREADS": "1", "PATH": str(Path(sys.executable).parent) + os.pathsep + env["PATH"]})
    if gpu:
        env["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
        # Probe in a separate process, releasing its CUDA context before Ray starts.
        probe = subprocess.run([sys.executable, "-m", "trustlessfl.endpoint_torch"], env=env,
                               cwd=output / "app", capture_output=True, text=True, timeout=120)
        (attempt / "cuda-preflight.log").write_text(probe.stdout + probe.stderr)
        probe.check_returncode()
        write_json(attempt / "cuda-preflight.json", json.loads(probe.stdout))
    # Reserve distinct free loopback ports; never connect to someone else's runtime.
    sockets = [socket.socket(), socket.socket()]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        control, runtime = [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()
    with (flower_dir / "config.toml").open("x") as stream:
        stream.write(tomli_w.dumps({"superlink": {"default": "endpoint-test", "endpoint-test": {
            "address": f"127.0.0.1:{control}", "insecure": True}}}))
    server_command = [superlink, "--insecure", "--simulation",
                      "--isolation", "subprocess", "--disable-runtime-dependency-installation",
                      "--control-api-address", f"127.0.0.1:{control}",
                      "--host", "127.0.0.1", "--port", str(runtime)]
    cpu_workers = int(config.get("simulation-workers", 2))
    if cpu_workers < 1:
        raise ValueError("simulation-workers must be positive")
    resources = ("client-resources-num-gpus=1 init-args-num-cpus=1 init-args-num-gpus=1" if gpu else
                 f"client-resources-num-gpus=0 init-args-num-cpus={cpu_workers} init-args-num-gpus=0")
    node_count = int(config.get("num-clients", 8))
    if node_count < 1:
        raise ValueError("Positive node count required")
    cli_command = [flwr, "run", str(output / "app"), "endpoint-test", "--stream",
                   "--federation-config", f"num-supernodes={node_count} client-resources-num-cpus=1 " + resources]
    write_json(attempt / "commands.json", {"superlink": server_command, "flwr": cli_command,
                                          "env": {k: env[k] for k in ("FLWR_HOME", "FLWR_TELEMETRY_ENABLED",
                                                   "OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS",
                                                   *( ["CUBLAS_WORKSPACE_CONFIG"] if gpu else []))}})
    with (attempt / "superlink.log").open("x") as server_log:
        server = subprocess.Popen(server_command, env=env, stdout=server_log,
                                  stderr=subprocess.STDOUT, start_new_session=True)
        try:
            deadline = time.monotonic() + 45
            while True:
                if server.poll() is not None:
                    raise RuntimeError(f"SuperLink exited; see {attempt / 'superlink.log'}")
                try:
                    with socket.create_connection(("127.0.0.1", control), timeout=.5):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("SuperLink startup timeout")
                    time.sleep(.25)
            print(f"Running official Flower CLI; logs: {attempt}", flush=True)
            started = time.perf_counter()
            with (attempt / "flwr.log").open("x") as cli_log:
                subprocess.run(cli_command, env=env, stdout=cli_log, stderr=subprocess.STDOUT,
                               cwd=output / "app", check=True,
                               timeout=int(config.get("runtime-cli-timeout", 1200 if gpu else 600)))
            write_json(attempt / "timing.json", {"flwr_cli_wall_seconds": time.perf_counter() - started})
            with (attempt / "run-status.json").open("x") as status:
                subprocess.run([flwr, "list", "--format", "json"], env=env,
                               stdout=status, stderr=subprocess.STDOUT, check=True, timeout=30)
            require_completed_run(json.loads((attempt / "run-status.json").read_text()))
        finally:
            # Only signal the process group created above, not unrelated Flower/Ray jobs.
            if server.poll() is None:
                os.killpg(server.pid, signal.SIGTERM)
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid, signal.SIGKILL)
                    server.wait(timeout=5)


def verify_run(output):
    candidates = list((output / "runtime-results").glob("run-*/results.json"))
    if len(candidates) != 1:
        raise RuntimeError("Expected exactly one complete Flower result")
    result_file = candidates[0]
    result = json.loads(result_file.read_text())
    config = result["config"]
    gpu = config.get("backend", "numpy") == "torch-cuda"
    atol = 1e-8 if gpu else 0.0
    provenance = json.loads((output / "provenance.json").read_text())
    if provenance.get("model_atol", 0.0) != atol:
        raise ValueError("Verification tolerance differs from predeclared provenance")
    shards = Path(config["data-dir"])
    manifest = json.loads((shards / "manifest.json").read_text())
    for name, sha in manifest["files"].items():
        if hashlib.sha256((shards / name).read_bytes()).hexdigest() != sha:
            raise ValueError("Shard changed since preparation")
    train, test = [], []
    for i in range(8):
        for split, target in (("train", train), ("test", test)):
            with np.load(shards / f"client-{i}-{split}.npz", allow_pickle=False) as data:
                target.append((data["x"], data["y"]))
    model = MLP(manifest["inputs"])
    expected_cases = {f"mu-{mu:g}-{condition}" for mu in (0., .1) for condition in ("clean", "poison")}
    if len(result["cases"]) != 4 or {c["case"] for c in result["cases"]} != expected_cases:
        raise ValueError("Expected exactly the four fixed experiment cases")
    checks, training = [], []
    for case in result["cases"]:
        if [h["round"] for h in case["history"]] != list(range(int(config["rounds"]) + 1)):
            raise ValueError("Missing or repeated history round")
        with np.load(result_file.parent / f"{case['case']}-models.npz", allow_pickle=False) as data:
            actual = data["models"]
        if (actual.shape != (int(config["rounds"]) + 1, model.dimension)
                or actual.dtype != np.float64 or not np.isfinite(actual).all()):
            raise ValueError("Invalid checkpoint shape or non-finite weights")
        weights, errors, confusion_matches, loss_errors = model.initialize(result["seed"]), [], [], []
        for round_id in range(int(config["rounds"]) + 1):
            if round_id:
                deltas = [train_delta(model, weights, xx, (yy + 1) % 9 if i in case["attackers"] else yy,
                                      seed=result["seed"], client=i, round_id=round_id,
                                      learning_rate=config["learning-rate"], epochs=config["epochs"],
                                      batch_size=config["batch-size"], mu=case["mu"])
                          for i, (xx, yy) in enumerate(train)]
                weights = weights + np.mean(deltas, axis=0)
            error = float(np.max(np.abs(actual[round_id] - weights)))
            errors.append(error)
            metrics = [evaluate(model, weights, xx, yy) for xx, yy in test]
            cm = sum(np.asarray(m["confusion_matrix"]) for m in metrics)
            actual_metrics = [evaluate(model, actual[round_id], xx, yy) for xx, yy in test]
            actual_cm = sum(np.asarray(m["confusion_matrix"]) for m in actual_metrics)
            recorded = case["history"][round_id]["test"]
            confusion_matches.append(bool(np.array_equal(cm, recorded["confusion_matrix"])
                                          and np.array_equal(actual_cm, recorded["confusion_matrix"])))
            n = sum(len(yy) for _, yy in test)
            losses = [sum(m["cross_entropy"] * len(yy) for m, (_, yy) in zip(items, test)) / n
                      for items in (metrics, actual_metrics)]
            loss_errors.append(max(abs(loss - recorded["cross_entropy"]) for loss in losses))
            training.extend(case["history"][round_id]["training_meta"])
        checks.append({"case": case["case"], "max_abs_error_by_round": errors,
                       "exact_match": all(e == 0 for e in errors),
                       "confusion_matches": confusion_matches, "cross_entropy_errors": loss_errors,
                       "passed": all(e <= atol for e in errors) and all(confusion_matches)
                                 and all(e <= 1e-8 for e in loss_errors),
                       "final_test": case["history"][-1]["test"]})
    pids = sorted({m["pid"] for m in training})
    gpu_verified = (len(training) == 8 * 4 * int(config["rounds"]) and len(pids) == 1
                    and all(m.get("device") == "cuda:0" and m.get("dtype") == "torch.float64"
                            and m.get("peak-allocated-bytes", 0) > 0 for m in training)) if gpu else None
    passed = all(c["passed"] for c in checks) and (gpu_verified if gpu else True)
    verification = {"run_id": result["run_id"], "cases": checks, "model_atol": atol,
                    "all_exact": all(c["exact_match"] for c in checks), "passed": passed,
                    "gpu_verified": gpu_verified, "worker_pids": pids, "training_replies": len(training)}
    verification_path = output / "verification.json"
    if verification_path.exists():
        verification_path = output / f"verification-{uuid.uuid4().hex[:8]}.json"
    write_json(verification_path, verification)
    if not passed:
        raise AssertionError("Official Runtime differs from sequential reference")
    print(json.dumps({"run_id": result["run_id"], "verification": str(verification_path),
                      "passed": passed, "all_exact": verification["all_exact"],
                      "gpu_verified": gpu_verified,
                      "cases": [{"case": c["case"], "macro_f1": c["final_test"]["macro_f1"]} for c in checks]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data", type=Path, default=Path(".cache/endpoint/v2"))
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--backend", choices=("numpy", "torch-cuda"), default="numpy",
                        help="Applied at preparation; run/verify use the staged configuration")
    parser.add_argument("--phase", choices=("all", "prepare", "run", "verify"), default="all")
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error("Positive rounds required")
    output = args.output.resolve()
    if args.phase in ("all", "prepare"):
        stage(output, args.data.resolve(), args.rounds, args.backend)
    if args.phase in ("all", "run"):
        run(output)
    if args.phase in ("all", "run", "verify"):
        verify_run(output)


if __name__ == "__main__":
    main()
