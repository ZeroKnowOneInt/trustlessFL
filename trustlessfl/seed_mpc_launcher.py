"""Official Flower CLI local runtime, independent of research experiment tooling."""
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
import tomli_w


def write_json(path, body):
    with Path(path).open('x') as stream:
        json.dump(body, stream)

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


def save_run_status(flwr, env, attempt):
    """Keep diagnostic stderr separate from the CLI's JSON stdout."""
    path=attempt / 'run-status.json'
    with path.open('x') as status, (attempt / 'run-status.stderr.log').open('x') as errors:
        subprocess.run([flwr,'list','--format','json'],env=env,stdout=status,
                       stderr=errors,check=True,timeout=30)
    return require_completed_run(json.loads(path.read_text()))


def run(output):
    superlink = shutil.which("flower-superlink")
    flwr = shutil.which("flwr")
    if not superlink or not flwr:
        raise FileNotFoundError("Flower CLI and flower-superlink must be on PATH")
    config = tomllib.loads((output / "app" / "pyproject.toml").read_text())["tool"]["flwr"]["app"]["config"]
    gpu = False
    if config.get("backend", "numpy") != "numpy":
        raise ValueError("Seed-MPC user runtime currently supports CPU models")
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
    if config.get('seed-mpc-runtime-guard', False):
        bootstrap = attempt / 'runtime-bootstrap'
        bootstrap.mkdir()
        (bootstrap / 'sitecustomize.py').write_text(
            'import os, sys\n'
            'if os.environ.get("TRUSTLESSFL_FLOWER_RUNTIME_GUARD") == "1":\n'
            '    try:\n'
            '        import hashlib, json\n'
            '        from pathlib import Path\n'
            '        from trustlessfl import seed_mpc_flower_runtime as guard\n'
            '        actual = hashlib.sha256(Path(guard.__file__).read_bytes()).hexdigest()\n'
            '        if actual != os.environ["TRUSTLESSFL_FLOWER_GUARD_SHA256"]:\n'
            '            raise RuntimeError("runtime guard artifact differs")\n'
            '        guard.install()\n'
            '        evidence = Path(os.environ["TRUSTLESSFL_FLOWER_GUARD_EVIDENCE"])\n'
            '        (evidence / (str(os.getpid()) + ".json")).write_text(json.dumps({"installed": True, "source_sha256": actual}))\n'
            '    except Exception as error:\n'
            '        sys.stderr.write("seed-MPC runtime guard rejected: " + str(error) + "\\n")\n'
            '        sys.stderr.flush()\n'
            '        os._exit(78)\n')
        env['TRUSTLESSFL_FLOWER_RUNTIME_GUARD'] = '1'
        evidence = bootstrap / 'guards'
        evidence.mkdir()
        env['TRUSTLESSFL_FLOWER_GUARD_EVIDENCE'] = str(evidence.resolve())
        env['TRUSTLESSFL_FLOWER_GUARD_SHA256'] = config['seed-mpc-runtime-guard-sha256']
        env['PYTHONPATH'] = (str(bootstrap.resolve()) + os.pathsep + str((output / 'app').resolve())
                             + os.pathsep + env.get('PYTHONPATH', ''))
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
        stream.write(tomli_w.dumps({"superlink": {"default": "seed-mpc-local", "seed-mpc-local": {
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
    cli_command = [flwr, "run", str(output / "app"), "seed-mpc-local", "--stream",
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
            save_run_status(flwr, env, attempt)
        finally:
            # Only signal the process group created above, not unrelated Flower/Ray jobs.
            if server.poll() is None:
                os.killpg(server.pid, signal.SIGTERM)
                try:
                    server.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(server.pid, signal.SIGKILL)
                    server.wait(timeout=5)
