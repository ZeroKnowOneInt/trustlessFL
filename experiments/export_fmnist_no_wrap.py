"""Export public FMNIST plaintext-reference results and standard scientific plots."""
import argparse
import json
from pathlib import Path

import numpy as np


def export(experiment, output):
    output.mkdir(parents=True, exist_ok=False)
    verifications = list(experiment.glob("verification*.json"))
    verified = json.loads(max(verifications, key=lambda p:p.stat().st_mtime).read_text())
    if not verified.get("passed") or not (verified.get("threshold_history_verified") or verified.get("dynamic_public_history_replay_matches")):
        raise RuntimeError("a verified threshold experiment is required")
    body = json.loads(next(experiment.glob("runtime-results/run-*/results.json")).read_text())
    attempts = [p.parent for p in experiment.glob("attempt-*/run-status.json")
                if json.loads(p.read_text())["runs"][0]["status"] == "finished:completed"]
    if len(attempts) != 1:
        raise RuntimeError("expected exactly one completed local Flower run")
    attempt = attempts[0]
    status = json.loads((attempt/"run-status.json").read_text())["runs"][0]
    timing = json.loads((attempt/"timing.json").read_text())
    provenance = json.loads((experiment/"provenance.json").read_text())
    mode=body["config"].get("threshold-mode","dynamic")
    summary = {"threshold_mode":mode,"date_KST": "2026-10-10", "flower_run_id": status["run-id"],
        "flower_status": status["status"], "fab_hash": status["fab-hash"],
        "versions": provenance["versions"], "config": provenance["config"],
        "flwr_cli_wall_seconds": timing["flwr_cli_wall_seconds"],
        "verification": verified, "model_dimension": 61706, "train_rows": 60000, "test_rows": 10000,
        "profiles": body["cases"][0]["history"][1]["profiles"],
        "threshold_rounds": [{k:r[k] for k in ("round", "accuracy", "squared_bound",
            "squared_norm_min", "squared_norm_max", "integer_mean_squared_norm", "accepted_count")}
            for r in body["cases"][-1]["history"][1:]],
        "privacy": "NONE: plaintext reference; diagnostic client norm range is for this public-data experiment only",
        "limitations": [f"Single seed, clean IID data, {body['config']['rounds']} rounds", "No poisoning-defense validation",
            "No MPC, VSS, BFT or cryptographic privacy in this Flower run", "Controlled [1,2] HPRF matrix, not author artifact",
            "No Hub publishing or changes to root project deployment/publisher settings"]}
    (output/"results.json").write_text(json.dumps(summary, indent=2))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))
    styles = {"fedavg": ("FedAvg", "#3465a4", "-", "o"),
              "quantized": ("Fixed-point", "#72747c", "--", "s"),
              "no-wrap-dynamic": ("No-wrap + dynamic bound", "#14865a", "-", "."),
              "no-wrap-static": ("No-wrap + static threshold", "#14865a", "-", ".")}
    for case in verified["cases"]:
        label, color, line, marker = styles[case["case"]]
        axes[0].plot(range(len(case["accuracy_by_round"])), np.asarray(case["accuracy_by_round"])*100,
                     label=label, color=color, linestyle=line, marker=marker, linewidth=1.8)
    axes[0].set(xlabel="Round", ylabel="Test accuracy (%)", ylim=(0, 100), xticks=range(body["config"]["rounds"]+1),
                title="Learning: same initialization / data / seed")
    axes[0].legend(fontsize=8, loc="lower right")
    S = body["config"]["scale"]
    rounds = summary["threshold_rounds"]
    rr = [r["round"] for r in rounds]
    minimum = [np.sqrt(r["squared_norm_min"])/S for r in rounds]
    maximum = [np.sqrt(r["squared_norm_max"])/S for r in rounds]
    axes[1].fill_between(rr, minimum, maximum, color="#14865a", alpha=.25, label="Normal client norm range")
    axes[1].plot(rr, maximum, color="#14865a", marker=".", linewidth=1)
    axes[1].plot(rr, [np.sqrt(r["squared_bound"])/S for r in rounds],
                 color="#c07218", marker="o", label="Static L2 threshold" if mode=="static" else "Dynamic L2 bound")
    axes[1].set(xlabel="Round", ylabel="L2 norm (real update units)", xticks=rr, ylim=(0, 5.5),
                title="Normal update norms and static threshold" if mode=="static" else "Normal update norms and dynamic boundary")
    axes[1].legend(fontsize=8)
    for axis in axes:
        axis.grid(alpha=.2)
    fig.suptitle(f"FMNIST / LeNet5: 4 clients, {body['config']['rounds']} rounds", fontsize=13)
    fig.text(.5, .015, "Plaintext arithmetic reference on the official Flower runtime; not MPC.",
             ha="center", fontsize=9, color="#555555")
    fig.tight_layout(rect=(0, .04, 1, .95))
    fig.savefig(output/"learning-and-boundary.png", dpi=180)
    fig.savefig(output/"learning-and-boundary.svg")
    plt.close(fig)
    print(json.dumps({"output": str(output), "passed": True}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    export(args.experiment.resolve(), args.output.resolve())


if __name__ == "__main__":
    main()
