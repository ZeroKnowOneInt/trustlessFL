"""Export public diagnostic metrics, keeping datasets and checkpoints in cache."""

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from experiments.run_endpoint import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, default=Path("docs/experiments/endpoint-plaintext-2026-09-13"))
    args = parser.parse_args()
    verification = json.loads((args.run / "verification.json").read_text())
    if not verification["passed"]:
        raise ValueError("Cannot export an unverified result")
    results = list((args.run / "runtime-results").glob("run-*/results.json"))
    if len(results) != 1:
        raise ValueError("Expected one result")
    result = json.loads(results[0].read_text())
    baseline_config = json.loads((args.baseline / "config.json").read_text())
    baseline_audit = json.loads((args.baseline / "data-audit.json").read_text())
    audit = json.loads((args.run / "data-audit.json").read_text())
    baseline_split = Path(baseline_config["output"]) / "split.npz"
    with np.load(args.run / "split.npz", allow_pickle=False) as current, np.load(baseline_split, allow_pickle=False) as previous:
        split_equal = all(np.array_equal(current[a], previous[b]) for a, b in
                          (("split", "split"), ("client", "client"), ("group", "feature_group")))
    if not split_equal or audit != baseline_audit:
        raise ValueError("Baseline data or split differs")
    if (result["config"]["learning-rate"] != .1 or baseline_config["batch_size"] != result["config"]["batch-size"]
            or baseline_config["rounds"] * baseline_config["epochs"] != result["config"]["steps"] * result["config"]["epochs-per-step"]):
        raise ValueError("Exposure or training settings differ")
    rows = [{"method": "centralized", "seed": c["seed"], **c["history"][-1]["metrics"]["test"]["pooled"]}
            for c in result["cases"]]
    baseline = json.loads((args.baseline / "summary.json").read_text())
    rows += [{**r, "method": "fl-equal-average"} for r in baseline if r["mu"] == 0 and not r["poison"]]
    summary = []
    for method in ("centralized", "fl-equal-average"):
        selected = [r for r in rows if r["method"] == method]
        if sorted(r["seed"] for r in selected) != sorted(c["seed"] for c in result["cases"]):
            raise ValueError("Seed mismatch")
        item = {"method": method, "seeds": [r["seed"] for r in selected]}
        for key in ("macro_f1", "normal_false_positive_rate", "malware_false_negative_rate", "device_macro_f1_min"):
            values = [r[key] for r in selected]
            item[key] = {"mean": float(np.mean(values)), "sample_std": float(np.std(values, ddof=1))}
        summary.append(item)
    args.output.mkdir(parents=True, exist_ok=False)
    write_json(args.output / "results.json", result)
    write_json(args.output / "summary.json", {"comparison": summary, "rows": rows, "same_data_and_split": True,
        "baseline_runtime": "NumPy sequential; learning quality comparison only, not runtime timing comparison"})
    write_json(args.output / "provenance.json", {"runtime": json.loads((args.run / "provenance.json").read_text()),
        "run_id": result["run_id"], "verification_passed": verification["passed"],
        "files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                  (results[0], args.run / "verification.json", args.baseline / "summary.json", baseline_split,
                   args.run / "split.npz")}})
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
