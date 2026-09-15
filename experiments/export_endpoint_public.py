"""Export public-recipe results without presenting reused validation as test."""

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
    args = parser.parse_args()
    verification = json.loads((args.run / "verification.json").read_text())
    if not verification["passed"]:
        raise ValueError("Unverified run")
    candidates = list((args.run / "runtime-results").glob("run-*/results.json"))
    if len(candidates) != 1:
        raise ValueError("Expected one completed result")
    result = json.loads(candidates[0].read_text())
    manifest = json.loads((args.run / "shards/manifest.json").read_text())
    old_root = Path(".cache/endpoint/runs/central-flower-2026-09-13")
    with np.load(args.run / "split.npz", allow_pickle=False) as new, np.load(old_root / "split.npz", allow_pickle=False) as old:
        if not all(np.array_equal(new[k], old[k]) for k in ("split", "group", "client")):
            raise ValueError("Independent group split differs from earlier central baseline")
    if (json.loads((args.run / "data-audit.json").read_text()) !=
            json.loads((old_root / "data-audit.json").read_text())):
        raise ValueError("Different input data")
    summaries, details, curves = [], [], []
    for case in result["cases"]:
        details.append({k: v for k, v in case.items() if k != "history"})
        curves.extend({"profile": case["profile"], "seed": case["seed"], "epoch": row["epoch"],
            "monitor": row["monitor"], "best_so_far": row["improved"],
            **{f"{split}_{metric}": row[split][metric] for split in ("train", "validation")
               for metric in ("macro_f1", "macro_accuracy", "cross_entropy", "normal_false_positive_rate", "malware_false_negative_rate")}}
            for row in case["history"])
    for profile in result["config"]["profiles"].split(","):
        selected = [c for c in result["cases"] if c["profile"] == profile]
        item = {"profile": profile, "evaluation_kind": selected[0]["evaluation_kind"], "seeds": [c["seed"] for c in selected]}
        for metric in ("macro_f1", "accuracy", "normal_false_positive_rate", "malware_false_negative_rate"):
            values = [c["evaluation"][metric] for c in selected]
            item[metric] = {"mean": float(np.mean(values)), "sample_std": float(np.std(values, ddof=1)) if len(values) > 1 else None}
        summaries.append(item)
    args.output.mkdir(parents=True, exist_ok=False)
    write_json(args.output / "summary.json", {"run_id": result["run_id"], "profiles": summaries, "cases": details,
        "independent_split_matches_previous": True, "overlap_audit": manifest["overlap_audit"]})
    write_json(args.output / "curves.json", curves)
    write_json(args.output / "provenance.json", {"run": json.loads((args.run / "provenance.json").read_text()),
        "verification": verification, "files": {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
            (candidates[0], args.run / "verification.json", args.run / "split.npz", old_root / "split.npz")}})
    print(json.dumps(summaries, indent=2))


if __name__ == "__main__":
    main()
