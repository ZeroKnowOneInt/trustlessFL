"""Validate and export completed avg/AION pilot evidence without cached models."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from experiments.run_aion_artifact import summarize_rounds, write_json


def comparison_checks(avg, aion):
    for report in [avg, aion]:
        if report["status"] != "completed" or len(report["rounds"]) != report["requested_rounds"]:
            raise ValueError("incomplete run")
        if report["metrics"] != summarize_rounds(report["rounds"]):
            raise ValueError("metrics do not match raw rounds")
    checks = {
        "same_initial_model": avg["initial_model_sha256"] == aion["initial_model_sha256"],
        "same_partition": avg["partition_sha256"] == aion["partition_sha256"],
        "same_poison_schedule": avg["poison_rounds"] == aion["poison_rounds"],
        "same_first_round_participants": avg["rounds"][0]["participants"] == aion["rounds"][0]["participants"],
        "same_first_round_updates": avg["rounds"][0]["aggregation"]["updates_sha256"]
                                    == aion["rounds"][0]["aggregation"]["updates_sha256"],
    }
    if not all(checks.values()):
        raise ValueError(f"initial comparison is not controlled: {checks}")
    return checks


def repeat_checks(previous, current):
    def scientific_rows(report):
        return [{key: value for key, value in row.items() if key != "seconds"} for row in report["rounds"]]

    checks = {"same_initial_model": previous["initial_model_sha256"] == current["initial_model_sha256"],
              "same_partition": previous["partition_sha256"] == current["partition_sha256"],
              "same_rounds_except_timing": scientific_rows(previous) == scientific_rows(current),
              "same_metrics": previous["metrics"] == current["metrics"],
              "same_matrix": previous["matrix_840_sha256"] == current["matrix_840_sha256"]}
    if not all(checks.values()):
        raise ValueError(f"repeat differs: {checks}")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--avg", type=Path, required=True)
    parser.add_argument("--aion", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeat-of", type=Path, help="previous exported avg/aion results directory")
    options = parser.parse_args()
    reports = {rule: json.loads((getattr(options, rule) / "result.json").read_text())
               for rule in ["avg", "aion"]}
    checks = comparison_checks(reports["avg"], reports["aion"])
    repeats = {rule: repeat_checks(json.loads((options.repeat_of / f"{rule}-result.json").read_text()), reports[rule])
               for rule in reports} if options.repeat_of else None
    options.output.mkdir(parents=True, exist_ok=False)
    files = {}
    for rule in ["avg", "aion"]:
        root = getattr(options, rule)
        names = ["result.json", "rounds.jsonl", "source-hashes.json", "runtime.patch"]
        if (root / "adapter-used.py").exists():
            if hashlib.sha256((root / "adapter-used.py").read_bytes()).hexdigest() != reports[rule]["adapter_sha256"]:
                raise ValueError("adapter snapshot mismatch")
            names.append("adapter-used.py")
        for name in names:
            if name == "rounds.jsonl":
                rows = [json.loads(line) for line in (root / name).read_text().splitlines()]
                if rows != reports[rule]["rounds"]:
                    raise ValueError("JSONL differs from final report")
            target = options.output / f"{rule}-{name}"
            shutil.copyfile(root / name, target)
            files[target.name] = hashlib.sha256(target.read_bytes()).hexdigest()
    write_json(options.output / "comparison.json", {
        "checks": checks, "files_sha256": files,
        "repeat_checks": repeats,
        "later_round_participants_equal": [a["participants"] == b["participants"] for a, b
                                            in zip(reports["avg"]["rounds"][1:], reports["aion"]["rounds"][1:])],
        "secure_aggregation_executed": False, "paper_reproduction_complete": False,
        "interpretation": "bounded centralized artifact pilot; not a paper-result reproduction",
    })
    print(json.dumps({"checks": checks, "output": str(options.output)}, indent=2))


if __name__ == "__main__":
    main()
