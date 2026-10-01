"""Publish a completed FMNIST Flower run without private staging material."""

import argparse
import hashlib
import json
from pathlib import Path

from trustlessfl.crypto import canonical

PUBLIC_KEYS = {
    "aggregator_count", "assigned_rows", "attack_boost", "attack_clients",
    "attack_probability", "attack_rounds", "attack_steps", "batch_size",
    "checkpoint_sha256", "client_count", "curve", "events", "json_payload_bytes",
    "learning_rate", "local_epochs", "local_worker_processes",
    "participation_schedule", "partition", "partition_sha256", "poison_batch",
    "poison_pool_rows", "poison_pool_sha256", "population", "rounds", "scope",
    "wall_seconds",
}


def export(source: Path, output: Path) -> dict:
    raw = source.read_bytes()
    result = json.loads(raw)
    if (not isinstance(result, dict) or set(result) != PUBLIC_KEYS
            or result.get("rounds", 0) < 1
            or len(result.get("curve", [])) != result["rounds"] + 1
            or not isinstance(result.get("events"), list)
            or any(set(event) != {"action", "attempted_requests", "error_replies",
                                      "occurrence", "replies", "reply_payload_bytes",
                                      "request_payload_bytes", "requests", "seconds"}
                   for event in result["events"])):
        raise ValueError("source is not a complete public FMNIST Flower result")
    if canonical(result) != raw:
        raise ValueError("source result is not canonical or has changed")
    output.mkdir(parents=True, exist_ok=False)
    (output / "results.json").write_bytes(raw)
    metadata = {"source_sha256": hashlib.sha256(raw).hexdigest(),
                "result_file": "results.json", "scope": result["scope"]}
    (output / "export.json").write_bytes(canonical(metadata))
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.source, args.output), indent=2))


if __name__ == "__main__":
    main()
