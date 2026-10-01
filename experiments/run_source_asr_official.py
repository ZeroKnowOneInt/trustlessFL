"""Stage a fresh source-ASR task and run it via official Flower SuperLink/Ray.

Reuses only public workload settings from --prepared; no old actor Context,
personal key, mask seed or VSS share is imported.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tomllib

import tomli_w

from trustlessfl.aion_source_asr import source_inventory
from trustlessfl.aion_source_server import provision_source
from trustlessfl.crypto import canonical
from trustlessfl.aion_source_cohort import make_cohorts


def stage(prepared, output, *, workers=2, rounds=None, attack_rounds=None):
    prepared, output = Path(prepared), Path(output).resolve()
    original = json.loads((prepared / "manifest.json").read_text())
    if workers < 1 or workers > len(original["clients"]) + 1:
        raise ValueError("invalid simulation worker count")
    count = original["rounds"] if rounds is None else rounds
    if count < 1:
        raise ValueError("positive rounds required")
    if source_inventory(original["source-root"]) != original["source-sha256"]:
        raise ValueError("prepared author snapshot changed")
    training = dict(original["training"]) if original.get("training") else None
    if attack_rounds is not None:
        if (not training or not training["attack_clients"] or not attack_rounds
                or any(type(r) is not int or not 1 <= r <= count for r in attack_rounds)
                or len(set(attack_rounds)) != len(attack_rounds)):
            raise ValueError("invalid staged attack schedule")
        training["attack_rounds"] = sorted(attack_rounds)
    if original["workload"] == "fmnist" and not training:
        raise ValueError("FMNIST stage requires pinned prepared training inputs")
    if training:
        inputs = Path(training["input_root"])
        for name, sha in training["input_sha256"].items():
            if hashlib.sha256((inputs / name).read_bytes()).hexdigest() != sha:
                raise ValueError("prepared training inputs changed")
        if any(r > count for r in training["attack_rounds"]):
            raise ValueError("attack schedule exceeds staged round count")
    schedule = original.get("cohort_schedule")
    participation = original.get("participation")
    if participation:
        schedule = make_cohorts(len(original["clients"]), participation["participants"], count,
            malicious=training["attack_clients"] if training else 0,
            attack_rounds=training["attack_rounds"] if training else (), seed=participation["seed"])
    path, nodes = provision_source(output, original["source-root"],
        clients=len(original["clients"]), committee=len(original["committee"]),
        dimension=original["dimension"], rounds=count, workload=original["workload"],
        decimals=original["decimals"], max_abs=original["max_abs"],
        learning_rate=original["learning_rate"], cohort_schedule=schedule,
        paper_numerics=original.get("paper_numerics"))
    manifest = json.loads(path.read_text())
    if participation:
        manifest["participation"] = participation
    if training:
        manifest["training"] = {**training}
        evaluation_names = ["test.npz"] + (["poison-test.npz"] if training["attack_clients"] else [])
        manifest["training"]["evaluation_sha256"] = {name: hashlib.sha256((inputs / name).read_bytes()).hexdigest()
                                                        for name in evaluation_names}
        for i in manifest["clients"]:
            nodes[i + 1].update({"fmnist-shard": str(inputs / f"client-{i}.npz"),
                "fmnist-reference": str(inputs / "reference.npz"), "fmnist-seed": training["seed"],
                "fmnist-epochs": training["epochs"], "fmnist-batch-size": 64})
            if i < training["attack_clients"]:
                nodes[i + 1]["fmnist-attack"] = dict(rounds=training["attack_rounds"],
                    clean_path=str(inputs / "attack-clean.npz"), poison_path=str(inputs / "attack-poison.npz"),
                    steps=training["attack_steps"], boost=training["attack_boost"], poison_batch=training["poison_batch"])
    path.write_bytes(canonical(manifest))
    catalog = output / "node-configs.json"
    catalog.write_bytes(canonical([nodes[i] for i in sorted(nodes)]))
    app = output / "app"
    package = app / "trustlessfl"
    package.mkdir(parents=True)
    inventory = {}
    repo = Path(__file__).resolve().parents[1]
    for source in sorted((repo / "trustlessfl").glob("*.py")):
        shutil.copyfile(source, package / source.name)
        inventory[source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
    config = tomllib.loads((repo / "configs/endpoint/flower-pyproject.toml").read_text())
    config["project"].update(name="trustlessfl-source-asr-runtime",
        description="Author Aion-ASR source port on official Flower simulation")
    config["tool"]["flwr"]["app"]["components"] = {
        "serverapp": "trustlessfl.aion_source_official:server_app",
        "clientapp": "trustlessfl.aion_source_official:client_app"}
    config["tool"]["flwr"]["app"]["config"] = {
        "aion-source-manifest": str(path), "source-manifest-sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "source-node-configs": str(catalog), "source-node-configs-sha256": hashlib.sha256(catalog.read_bytes()).hexdigest(),
        "num-clients": len(nodes), "simulation-workers": workers, "backend": "numpy",
        "timeout": 120.0, "runtime-cli-timeout": 1800}
    (app / "pyproject.toml").write_text(tomli_w.dumps(config))
    (output / "staging.json").write_bytes(canonical(dict(prepared=str(prepared.resolve()),
        source_sha256=inventory, app_config_sha256=hashlib.sha256((app / "pyproject.toml").read_bytes()).hexdigest(),
        scope="fresh actor Contexts; official local Flower simulation; not remote network measurement")))
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--rounds", type=int)
    parser.add_argument("--attack-rounds", type=int, nargs="+",
                        help="Override the prepared attack schedule for the fresh task")
    args = parser.parse_args()
    output = stage(args.prepared, args.output, workers=args.workers, rounds=args.rounds,
                   attack_rounds=args.attack_rounds)
    from experiments.run_endpoint_flower import run
    run(output)
    result = json.loads((output / "results.json").read_text())
    if len(result["history"]) != json.loads((output / "manifest.json").read_text())["rounds"]:
        raise RuntimeError("incomplete official source ASR run")
    print(json.dumps(dict(output=str(output), rounds=len(result["history"]),
        transport=result["transport"], key_share_deliveries=result["key_share_deliveries"],
        mask_share_deliveries=result["mask_share_deliveries"]), indent=2))


if __name__ == "__main__":
    main()
