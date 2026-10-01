"""Compare verified masked AION-MGF and no-filter Flower runs on matching inputs."""

import argparse
import hashlib
import json
from pathlib import Path

from experiments.run_fmnist_official import verify
from trustlessfl.crypto import canonical

CONDITION_FIELDS = ("population", "participants", "aggregators", "rounds", "seed",
    "attack_clients", "attack_rounds", "checkpoint_sha256", "partition_sha256",
    "poison_indices_sha256", "partition_rng_policy", "poison_rng_policy",
    "cohort_sampling", "schedule", "input_sha256", "simulation_workers")


def conditions(source, mode):
    source = Path(source).resolve()
    provenance = json.loads((source / "provenance.json").read_text())
    root = source / mode / "provision"
    manifest = json.loads((root / provenance["case"] / "manifest.json").read_text())
    catalog = json.loads((root / "catalog.json").read_text())[provenance["case"]]
    profiles = []
    for index in range(provenance["population"]):
        node = catalog[str(index)]
        for field, filename in (("fmnist-shard", f"client-{index}.npz"),
                                ("fmnist-reference", "reference.npz")):
            if Path(node[field]).resolve() != source / "inputs" / filename:
                raise ValueError(f"training path differs from staged input: {field}")
        profile = {field: node[field] for field in
                   ("fmnist-seed", "fmnist-epochs", "fmnist-batch-size", "fmnist-device")}
        if profile["fmnist-seed"] != provenance["seed"]:
            raise ValueError("training seed differs from experiment seed")
        attack = node.get("fmnist-attack")
        if (attack is not None) != (index < provenance["attack_clients"]):
            raise ValueError("training attacker identity differs from staged experiment")
        if attack is not None:
            for field, filename in (("clean_path", "attack-clean.npz"),
                                    ("poison_path", "attack-poison.npz")):
                if Path(attack[field]).resolve() != source / "inputs" / filename:
                    raise ValueError("attack path differs from staged input")
            profile["attack"] = {key: attack[key] for key in ("rounds", "steps", "boost", "poison_batch")}
            if attack["rounds"] != provenance["attack_rounds"]:
                raise ValueError("training attack schedule differs from experiment")
        profiles.append(profile)
    return {**{field: provenance[field] for field in CONDITION_FIELDS},
            "training_profiles": profiles,
            "learning_rate": manifest["parameters"]["learning_rate"],
            "decimals": manifest["parameters"]["decimals"],
            "training_source_sha256": {filename: provenance["source_sha256"][filename]
                                       for filename in ("trustlessfl/fmnist.py", "trustlessfl/numeric.py")}}


def require_matching(defense, control):
    if defense != control:
        differing = [field for field in set(defense) | set(control)
                     if defense.get(field) != control.get(field)]
        raise ValueError("Flower experiment conditions differ: " + ", ".join(sorted(differing)))


def compare(defense, control, output):
    defense, control, output = Path(defense).resolve(), Path(control).resolve(), Path(output)
    settings = conditions(defense, "aion_mgf_beta")
    require_matching(settings, conditions(control, "quantized"))
    # Revalidate sources, input hashes, certificates, selection, model state,
    # and metrics; an old verification.json alone is not sufficient evidence.
    verify(defense)
    verify(control)
    verified = {label: json.loads((source / "verification.json").read_text())[mode]
                for label, source, mode in (("masked_mgf", defense, "aion_mgf_beta"),
                                           ("no_filter", control, "quantized"))}
    curves = {label: run["curve"] for label, run in verified.items()}
    if curves["masked_mgf"][0] != curves["no_filter"][0]:
        raise ValueError("Flower experiments start from different evaluated checkpoints")
    selections = [{"round": row["round"], "selected_count": row["selected_count"],
                   "selected_attackers": [name for name in row["selected"]
                       if int(name.removeprefix("client-")) < settings["attack_clients"]]}
                  for row in verified["masked_mgf"]["selections"]]
    result = {"scope": "matched official Flower experiments; not a privacy proof or paper-scale timing reproduction",
              "population": settings["population"], "participants": settings["participants"],
              "rounds": settings["rounds"], "seed": settings["seed"],
              "attack_rounds": settings["attack_rounds"], "curves": curves,
              "masked_selection": selections,
              "condition_sha256": hashlib.sha256(canonical(settings)).hexdigest(),
              "sources": {label: {"run_id": run["run_id"], "seconds": run["seconds"],
                  "verification_sha256": hashlib.sha256((source / "verification.json").read_bytes()).hexdigest(),
                  "provenance_sha256": hashlib.sha256((source / "provenance.json").read_bytes()).hexdigest()}
                  for label, source, run in (("masked_mgf", defense, verified["masked_mgf"]),
                                            ("no_filter", control, verified["no_filter"]))}}
    output.mkdir(parents=True, exist_ok=False)
    (output / "results.json").write_bytes(canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--defense", type=Path, required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.defense, args.control, args.output)
    print(json.dumps({"output": str(args.output), "curves": result["curves"],
                      "selection": result["masked_selection"]}, indent=2))


if __name__ == "__main__":
    main()
