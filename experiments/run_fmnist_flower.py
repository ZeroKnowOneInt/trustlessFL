"""Run Fashion-MNIST/LeNet5 on the Flower AION ServerApp/ClientApp path.

This is an experiment-aligned clean-training bridge, not yet the paper's
60-round poisoning curves: the current protocol uses a fixed client cohort.
"""

import argparse
import hashlib
import json
import random
import tempfile
import time
import uuid
from pathlib import Path

import numpy as np
from flwr.app import Context, RecordDict

from experiments.prepare_fashion_mnist import RESOURCES, validate_resource
from experiments.probe_aion_checkpoint import CHECKPOINT_SHA256, checkpoint_arrays
from experiments.run_aion import Case, ObservedGrid
from trustlessfl.crypto import canonical
from trustlessfl.demo import provision
from trustlessfl.fmnist import (DIMENSION, FmnistTrainer, artifact_dirichlet_partition,
                                artifact_poison_indices, attack_success_rate,
                                evaluate, make_model, parameter_vector, TARGET_LABEL)
from trustlessfl.protocol import Parameters
from trustlessfl.server_app import app


def read_dataset(raw_dir: Path) -> dict[str, np.ndarray]:
    arrays = {}
    for name, (md5, header) in RESOURCES.items():
        content = (raw_dir / name).read_bytes()
        raw = validate_resource(content, md5, header)
        target = ("test" if name.startswith("t10k") else "train") + (
            "_x" if "images" in name else "_y")
        arrays[target] = np.frombuffer(raw, dtype=np.uint8, offset=4 * len(header)).copy().reshape(header[1:])
    return arrays


def pinned_reference(checkpoint: Path) -> np.ndarray:
    import torch

    content = checkpoint.read_bytes()
    if hashlib.sha256(content).hexdigest() != CHECKPOINT_SHA256:
        raise ValueError("FMNIST checkpoint differs from audited artifact")
    tensors = checkpoint_arrays(content)
    model = make_model()
    model.load_state_dict({name: torch.from_numpy(value) for name, value in tensors.items()}, strict=True)
    return parameter_vector(model)


def scheduled_cohorts(population: int, participants: int, malicious: int,
                      rounds: int, attack_rounds: list[int], seed: int) -> dict[str, list[str]]:
    """Sample complete two-client privacy groups from a fixed population."""
    if (population % 2 or participants % 2 or participants > population
            or malicious > participants or population < 4):
        raise ValueError("dynamic ASR sampling needs even population/q and sufficient capacity")
    group_count = population // 2
    chosen_groups = participants // 2
    mandatory = (malicious + 1) // 2
    if group_count - mandatory < chosen_groups or mandatory > chosen_groups:
        raise ValueError("insufficient benign privacy groups for attack/nonattack rounds")
    generator = random.Random(seed)
    result = {}
    for round_id in range(1, rounds + 1):
        if round_id in attack_rounds:
            groups = list(range(mandatory)) + generator.sample(
                range(mandatory, group_count), chosen_groups - mandatory)
        else:
            groups = generator.sample(range(mandatory, group_count), chosen_groups)
        selected = set(groups)
        result[str(round_id)] = [f"client-{i}" for i in range(population) if i // 2 in selected]
    return result


def scheduled_individual_cohorts(population: int, participants: int, malicious: int,
                                 rounds: int, attack_rounds: list[int], seed: int
                                 ) -> dict[str, list[str]]:
    """Use the artifact's individual-client inclusion rule and ordering.

    The staged schedule has its own seeded RNG. Original local training
    interleaves Python RNG calls, so this is not the full artifact transcript.
    """
    if (population < 2 or participants < 2 or participants > population
            or malicious < 0 or malicious > participants
            or population - malicious < participants or rounds < 1 or seed < 0
            or any(type(r) is not int or not 1 <= r <= rounds for r in attack_rounds)):
        raise ValueError("individual sampling needs enough benign clients")
    generator = random.Random(seed)
    benign = range(malicious, population)
    result = {}
    for round_id in range(1, rounds + 1):
        chosen = (list(range(malicious)) + generator.sample(benign, participants - malicious)
                  if round_id in attack_rounds else generator.sample(benign, participants))
        result[str(round_id)] = [f"client-{i}" for i in chosen]
    return result


def run(args) -> dict:
    population = args.population or args.clients
    if args.clients < 2 or args.aggregators < 4 or args.rounds < 1 or population < args.clients:
        raise ValueError("invalid client, aggregator, or round count")
    if ((args.workers is None and population + args.aggregators > 32)
            or (args.workers is not None and not 1 <= args.workers <= population + args.aggregators)):
        raise ValueError("large cohorts require an explicit bounded --workers setting")
    if (not 0 <= args.attack_clients <= args.clients // 2
            or not 0 <= args.attack_probability <= 1
            or args.attack_steps < 1 or not 0 < args.boost <= 100
            or not 0 < args.poison_batch < args.batch_size
            or (args.force_attack_rounds and args.attack_clients == 0)
            or any(r < 1 or r > args.rounds for r in args.force_attack_rounds)):
        raise ValueError("invalid FMNIST attack schedule or settings")
    data = read_dataset(args.data_dir)
    reference = pinned_reference(args.checkpoint)
    numpy_rng = np.random.RandomState(args.seed)
    python_rng = random.Random(args.seed)
    partitions = artifact_dirichlet_partition(data["train_y"], population,
                                               alpha=args.dirichlet_alpha, seed=args.seed,
                                               adversaries=args.attack_clients,
                                               rng_policy=args.partition_rng,
                                               numpy_rng=numpy_rng,
                                               python_rng=python_rng)
    if any(len(indices) == 0 for indices in partitions):
        raise ValueError("empty client shard; choose more training rows or fewer clients")
    poison_indices = artifact_poison_indices(
        data["test_y"], seed=args.seed,
        python_rng=python_rng if args.poison_rng == "artifact" else None)
    if args.force_attack_rounds:
        attack_rounds = sorted(set(args.force_attack_rounds))
    elif args.attack_clients:
        attack_rounds = (np.flatnonzero(numpy_rng.uniform(size=args.rounds)
                                      >= 1 - args.attack_probability) + 1).tolist()
    else:
        attack_rounds = []
    schedule = (scheduled_cohorts(population, args.clients, args.attack_clients,
                                  args.rounds, attack_rounds, args.seed)
                if population != args.clients else None)
    clients = tuple(f"client-{i}" for i in range(population))
    privacy_groups = (tuple(clients[i:i + 2] for i in range(0, population, 2))
                      if schedule is not None else ())
    p = Parameters(uuid.uuid4().hex, clients,
                   tuple(f"aggregator-{i}" for i in range(args.aggregators)),
                   faults=(args.aggregators - 1) // 3, dimension=DIMENSION,
                   decimals=args.decimals, learning_rate=args.learning_rate,
                   privacy_groups=privacy_groups)
    args.output.mkdir(parents=True, exist_ok=False)
    case = Case("fmnist-lenet5", clients=population,
                aggregators=args.aggregators, dimension=DIMENSION, rounds=args.rounds,
                learning_rate=args.learning_rate)
    with tempfile.TemporaryDirectory(prefix="aion-fmnist-") as temporary:
        root = Path(temporary)
        manifest, nodes = provision(root / "identities", p)
        schedule_path = root / "participation.json"
        if schedule is not None:
            schedule_path.write_bytes(canonical(schedule))
        reference_path = root / "reference.npz"
        np.savez(reference_path, weights=reference)
        if args.attack_clients:
            attack_clean = root / "attack-clean.npz"
            attack_poison = root / "attack-poison.npz"
            clean_selection = data["train_y"] != TARGET_LABEL
            np.savez(attack_clean, x=data["train_x"][clean_selection],
                     y=data["train_y"][clean_selection])
            np.savez(attack_poison, x=data["test_x"][poison_indices],
                     y=data["test_y"][poison_indices])
        trainers = []
        for i, indices in enumerate(partitions):
            shard = root / "identities" / f"client-{i}" / "fmnist.npz"
            np.savez(shard, x=data["train_x"][indices], y=data["train_y"][indices])
            nodes[i + 1].update({"fmnist-shard": str(shard),
                                 "fmnist-reference": str(reference_path),
                                 "fmnist-seed": args.seed, "fmnist-epochs": args.local_epochs,
                                 "fmnist-batch-size": args.batch_size,
                                 "fmnist-device": args.device})
            attack = None
            if i < args.attack_clients:
                attack = {"rounds": attack_rounds, "clean_path": str(attack_clean),
                          "poison_path": str(attack_poison), "steps": args.attack_steps,
                          "boost": args.boost, "poison_batch": args.poison_batch}
                nodes[i + 1]["fmnist-attack"] = attack
            trainers.append(FmnistTrainer(shard, reference_path, args.seed,
                                           args.local_epochs, args.batch_size,
                                           device=args.device, attack=attack))
        context = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(), run_config={
            "aion-manifest": str(manifest), "research-mode": True,
            "num-server-rounds": args.rounds, "timeout": args.timeout,
            **({"participation-schedule": str(schedule_path)} if schedule is not None else {})})
        started = time.perf_counter()
        with ObservedGrid(nodes, case, p, workers=args.workers) as grid:
            app(grid, context)
            events = grid.events
        wall = time.perf_counter() - started
        history = json.loads(context.state["aion-result"]["history"])
        models = [np.asarray(entry["body"]["model"], dtype=np.float64) for entry in history]
        baseline = None if args.no_baseline else [np.zeros(DIMENSION, dtype=np.float64)]
        if not args.no_baseline:
            for round_id in range(1, args.rounds + 1):
                selected_indices = (range(population) if schedule is None else
                                    [int(name.split("-")[1]) for name in schedule[str(round_id)]])
                encoded = [p.codec.encode(trainers[i](baseline[-1], i, p.learning_rate, round_id))
                           for i in selected_indices]
                baseline.append(baseline[-1] + np.sum(encoded, axis=0)
                                / (len(encoded) * p.codec.scale))
    curve = []
    for round_id, model in enumerate(models):
        row = {"round": round_id,
               **evaluate(model, reference, data["test_x"], data["test_y"], device=args.device),
               "attack_success_rate": attack_success_rate(
                   model, reference, data["test_x"][poison_indices], device=args.device)}
        if baseline is not None:
            row["max_abs_error_fixed"] = float(np.max(np.abs(model - baseline[round_id])))
        curve.append(row)
    result = {"scope": "Flower FMNIST/LeNet5; pair-group sampling is not paper CCS/VRF or MGF",
              "checkpoint_sha256": CHECKPOINT_SHA256,
              "client_count": args.clients, "population": population,
              "aggregator_count": args.aggregators,
              "local_worker_processes": args.workers or population + args.aggregators,
              "participation_schedule": schedule,
              "rounds": args.rounds, "local_epochs": args.local_epochs,
              "batch_size": args.batch_size, "learning_rate": args.learning_rate,
              "attack_clients": args.attack_clients, "attack_rounds": attack_rounds,
              "attack_probability": args.attack_probability, "attack_steps": args.attack_steps,
              "attack_boost": args.boost, "poison_batch": args.poison_batch,
              "poison_pool_rows": len(poison_indices),
              "poison_pool_sha256": hashlib.sha256(poison_indices.astype("<i8").tobytes()).hexdigest(),
              "poison_rng_policy": args.poison_rng,
              "partition": "artifact-style rounded per-class Dirichlet; fresh seed, not original RNG state",
              "partition_sha256": [hashlib.sha256(indices.astype("<i8").tobytes()).hexdigest()
                                   for indices in partitions],
              "assigned_rows": sum(len(indices) for indices in partitions),
              "wall_seconds": wall, "curve": curve,
              "json_payload_bytes": sum(event["request_payload_bytes"] + event["reply_payload_bytes"]
                                        for event in events), "events": events}
    (args.output / "results.json").write_bytes(canonical(result))
    print(json.dumps({"output": str(args.output), "final": curve[-1], "wall_seconds": wall}, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path(
        "../Aion/input_validation/FL_Backdoor_CV/data/FashionMNIST/raw"))
    parser.add_argument("--checkpoint", type=Path, default=Path(
        "../Aion/input_validation/FL_Backdoor_CV/saved_models/Revision_1/fmnist/avg_300.pth"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--population", type=int, default=None,
                        help="Registered clients N; --clients is participants q per round")
    parser.add_argument("--aggregators", type=int, default=4)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--local-epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--dirichlet-alpha", type=float, default=0.5)
    parser.add_argument("--partition-rng", choices=("artifact", "legacy"),
                        default="artifact",
                        help="Artifact class order and 150-client RNG prelude; legacy reproduces earlier Flower reports")
    parser.add_argument("--poison-rng", choices=("artifact", "legacy"), default="artifact",
                        help="Continue partition Python RNG into poison sampling; legacy reseeds")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--decimals", type=int, default=6)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--no-baseline", action="store_true")
    parser.add_argument("--workers", type=int, default=None,
                        help="Bound local Flower ClientApp processes; identities still keep separate durable state")
    parser.add_argument("--attack-clients", type=int, default=0,
                        help="First N clients perform artifact-style MR on attack rounds")
    parser.add_argument("--attack-probability", type=float, default=0.5)
    parser.add_argument("--force-attack-rounds", type=int, nargs="*", default=[])
    parser.add_argument("--attack-steps", type=int, default=120)
    parser.add_argument("--boost", type=float, default=20.0)
    parser.add_argument("--poison-batch", type=int, default=6)
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
