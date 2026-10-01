"""Stage, run, and evaluate FMNIST AION on the official Flower Simulation Runtime.

Each mode is a separate Flower app/run with fresh provisioned identities. The
MGF control receives plaintext local updates and is not a secure AION run.
"""

import argparse
import hashlib
import importlib.metadata
import json
import math
from pathlib import Path
import random
import shutil
import tomllib
import uuid

import numpy as np
import tomli_w

from experiments.run_endpoint_flower import run as flower_run
from experiments.run_fmnist_flower import (pinned_reference, read_dataset,
                                           scheduled_cohorts, scheduled_individual_cohorts)
from trustlessfl.crypto import canonical, digest
from trustlessfl.demo import provision
from trustlessfl.fmnist import (DIMENSION, TARGET_LABEL, artifact_dirichlet_partition,
                                artifact_poison_indices, attack_success_rate, evaluate)
from trustlessfl.fmnist_artifact_mgf import CLASSIFIER_WEIGHT
from trustlessfl.protocol import Parameters, check_finalized_model, check_finalized_roster
from trustlessfl.mgf_selection import select_probes

MODES = ("aion", "quantized", "avg", "mgf", "aion_mgf_oracle", "aion_mgf_beta")
DEFAULT_MODES = ("aion_mgf_oracle", "mgf")


def verify_secure_training_sampling(root, case, parameters, expected_cohorts, policy):
    """Offline audit of simulation client metadata, not a training proof.

    Only read task-scoped client state; never export keys, shares or gradients.
    This confirms the requested trainer ran before MGF selection, including
    clients rejected by the filter.
    """
    catalog = json.loads((Path(root) / "catalog.json").read_text())[case]
    count = 0
    for index, name in enumerate(parameters.clients):
        node = catalog[str(index)]
        if node.get("fmnist-sampling-policy", "legacy") != policy:
            raise ValueError("secure catalog training sampling policy differs from provenance")
        expected = {str(r) for r, cohort in expected_cohorts.items() if name in cohort}
        path = Path(node["aion-identity"]).parent / f"state-{digest({'task': parameters.task, 'party': name})}.json"
        metadata = json.loads(path.read_text()).get("training_meta", {}) if path.exists() else {}
        if not isinstance(metadata, dict) or set(metadata) != expected:
            raise ValueError("secure training metadata differs from staged cohort")
        for key, meta in metadata.items():
            if (not isinstance(meta, dict) or type(meta.get("round")) is not int
                    or type(meta.get("partition")) is not int
                    or meta["round"] != int(key) or meta["partition"] != index
                    or meta.get("sampling_policy", "legacy") != policy):
                raise ValueError("actual secure training sampling policy or identity differs from provenance")
            count += 1
    return {"sampling_policy": policy, "training_calls": count,
            "scope": "offline simulation client-state metadata; not verifiable training"}


def verify_mgf_trace(selections, models, expected_cohorts, *, selection_slice=CLASSIFIER_WEIGHT,
                     author_arithmetic=False):
    """Check the artifact selector's recorded decisions against saved model steps.

    Individual plaintext updates are deliberately not persisted, so this
    verifies decision arithmetic and aggregate norms, not each reported norm.
    """
    if len(selections) != len(models) - 1:
        raise ValueError("missing plaintext MGF selection trace")
    previous_norms = []
    previous_mask_linf = previous_bound = 1.0
    for round_id, item in enumerate(selections, 1):
        if author_arithmetic != (item.get("mgf_arithmetic") == "author-torch-float32-cpu"):
            raise ValueError("MGF arithmetic differs from experiment provenance")
        cohort = item.get("cohort")
        if (item.get("round") != round_id or not isinstance(cohort, list)
                or len(set(cohort)) != len(cohort)
                or set(cohort) != expected_cohorts[round_id]):
            raise ValueError("MGF cohort differs from staged schedule")
        count = len(cohort)
        norms = np.asarray(item.get("masked_norms"), dtype=np.float64)
        mask_linf = item.get("mask_linf")
        if (norms.shape != (count,) or not np.isfinite(norms).all()
                or (norms < 0).any() or not isinstance(mask_linf, (int, float))
                or not math.isfinite(mask_linf) or mask_linf < 0):
            raise ValueError("invalid MGF masked norm trace")
        if author_arithmetic:
            import torch
            _, indices = torch.sort(torch.tensor(norms, dtype=torch.float32))
            order = indices.numpy()
        else:
            order = np.argsort(norms, kind="stable")
        ordered_norms = norms[order]
        if round_id <= 3:
            bound = float(ordered_norms[int(0.1 * count)])
        else:
            denominator = previous_norms[0] + previous_mask_linf
            if denominator <= 0:
                raise ValueError("invalid MGF bound denominator")
            bound = ((previous_norms[1] + mask_linf) / denominator) * previous_bound
            if author_arithmetic:
                factor = (previous_norms[1] + mask_linf) / denominator
                bound = float(torch.tensor(previous_bound, dtype=torch.float32) * factor)
        minimum = max(2, int(0.1 * count))
        if author_arithmetic and int(0.1 * count) < 2:
            raise ValueError("author MGF minimum rank is incompatible with secure cohort size")
        maximum = max(minimum, int(0.8 * count))
        retained = max(minimum, min(maximum, int(np.searchsorted(ordered_norms, bound, side="left"))))
        selected = [cohort[i] for i in order[:retained]]
        if (item.get("selected") != selected or item.get("selected_count") != retained
                or item.get("small_cohort_floor_override") != (int(0.1 * count) < 2)
                or not isinstance(item.get("bound"), (int, float))
                or not math.isclose(item["bound"], bound, rel_tol=1e-12, abs_tol=1e-12)):
            raise ValueError("MGF selection differs from recorded norms or bound")
        projected = (models[round_id] - models[round_id - 1])[selection_slice]
        if author_arithmetic:
            tensor = torch.tensor(projected, dtype=torch.float32)
            aggregate_l2 = float(torch.norm(tensor))
            aggregate_linf = float(torch.norm(tensor, p=float("inf")))
        else:
            aggregate_l2 = float(np.linalg.norm(projected))
            aggregate_linf = float(np.max(np.abs(projected)))
        if (not isinstance(item.get("global_weight_l2"), (int, float))
                or not isinstance(item.get("global_weight_linf"), (int, float))
                or not math.isclose(item["global_weight_l2"], aggregate_l2,
                                  rel_tol=1e-6, abs_tol=1e-7)
                or not math.isclose(item["global_weight_linf"], aggregate_linf,
                                  rel_tol=1e-6, abs_tol=1e-7)):
            raise ValueError("MGF aggregate trace differs from saved model")
        if round_id <= 2:
            previous_norms.append(item["global_weight_l2"])
        else:
            previous_norms = [previous_norms[1], item["global_weight_l2"]]
        previous_mask_linf, previous_bound = mask_linf, bound


def verify_oracle_selection_agreement(oracle_selections, clear_selections, rounds):
    """Require the paired Flower runs to choose the same clients in every round."""
    if len(oracle_selections) != rounds or len(clear_selections) != rounds:
        raise ValueError("oracle/clear MGF selection trace has the wrong round count")
    agreement = [a["selected"] == b["selected"]
                 for a, b in zip(oracle_selections, clear_selections, strict=True)]
    if not all(agreement):
        differing = [i for i, equal in enumerate(agreement, 1) if not equal]
        raise AssertionError(f"oracle ASR and plaintext MGF differ in rounds {differing}")
    return agreement


def stage(args):
    output = args.output.resolve()
    source = Path(__file__).resolve().parents[1]
    for path in (source / "trustlessfl").glob("*.py"):
        compile(path.read_bytes(), str(path), "exec")
    if (args.population < 2 or args.participants < 2 or args.population < args.participants
            or args.aggregators < 4 or args.rounds < 1 or args.seed < 0
            or not 0 <= args.attack_clients <= args.participants // 2
            or not 0 <= args.attack_probability <= 1
            or (args.attack_rounds is not None and
                (any(r < 1 or r > args.rounds for r in args.attack_rounds)
                 or (args.attack_rounds and not args.attack_clients)))
            or args.local_epochs < 1 or args.batch_size < 2
            or args.attack_steps < 1 or not 0 < args.boost <= 100
            or not 0 < args.poison_batch < args.batch_size
            or not math.isfinite(args.timeout) or args.timeout <= 0 or args.cli_timeout < 1
            or args.workers < 1
            or len(set(args.modes)) != len(args.modes) or any(mode not in MODES for mode in args.modes)):
        raise ValueError("invalid FMNIST official-runtime experiment settings")
    cohort_sampling = args.cohort_sampling
    if getattr(args, "training_sampling", "legacy") not in ("legacy", "author-loader"):
        raise ValueError("invalid FMNIST training sampling policy")
    author_mgf = getattr(args, "author_mgf", False)
    author_files, author_reference = {}, None
    reference_directory = getattr(args, "author_reference_dir", None)
    if reference_directory is not None:
        if not author_mgf:
            raise ValueError("--author-reference-dir requires --author-mgf")
        from trustlessfl.aion_author_reference import load_author_reference
        author_files, author_reference = load_author_reference(reference_directory)
    if author_mgf and ("mgf" not in args.modes or args.participants < 20
                       or "aion_mgf_beta" in args.modes):
        raise ValueError("--author-mgf requires mgf mode, q>=20, and no bounded-MGF mode")
    original_setup, original_hashes = (), {}
    original_directory = getattr(args, "original_hprf_dir", None)
    if original_directory is not None:
        if not any(m in args.modes for m in ("aion", "aion_mgf_oracle", "aion_mgf_beta")):
            raise ValueError("original HPRF requires an AION secure aggregation mode")
        from trustlessfl.aion_original_hprf import OriginalAionHPRF
        original_setup = OriginalAionHPRF.from_directory(original_directory).public_setup()
        original_hashes = {name: hashlib.sha256((original_directory / name).read_bytes()).hexdigest()
                           for name in ("matrix", "initialization_values", "hprf.py")}
    if args.mgf_percentile and (not args.mgf_projection or "aion_mgf_beta" not in args.modes):
        raise ValueError("masked percentile selection requires aion_mgf_beta and --mgf-projection")
    if args.mgf_artifact_bound and not args.mgf_percentile:
        raise ValueError("artifact bound requires --mgf-percentile")
    if getattr(args, "mgf_single_view", False) and (not args.mgf_projection or "aion_mgf_beta" not in args.modes):
        raise ValueError("single-view MGF requires projection and aion_mgf_beta")
    if cohort_sampling == "auto":
        cohort_sampling = "groups" if "aion" in args.modes else "individuals"
    if args.population != args.participants:
        if cohort_sampling == "groups" and (args.population % 2 or args.participants % 2):
            raise ValueError("scheduled privacy groups require even N and q")
        if cohort_sampling == "individuals" and "aion" in args.modes:
            raise ValueError("fixed-key AION requires group sampling; use aion_mgf_oracle")
    data = read_dataset(args.data_dir)
    reference = pinned_reference(args.checkpoint)
    numpy_rng = np.random.RandomState(args.seed)
    python_rng = random.Random(args.seed)
    partitions = artifact_dirichlet_partition(data["train_y"], args.population,
                                               alpha=args.dirichlet_alpha, seed=args.seed,
                                               adversaries=args.attack_clients,
                                               rng_policy=args.partition_rng,
                                               numpy_rng=numpy_rng,
                                               python_rng=python_rng)
    if any(len(indices) == 0 for indices in partitions):
        raise ValueError("empty client shard")
    if args.attack_rounds is None:
        attack_rounds = ((np.flatnonzero(numpy_rng.uniform(size=args.rounds)
                                            >= 1 - args.attack_probability) + 1).tolist()
                         if args.attack_clients else [])
    else:
        attack_rounds = sorted(set(args.attack_rounds))
    schedule = ((scheduled_cohorts if cohort_sampling == "groups"
                 else scheduled_individual_cohorts)(
                     args.population, args.participants, args.attack_clients,
                     args.rounds, attack_rounds, args.seed)
                if args.population != args.participants else None)
    poison_indices = artifact_poison_indices(
        data["test_y"], seed=args.seed,
        python_rng=python_rng if args.poison_rng == "artifact" else None)
    output.mkdir(parents=True, exist_ok=False)
    if author_reference is not None:
        from trustlessfl.aion_author_reference import stage_author_reference
        stage_author_reference(author_files, output)
    inputs = output / "inputs"
    inputs.mkdir()
    np.savez(inputs / "reference.npz", weights=reference)
    np.savez_compressed(inputs / "test.npz", x=data["test_x"], y=data["test_y"])
    np.savez_compressed(inputs / "poison-test.npz", x=data["test_x"][poison_indices])
    if args.attack_clients:
        clean = data["train_y"] != TARGET_LABEL
        np.savez_compressed(inputs / "attack-clean.npz", x=data["train_x"][clean],
                            y=data["train_y"][clean])
        np.savez_compressed(inputs / "attack-poison.npz", x=data["test_x"][poison_indices],
                            y=data["test_y"][poison_indices])
    for i, indices in enumerate(partitions):
        np.savez_compressed(inputs / f"client-{i}.npz", x=data["train_x"][indices],
                            y=data["train_y"][indices])
    if schedule is not None:
        (inputs / "participation.json").write_bytes(canonical(schedule))
    clients = tuple(f"client-{i}" for i in range(args.population))
    groups = (tuple(clients[i:i + 2] for i in range(0, len(clients), 2))
              if schedule is not None else ())
    scenario = "attack" if attack_rounds else "clean"
    case = f"seed-{args.seed}--{scenario}"
    for mode in args.modes:
        root = output / mode
        app, keys = root / "app", root / "provision"
        app.mkdir(parents=True)
        keys.mkdir(mode=0o700)
        p = Parameters(uuid.uuid4().hex, clients,
                       tuple(f"aggregator-{i}" for i in range(args.aggregators)),
                       faults=(args.aggregators - 1) // 3, dimension=DIMENSION,
                       mask_backend=("aion-original" if original_setup and mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta")
                                     else "artifact"),
                       original_hprf_setup=(original_setup if mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta") else ()),
                       decimals=args.decimals, learning_rate=args.learning_rate,
                       privacy_groups=(() if mode in ("aion_mgf_oracle", "aion_mgf_beta") else groups),
                       hotstuff=args.hotstuff and mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta"),
                       mgf_beta=args.mgf_beta if mode == "aion_mgf_beta" else "",
                       mgf_initial_alpha=args.mgf_initial_alpha if mode == "aion_mgf_beta" else "",
                       mgf_initial_bound=args.mgf_initial_bound if mode == "aion_mgf_beta" else "",
                       mgf_initial_term=args.mgf_initial_term if mode == "aion_mgf_beta" else "",
                       mgf_projection=((CLASSIFIER_WEIGHT.start, CLASSIFIER_WEIGHT.stop)
                                       if mode == "aion_mgf_beta" and args.mgf_projection else ()),
                       mgf_single_view=mode == "aion_mgf_beta" and getattr(args, "mgf_single_view", False),
                       mgf_percentile=mode == "aion_mgf_beta" and args.mgf_percentile,
                       mgf_artifact_bound=mode == "aion_mgf_beta" and args.mgf_artifact_bound,
                       oracle_mgf=mode == "aion_mgf_oracle")
        _, nodes = provision(keys / case, p)
        for i in range(args.population):
            nodes[i + 1].update({
                "fmnist-shard": str(inputs / f"client-{i}.npz"),
                "fmnist-reference": str(inputs / "reference.npz"),
                "fmnist-seed": args.seed, "fmnist-epochs": args.local_epochs,
                "fmnist-sampling-policy": getattr(args, "training_sampling", "legacy"),
                "fmnist-batch-size": args.batch_size, "fmnist-device": args.device,
            })
            if i < args.attack_clients:
                nodes[i + 1]["fmnist-attack"] = {
                    "rounds": attack_rounds,
                    "clean_path": str(inputs / "attack-clean.npz"),
                    "poison_path": str(inputs / "attack-poison.npz"),
                    "steps": args.attack_steps, "boost": args.boost,
                    "poison_batch": args.poison_batch,
                }
        (keys / "catalog.json").write_bytes(canonical({
            case: {str(i - 1): node for i, node in nodes.items()}}))
        shutil.copytree(source / "trustlessfl", app / "trustlessfl",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        config = tomllib.loads((source / "configs/endpoint/flower-pyproject.toml").read_text())
        config["project"].update({
            "name": f"tf-fmnist-{mode.replace('_', '-')}",
            "description": "FMNIST AION-ASR research baseline on Flower Simulation Runtime",
            "dependencies": ["flwr[simulation]==1.36.0", "numpy>=2.5.0,<3",
                             "cryptography>=46.0.7,<47", "torch>=2.4,<3",
                             *(["gmpy2>=2.2,<3"] if mode == "aion_mgf_beta" else [])],
        })
        config["tool"]["flwr"]["app"]["components"] = {
            "serverapp": "trustlessfl.aion_runtime:server_app",
            "clientapp": ("trustlessfl.aion_runtime:client_app" if mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta")
                          else "trustlessfl.aion_runtime:plain_app"),
        }
        config["tool"]["flwr"]["app"]["config"] = {
            "provision-dir": str(keys), "output-dir": str(root / "runtime-results"),
            "rounds": args.rounds, "num-clients": args.population + args.aggregators,
            "mode": mode, "workload": "fmnist", "timeout": args.timeout,
            "runtime-cli-timeout": args.cli_timeout,
            "simulation-workers": args.workers,
            "mgf-seed": args.seed,
            **({"author-mgf": True} if author_mgf else {}),
            **({"participation-schedule": str(inputs / "participation.json")}
               if schedule is not None else {}),
        }
        (app / "pyproject.toml").write_text(tomli_w.dumps(config))
    versions = {name: importlib.metadata.version(name)
                for name in ("flwr", "ray", "numpy", "torch", "cryptography")}
    try:
        versions["gmpy2"] = importlib.metadata.version("gmpy2")
    except importlib.metadata.PackageNotFoundError:
        pass
    (output / "provenance.json").write_bytes(canonical({
        "scope": "official Flower SuperLink/Ray runtime; separate FAB per mode",
        "versions": versions,
        "source_sha256": {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted((source / "trustlessfl").glob("*.py"))},
        "manifest_sha256": {
            mode: hashlib.sha256((output / mode / "provision" / case / "manifest.json").read_bytes()).hexdigest()
            for mode in args.modes},
        "catalog_sha256": {mode: hashlib.sha256(
            (output / mode / "provision/catalog.json").read_bytes()).hexdigest() for mode in args.modes},
        "training": {"learning_rate": args.learning_rate, "local_epochs": args.local_epochs,
                     "batch_size": args.batch_size, "decimals": args.decimals, "device": args.device,
                     "attack_steps": args.attack_steps, "boost": args.boost,
                     "poison_batch": args.poison_batch,
                     "sampling_policy": getattr(args, "training_sampling", "legacy")},
        "modes": args.modes, "case": case, "population": args.population,
        "roster_trace_version": 1,
        "model_certificate_trace_version": 1,
        "participants": args.participants, "aggregators": args.aggregators,
        "rounds": args.rounds, "seed": args.seed, "attack_clients": args.attack_clients,
        "dirichlet_alpha": args.dirichlet_alpha,
        "hotstuff": args.hotstuff,
        "simulation_workers": args.workers,
        "attack_rounds": attack_rounds, "attack_probability": args.attack_probability,
        "attack_round_rng_policy": ("post-partition" if args.attack_rounds is None
                                    else "explicit"),
        "checkpoint_sha256": hashlib.sha256(args.checkpoint.read_bytes()).hexdigest(),
        "partition_sha256": [hashlib.sha256(v.astype("<i8").tobytes()).hexdigest() for v in partitions],
        "poison_indices_sha256": hashlib.sha256(
            poison_indices.astype("<i8").tobytes()).hexdigest(),
        "partition_rng_policy": args.partition_rng,
        "poison_rng_policy": args.poison_rng,
        "cohort_sampling": cohort_sampling,
        "assigned_rows": sum(map(len, partitions)), "schedule": schedule,
        "input_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in sorted(inputs.iterdir()) if path.is_file()},
        "mgf_scope": ("mgf is central plaintext control; aion_mgf_oracle exposes signed classifier updates; "
                      "aion_mgf_beta is the experimental bounded-mask/Pedersen wire, with no proven input privacy"),
        "mgf_beta": ({"beta": args.mgf_beta, "initial_alpha": args.mgf_initial_alpha,
                      "initial_bound": args.mgf_initial_bound,
                      "initial_term": args.mgf_initial_term}
                     if "aion_mgf_beta" in args.modes else None),
        "mgf_projection": args.mgf_projection,
        "mgf_single_view": getattr(args, "mgf_single_view", False),
        "mgf_percentile": args.mgf_percentile,
        "mgf_artifact_bound": args.mgf_artifact_bound,
        "author_mgf": author_mgf,
        **({"author_reference": author_reference} if author_reference is not None else {}),
        **({"original_hprf_sha256": original_hashes,
            "original_hprf_setup_sha256": digest(original_setup)} if original_setup else {}),
    }))
    print(json.dumps({"staged": str(output), "modes": args.modes, "case": case}, indent=2))


def verify(output, *, replay_selected=False):
    provenance = json.loads((output / "provenance.json").read_text())
    if replay_selected and ("aion_mgf_beta" not in provenance["modes"]
                            or provenance.get("model_certificate_trace_version") != 1):
        raise ValueError("selected replay requires bounded-MGF mode and full model certificates")
    if "author_reference" in provenance:
        from trustlessfl.aion_author_reference import verify_author_reference
        verify_author_reference(output, provenance["author_reference"])
    if provenance.get("attack_round_rng_policy") == "post-partition":
        rng = np.random.RandomState(provenance["seed"])
        for _ in range(10):
            rng.dirichlet(np.full(provenance["population"], provenance["dirichlet_alpha"]))
        expected = ((np.flatnonzero(rng.uniform(size=provenance["rounds"])
                                    >= 1 - provenance["attack_probability"]) + 1).tolist()
                    if provenance["attack_clients"] else [])
        if provenance["attack_rounds"] != expected:
            raise ValueError("attack rounds differ from post-partition NumPy RNG")
    inputs = output / "inputs"
    for name, expected in provenance["input_sha256"].items():
        if hashlib.sha256((inputs / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"staged input changed: {name}")
    schedule_path = inputs / "participation.json"
    if ((provenance["schedule"] is None and schedule_path.exists())
            or (provenance["schedule"] is not None
                and (not schedule_path.exists()
                     or schedule_path.read_bytes() != canonical(provenance["schedule"])))):
        raise ValueError("provenance participation schedule differs from staged input")
    cohort_sampling = provenance.get("cohort_sampling")
    if provenance["schedule"] is not None and cohort_sampling in ("groups", "individuals"):
        sampler = (scheduled_cohorts if cohort_sampling == "groups"
                   else scheduled_individual_cohorts)
        expected_schedule = sampler(
            provenance["population"], provenance["participants"],
            provenance["attack_clients"], provenance["rounds"],
            provenance["attack_rounds"], provenance["seed"])
        if provenance["schedule"] != expected_schedule:
            raise ValueError("participation schedule differs from recorded sampling policy")
    for mode in provenance["modes"]:
        expected_catalog = provenance.get("catalog_sha256", {}).get(mode)
        if (expected_catalog is not None and hashlib.sha256(
                (output / mode / "provision/catalog.json").read_bytes()).hexdigest() != expected_catalog):
            raise ValueError(f"staged training catalog changed: {mode}")
        expected_manifest = provenance.get("manifest_sha256", {}).get(mode)
        if (expected_manifest is not None and hashlib.sha256(
                (output / mode / "provision" / provenance["case"] / "manifest.json").read_bytes()
                ).hexdigest() != expected_manifest):
            raise ValueError(f"staged AION manifest changed: {mode}")
        for relative, expected in provenance.get("source_sha256", {}).items():
            staged = output / mode / "app" / relative
            if hashlib.sha256(staged.read_bytes()).hexdigest() != expected:
                raise ValueError(f"staged Flower source changed: {mode}/{relative}")
    with np.load(inputs / "reference.npz", allow_pickle=False) as archive:
        reference = archive["weights"]
    with np.load(inputs / "test.npz", allow_pickle=False) as archive:
        test_x, test_y = archive["x"], archive["y"]
    with np.load(inputs / "poison-test.npz", allow_pickle=False) as archive:
        poison_x = archive["x"]
    report = {}
    for mode in provenance["modes"]:
        result_paths = list((output / mode / "runtime-results").glob("run-*/results.json"))
        if len(result_paths) != 1:
            raise ValueError(f"expected one complete official Flower run for {mode}")
        result = json.loads(result_paths[0].read_text())
        if len(result["cases"]) != 1 or result["cases"][0]["case"] != provenance["case"]:
            raise ValueError("unexpected Flower runtime case")
        row = result["cases"][0]
        if (result["config"]["mode"] != mode or row["mode"] != mode
                or result["config"]["rounds"] != provenance["rounds"]
                or result["config"]["num-clients"] != provenance["population"] + provenance["aggregators"]
                or row["status"] != "completed"):
            raise ValueError(f"Flower run did not complete: {mode}")
        if bool(result["config"].get("author-mgf", False)) != provenance.get("author_mgf", False):
            raise ValueError("Flower author-MGF configuration differs from provenance")
        expected_cohorts = {
            round_id: set(provenance["schedule"][str(round_id)] if provenance["schedule"]
                          else (f"client-{i}" for i in range(provenance["population"])))
            for round_id in range(1, provenance["rounds"] + 1)
        }
        training_audit = None
        masked_wire_audit = None
        selected_replay = None
        masked_round_state = None
        if mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta"):
            policy = provenance.get("training", {}).get("sampling_policy", "legacy")
            if policy != "legacy":
                manifest = json.loads((output / mode / "provision" / provenance["case"]
                                       / "manifest.json").read_text())
                training_audit = verify_secure_training_sampling(
                    output / mode / "provision", provenance["case"],
                    Parameters.from_dict(manifest["parameters"]), expected_cohorts, policy)
            certificates = row.get("certificates", [])
            if ([entry["round"] for entry in certificates] != list(range(provenance["rounds"] + 1))
                    or any(len(set(entry["signers"])) < provenance["aggregators"]
                           - (provenance["aggregators"] - 1) // 3 for entry in certificates)):
                raise ValueError("missing AION certificate quorum")
            if provenance.get("hotstuff") and any(
                    entry.get("hotstuff_stage") != "commit" for entry in certificates[1:]):
                raise ValueError("missing HotStuff commit QC on AION model")
            if provenance.get("roster_trace_version") == 1:
                manifest = json.loads((output / mode / "provision" / provenance["case"]
                                       / "manifest.json").read_text())
                parameters = Parameters.from_dict(manifest["parameters"])
                if mode == "aion_mgf_beta" and parameters.mgf_single_view != provenance.get("mgf_single_view", False):
                    raise ValueError("MGF single-view policy differs from provenance")
                expected_setup = provenance.get("original_hprf_setup_sha256")
                if expected_setup and mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta"):
                    if (parameters.mask_backend != "aion-original"
                            or digest(parameters.original_hprf_setup) != expected_setup):
                        raise ValueError("original HPRF setup differs from provenance")
                percentile_models = (json.loads((result_paths[0].parent /
                    f"{provenance['case']}-certificates.json").read_text()) if parameters.mgf_percentile else None)
                rosters = row.get("certified_rosters", [])
                if len(rosters) != provenance["rounds"] or row["task"] != parameters.task:
                    raise ValueError("missing AION certified roster trace")
                for round_id, roster in enumerate(rosters, 1):
                    body = check_finalized_roster(roster, parameters, manifest["registry"])
                    if parameters.mgf_percentile:
                        probes = roster.get("mgf_candidates")
                        state = percentile_models[round_id - 1]["body"]["mgf_state"]
                        bound = state["bound"]
                        if parameters.mgf_artifact_bound:
                            from trustlessfl.mgf_selection import artifact_selection_bound
                            norm = body["mgf_selection"]["cohort_norm_certificate"]
                            bound = artifact_selection_bound(parameters, manifest["registry"], state,
                                                             norm, probes, body["parent"], round_id)
                        chosen, selection = select_probes(parameters, manifest["registry"], probes,
                            body["parent"], round_id, bound)
                        if parameters.mgf_artifact_bound:
                            selection.update(cohort_mask_linf=norm["body"]["mask_linf"],
                                             cohort_norm_certificate=norm)
                        if (set(selection["cohort"]) != expected_cohorts[round_id]
                                or chosen != body["members"] or selection != body.get("mgf_selection")
                                or digest(probes) != body.get("mgf_candidates")):
                            raise ValueError("masked MGF candidate witness or percentile selection differs")
                    cohort = (set(row["selections"][round_id - 1]["selected"])
                              if mode in ("aion_mgf_oracle", "aion_mgf_beta")
                              else expected_cohorts[round_id])
                    if mode == "aion_mgf_beta" and (
                            len(cohort) < 2 or not cohort.issubset(expected_cohorts[round_id])):
                        raise ValueError("bounded MGF roster is smaller than two or outside the cohort")
                    expected = [client for client in parameters.clients if client in cohort]
                    if (body["round"] != round_id or body["members"] != expected
                            or body["parent"] != certificates[round_id - 1]["digest"]
                            or certificates[round_id]["roster_digest"] != digest(body)):
                        raise ValueError("AION certified roster differs from staged cohort or model")
        else:
            observed = {round_id: set() for round_id in expected_cohorts}
            for meta in row["training_meta"]:
                if meta.get("sampling_policy", "legacy") != provenance.get("training", {}).get("sampling_policy", "legacy"):
                    raise ValueError("actual training sampling policy differs from provenance")
                round_id, partition = meta["round"], meta["partition"]
                if round_id not in observed or partition < 0 or partition >= provenance["population"]:
                    raise ValueError("invalid training metadata")
                name = f"client-{partition}"
                if name in observed[round_id]:
                    raise ValueError("duplicate plaintext training")
                observed[round_id].add(name)
            if observed != expected_cohorts:
                raise ValueError("plaintext cohort differs from staged schedule")
        with np.load(result_paths[0].parent / f"{provenance['case']}-models.npz",
                     allow_pickle=False) as archive:
            models = archive["offsets"]
        if (models.shape != (provenance["rounds"] + 1, DIMENSION)
                or not np.isfinite(models).all()):
            raise ValueError(f"invalid Flower model history: {mode}")
        if mode in ("mgf", "aion_mgf_oracle"):
            verify_mgf_trace(row.get("selections", []), models, expected_cohorts,
                             author_arithmetic=provenance.get("author_mgf", False))
        if mode == "aion_mgf_oracle":
            error = row.get("oracle_max_classifier_error")
            if (not isinstance(error, (int, float)) or not math.isfinite(error)
                    or error < 0 or error > 2 / 10**parameters.decimals):
                raise ValueError("oracle classifier differs from selected ASR aggregate")
        if mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta") and provenance.get("model_certificate_trace_version") == 1:
            manifest = json.loads((output / mode / "provision" / provenance["case"]
                                   / "manifest.json").read_text())
            parameters = Parameters.from_dict(manifest["parameters"])
            trace_path = result_paths[0].parent / f"{provenance['case']}-certificates.json"
            trace_bytes = trace_path.read_bytes()
            if hashlib.sha256(trace_bytes).hexdigest() != row.get("certificate_trace_sha256"):
                raise ValueError("AION model certificate trace changed")
            full_certificates = json.loads(trace_bytes)
            if not isinstance(full_certificates, list) or len(full_certificates) != len(models):
                raise ValueError("missing full AION model certificate trace")
            for round_id, cert in enumerate(full_certificates):
                body = check_finalized_model(cert, parameters, manifest["registry"])
                summary = row["certificates"][round_id]
                if (body["round"] != round_id or digest(body) != summary["digest"]
                        or body.get("roster") != summary["roster_digest"]
                        or [vote["sender"] for vote in cert["votes"]] != summary["signers"]
                        or not np.array_equal(np.asarray(body["model"]), models[round_id])):
                    raise ValueError("AION model certificate differs from saved result")
                if parameters.mgf_artifact_bound and round_id:
                    from trustlessfl.mgf_wire import evolve_artifact_state
                    roster = row["certified_rosters"][round_id - 1]["body"]
                    count = len(roster["members"])
                    quantized = ((models[round_id] - models[round_id - 1])[parameters.mgf_slice]
                                 * parameters.codec.scale * count)
                    rounded = np.rint(quantized)
                    if (not np.isfinite(quantized).all()
                            or np.max(np.abs(quantized - rounded)) > 1e-4):
                        raise ValueError("artifact MGF model delta is not on the certified integer grid")
                    successor = evolve_artifact_state(parameters,
                        full_certificates[round_id - 1]["body"]["mgf_state"],
                        [int(value) for value in rounded], count, roster["mgf_selection"])
                    if body["mgf_state"] != successor:
                        raise ValueError("artifact MGF norm history or alpha differs from actual model delta")
                if round_id and (body.get("parent") != digest(full_certificates[round_id - 1]["body"])
                                 or body.get("roster") != digest(row["certified_rosters"][round_id - 1]["body"])):
                    raise ValueError("AION model certificate chain differs from roster")
            if mode == "aion_mgf_beta":
                from experiments.audit_masked_wire import audit_masked_wire
                masked_wire_audit = audit_masked_wire(output / mode / "provision",
                    provenance["case"], parameters, manifest["registry"], expected_cohorts,
                    full_certificates, row["certified_rosters"])
                masked_round_state = [{"round": r,
                    "input_alpha": full_certificates[r - 1]["body"]["mgf_state"]["alpha"],
                    "next_alpha": full_certificates[r]["body"]["mgf_state"]["alpha"],
                    "next_bound": full_certificates[r]["body"]["mgf_state"]["bound"],
                    "filter_bound": (roster["body"]["mgf_selection"]["bound"]
                                     if parameters.mgf_percentile else
                                     {"decimal": full_certificates[r - 1]["body"]["mgf_state"]["bound"]})}
                    for r, roster in enumerate(row["certified_rosters"], 1)]
                if replay_selected:
                    from experiments.audit_masked_wire import replay_selected_aggregate
                    selected_replay = replay_selected_aggregate(output / mode / "provision",
                        provenance["case"], parameters, full_certificates,
                        row["certified_rosters"])
        curve = [{"round": i, **evaluate(model, reference, test_x, test_y),
                  "attack_success_rate": attack_success_rate(model, reference, poison_x)}
                 for i, model in enumerate(models)]
        report[mode] = {"run_id": result["run_id"], "curve": curve,
                        "seconds": row["seconds"], "selections": row.get("selections", [])}
        if training_audit is not None:
            report[mode]["training_sampling_audit"] = training_audit
        if masked_wire_audit is not None:
            report[mode]["masked_wire_audit"] = masked_wire_audit
            report[mode]["masked_round_state"] = masked_round_state
        if selected_replay is not None:
            report[mode]["selected_replay"] = selected_replay
    if "aion" in report and "quantized" in report:
        aion_path = list((output / "aion/runtime-results").glob("run-*/*-models.npz"))[0]
        clear_path = list((output / "quantized/runtime-results").glob("run-*/*-models.npz"))[0]
        with np.load(aion_path, allow_pickle=False) as archive:
            secure = archive["offsets"]
        with np.load(clear_path, allow_pickle=False) as archive:
            plain = archive["offsets"]
        report["aion_quantized_max_abs_error"] = float(np.max(np.abs(secure - plain)))
        if report["aion_quantized_max_abs_error"] != 0:
            raise AssertionError("AION differs from same-cohort quantized Flower control")
    if "aion_mgf_oracle" in report and "mgf" in report:
        secure_path = list((output / "aion_mgf_oracle/runtime-results").glob("run-*/*-models.npz"))[0]
        clear_path = list((output / "mgf/runtime-results").glob("run-*/*-models.npz"))[0]
        with np.load(secure_path, allow_pickle=False) as archive:
            oracle_models = archive["offsets"]
        with np.load(clear_path, allow_pickle=False) as archive:
            clear_models = archive["offsets"]
        oracle_selections = report["aion_mgf_oracle"]["selections"]
        clear_selections = report["mgf"]["selections"]
        agreement = verify_oracle_selection_agreement(
            oracle_selections, clear_selections, provenance["rounds"])
        report["oracle_mgf_control"] = {
            "model_max_abs_error": float(np.max(np.abs(oracle_models - clear_models))),
            "selected_equal_by_round": agreement,
        }
    (output / "verification.json").write_bytes(canonical(report))
    print(json.dumps({"verified": str(output / "verification.json"),
                      "final": {mode: row["curve"][-1] for mode, row in report.items()
                                if isinstance(row, dict) and "curve" in row}}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, default=Path(
        "../Aion/input_validation/FL_Backdoor_CV/data/FashionMNIST/raw"))
    parser.add_argument("--checkpoint", type=Path, default=Path(
        "../Aion/input_validation/FL_Backdoor_CV/saved_models/Revision_1/fmnist/avg_300.pth"))
    parser.add_argument("--phase", choices=("all", "stage", "run", "verify"), default="all")
    parser.add_argument("--replay-selected", action="store_true",
                        help="Offline verification: re-train bounded-MGF survivors and check the quantized mean; requires local staged data")
    parser.add_argument("--modes", nargs="+", choices=MODES, default=list(DEFAULT_MODES),
                        help="Flower runs to compare (default: aion_mgf_oracle mgf; oracle mode reveals signed classifier updates to the coordinator)")
    parser.add_argument("--population", type=int, default=500)
    parser.add_argument("--participants", type=int, default=100)
    parser.add_argument("--aggregators", type=int, default=8)
    parser.add_argument("--rounds", type=int, default=10,
                        help="Flower rounds (default: 10 for a practical attack/recovery run; use 60 for the paper-length curve)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--attack-clients", type=int, default=20)
    parser.add_argument("--attack-rounds", type=int, nargs="*", default=None,
                        help="Override seeded 50%% attack probability with exact round numbers")
    parser.add_argument("--attack-probability", type=float, default=0.5)
    parser.add_argument("--dirichlet-alpha", type=float, default=0.5)
    parser.add_argument("--partition-rng", choices=("artifact", "legacy"),
                        default="artifact",
                        help="Artifact class order and 150-client RNG prelude; legacy reproduces earlier Flower reports")
    parser.add_argument("--poison-rng", choices=("artifact", "legacy"), default="artifact",
                        help="Continue partition Python RNG into the poison pool; legacy reseeds for older reports")
    parser.add_argument("--cohort-sampling", choices=("auto", "individuals", "groups"),
                        default="auto",
                        help="auto uses individual clients for oracle/plain runs and privacy groups for fixed-key AION")
    parser.add_argument("--learning-rate", type=float, default=0.001)
    parser.add_argument("--local-epochs", type=int, default=2)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--attack-steps", type=int, default=120)
    parser.add_argument("--boost", type=float, default=20.0)
    parser.add_argument("--poison-batch", type=int, default=6)
    parser.add_argument("--decimals", type=int, default=6)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--timeout", type=float, default=600.0)
    parser.add_argument("--cli-timeout", type=int, default=86400,
                        help="Maximum seconds for one official Flower run, including all rounds")
    parser.add_argument("--workers", type=int, default=8,
                        help="Ray CPU worker slots for official Flower simulation")
    parser.add_argument("--hotstuff", action="store_true",
                        help="Enable experimental HotStuff voting for AION rosters/models")
    parser.add_argument("--mgf-beta", default="0.5",
                        help="Per-round bounded-mask MGF beta for aion_mgf_beta mode")
    parser.add_argument("--mgf-projection", action="store_true",
                        help="Filter masked classifier coordinates only; aggregate the full model with ASR")
    parser.add_argument("--mgf-single-view", action="store_true",
                        help="Do not also send projected coordinates in the modular ASR vector; reconstruct them only from the bounded probe")
    parser.add_argument("--mgf-percentile", action="store_true",
                        help="Artifact percentile bootstrap and 10/80%% rank clipping over signed masked probes")
    parser.add_argument("--training-sampling", choices=("legacy", "author-loader"), default="legacy",
                        help="author DataLoader batch semantics with isolated client/round RNG")
    parser.add_argument("--mgf-artifact-bound", action="store_true",
                        help="Use certified full-cohort mask norms and two historical aggregate norms")
    parser.add_argument("--author-mgf", action="store_true",
                        help="Use author SHPRG and layer-wise torch.float32 arithmetic in plaintext mgf mode (q>=20)")
    parser.add_argument("--author-reference-dir", type=Path,
                        help="Snapshot and hash the author FL_Backdoor_CV sources and actual SHPRG initialization")
    parser.add_argument("--original-hprf-dir", type=Path,
                        help="Author HPRF files for aion/aion_mgf_oracle/aion_mgf_beta; public coefficients are bound in each task")
    parser.add_argument("--mgf-initial-alpha", default="0.001",
                        help="Committed bootstrap mask bound for aion_mgf_beta mode")
    parser.add_argument("--mgf-initial-bound", default="10",
                        help="Committed bootstrap norm bound for aion_mgf_beta mode")
    parser.add_argument("--mgf-initial-term", default="1",
                        help="Committed bootstrap reference term for aion_mgf_beta mode")
    args = parser.parse_args()
    args.output = args.output.resolve()
    if (args.replay_selected and args.phase in ("all", "stage")
            and "aion_mgf_beta" not in args.modes):
        parser.error("--replay-selected requires aion_mgf_beta in --modes")
    if args.phase == "all" and (not shutil.which("flower-superlink") or not shutil.which("flwr")):
        raise FileNotFoundError("Flower CLI and flower-superlink must be on PATH before staging")
    if args.phase in ("all", "stage"):
        stage(args)
    if args.phase in ("all", "run"):
        modes = json.loads((args.output / "provenance.json").read_text())["modes"]
        for mode in modes:
            flower_run(args.output / mode)
            if len(list((args.output / mode / "runtime-results").glob("run-*/results.json"))) != 1:
                raise RuntimeError(f"Flower {mode} run ended without a complete result; inspect attempt logs")
    if args.phase in ("all", "run", "verify"):
        verify(args.output, replay_selected=args.replay_selected)


if __name__ == "__main__":
    main()
