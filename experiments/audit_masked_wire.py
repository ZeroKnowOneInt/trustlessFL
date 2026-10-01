"""Offline signed-wire audit; never export local secrets or gradient values."""

import json
from pathlib import Path

import numpy as np

from trustlessfl.crypto import digest, verify


def audit_masked_wire(root, case, p, registry, cohorts, history, rosters):
    """Bind cached client messages to certified rosters and percentile probes.

    Certificates must be independently verified by the caller. This checks
    signed message schemas and references, not a proof that the client trained
    honestly or that its bounded mask provides semantic input privacy.
    """
    if not p.mgf_enabled or p.oracle_mgf:
        raise ValueError("masked wire audit requires non-oracle MGF")
    rounds = len(rosters)
    if len(history) != rounds + 1 or set(cohorts) != set(range(1, rounds + 1)):
        raise ValueError("masked wire audit has incomplete round history")
    catalog = json.loads((Path(root) / "catalog.json").read_text())[case]
    per_round = {r: {} for r in cohorts}
    fields = {"parent", "vector", "mgf"}
    if p.mgf_projection:
        fields.add("mgf_vector")
    if p.mgf_percentile:
        fields.add("mgf_probe")
    for index, name in enumerate(p.clients):
        node = catalog[str(index)]
        path = Path(node["aion-identity"]).parent / f"state-{digest({'task': p.task, 'party': name})}.json"
        updates = json.loads(path.read_text()).get("updates", {}) if path.exists() else {}
        expected = {str(r) for r, cohort in cohorts.items() if name in cohort}
        if not isinstance(updates, dict) or set(updates) != expected:
            raise ValueError("masked wire cache differs from staged cohort")
        for key, envelope in updates.items():
            round_id = int(key)
            body = verify(envelope, registry)
            previous = history[round_id - 1]["body"]
            if (envelope["sender"] != name or type(body.get("round")) is not int
                    or set(body) != set(p.claim("update", round_id)) | fields
                    or body != p.claim("update", round_id, **{f: body[f] for f in fields})
                    or body["parent"] != digest(previous)):
                raise ValueError("masked wire signed update has unexpected fields or context")
            material = body["mgf"]
            if (not isinstance(material, dict)
                    or set(material) != {"alpha", "key_commitments", "key_packets",
                                         "mask_commitments", "mask_packets"}
                    or material["alpha"] != previous["mgf_state"]["alpha"]):
                raise ValueError("masked wire material differs from certified mask scale")
            vector = body["vector"]
            if (not isinstance(vector, list) or len(vector) != p.dimension
                    or any(type(value) is not int for value in vector)):
                raise ValueError("masked wire vector is not the full integer update")
            if p.mgf_projection:
                modulus = p.codec.output_modulus
                if any(not 0 <= value < modulus for value in vector):
                    raise ValueError("masked wire vector is outside the HPRF ring")
                if p.mgf_single_view and any(vector[p.mgf_slice]):
                    raise ValueError("masked wire contains duplicate projection coordinates")
            probe = body["mgf_vector"] if p.mgf_projection else vector
            if (not isinstance(probe, list) or len(probe) != p.mgf_dimension
                    or any(type(value) is not int for value in probe)):
                raise ValueError("masked wire probe has invalid coordinates")
            if p.mgf_percentile:
                signed = body["mgf_probe"]
                probe_body = verify(signed, registry)
                unsigned_body = {k: v for k, v in body.items() if k != "mgf_probe"}
                expected_probe = p.claim("mgf-probe", round_id,
                    parent=body["parent"], vector=probe, update=digest(unsigned_body),
                    key_material={"commitments": material["key_commitments"],
                                  "packets": material["key_packets"]})
                if signed["sender"] != name or probe_body != expected_probe:
                    raise ValueError("masked wire percentile probe is not bound to update")
            per_round[round_id][name] = envelope
    selected_count = 0
    for round_id, certificate in enumerate(rosters, 1):
        roster = certificate["body"]
        candidates = per_round[round_id]
        members = roster["members"]
        if (roster["parent"] != digest(history[round_id - 1]["body"])
                or len(members) < 2 or len(set(members)) != len(members)
                or any(name not in candidates for name in members)
                or digest([candidates[name] for name in members]) != roster["updates"]):
            raise ValueError("masked wire selected updates differ from certified roster")
        if p.mgf_percentile:
            probes = [candidates[name]["body"]["mgf_probe"] for name in p.clients if name in candidates]
            if certificate.get("mgf_candidates") != probes:
                raise ValueError("masked wire candidate witnesses differ from client messages")
        else:
            bound = history[round_id - 1]["body"]["mgf_state"]["bound"]
            if any(not p.mgf_codec.accepts(candidates[name]["body"].get(
                    "mgf_vector", candidates[name]["body"]["vector"]), bound) for name in members):
                raise ValueError("masked wire selected update exceeds certified MGF bound")
        selected_count += len(members)
    return {"rounds": rounds, "candidate_updates": sum(map(len, per_round.values())),
            "selected_updates": selected_count, "plaintext_classifier_fields": 0,
            "mask_backend": p.mask_backend, "model_coordinates": p.dimension,
            "filter_coordinates": p.mgf_dimension,
            **({"single_view_coordinates": p.mgf_dimension} if p.mgf_single_view else {}),
            "scope": "offline signed client cache/roster/probe binding; not a training or privacy proof"}


def replay_selected_aggregate(root, case, p, history, rosters, *, trainer_factory=None):
    """Optional local experiment check, never part of the secure wire protocol.

    Re-train selected clients using the staged data and seeds and compare their
    quantized mean with the certified model. This needs local experiment data;
    it is not a distributed training proof and does not export client deltas.
    """
    if not p.mgf_enabled or p.ema_weight or len(history) != len(rosters) + 1:
        raise ValueError("selected replay requires complete bounded-MGF history without EMA")
    catalog = json.loads((Path(root) / "catalog.json").read_text())[case]
    native_trainer = trainer_factory is None
    if native_trainer:
        import torch
        from trustlessfl.fmnist import FmnistTrainer

        def trainer_factory(node):
            return FmnistTrainer(node["fmnist-shard"], node["fmnist-reference"],
                seed=int(node.get("fmnist-seed", 1)), epochs=int(node.get("fmnist-epochs", 2)),
                batch_size=int(node.get("fmnist-batch-size", 64)),
                device=str(node.get("fmnist-device", "cpu")), attack=node.get("fmnist-attack"),
                sampling_policy=node.get("fmnist-sampling-policy", "legacy"))
    calls, max_error = 0, 0.0
    for round_id, certificate in enumerate(rosters, 1):
        previous = history[round_id - 1]["body"]["model"]
        members = certificate["body"]["members"]
        if len(members) < 2 or len(set(members)) != len(members):
            raise ValueError("selected replay has invalid roster")
        total = [0] * p.dimension
        for name in members:
            index = p.clients.index(name)
            trainer = trainer_factory(catalog[str(index)])
            if native_trainer:
                # Official Flower workers use OMP/MKL_NUM_THREADS=1. Threaded
                # CPU reductions can cross a fixed-point rounding boundary.
                # Match the worker instead of loosening aggregate tolerance.
                previous_threads = torch.get_num_threads()
                try:
                    torch.set_num_threads(1)
                    delta = trainer(np.asarray(previous), index, p.learning_rate, round_id)
                finally:
                    torch.set_num_threads(previous_threads)
            else:
                delta = trainer(np.asarray(previous), index, p.learning_rate, round_id)
            encoded = p.codec.encode(delta)
            if len(encoded) != p.dimension:
                raise ValueError("selected replay trainer dimension differs")
            total = [a + b for a, b in zip(total, encoded, strict=True)]
            calls += 1
        expected = [w + x / (p.codec.scale * len(members))
                    for w, x in zip(previous, total, strict=True)]
        actual = np.asarray(history[round_id]["body"]["model"])
        if actual.shape != (p.dimension,) or not np.isfinite(actual).all():
            raise ValueError("selected replay has invalid certified model")
        error = float(np.max(np.abs(actual - expected)))
        max_error = max(max_error, error)
        if error > 1e-12:
            raise ValueError(f"selected replay quantized mean differs from certified model "
                             f"in round {round_id} (max_abs_error={error:.6g})")
    return {"rounds": len(rosters), "replayed_training_calls": calls,
            "model_max_abs_error": max_error, "tolerance": 1e-12,
            **({"cpu_intraop_threads": 1} if native_trainer else {}),
            "scope": "offline selected-client training replay; no client deltas exported; not a training proof"}
