"""Offline replay of selected source-ASR learning updates; no deltas exported."""

import argparse
import hashlib
import json
from pathlib import Path
import tomllib

import numpy as np

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.aion_source_asr import source_inventory
from trustlessfl.aion_source_bft import check_source_commit
from trustlessfl.crypto import canonical, digest
from trustlessfl.numeric import FixedPoint
from trustlessfl.aion_source_cohort import round_clients
from trustlessfl import aion_source_roster as roster_consensus
from trustlessfl.source_profiles import (CENTERED, TransmissionCodec, profile,
                                        validate_profile, update_codec)


def verify_learning(root, *, inputs=None, epochs=2, seed=0):
    root = Path(root)
    manifest = json.loads((root / "manifest.json").read_text())
    from trustlessfl import aion_source_sharing as sharing
    reconstruction_threshold = sharing.threshold(manifest) if sharing.enabled(manifest) else None
    from trustlessfl.source_paper_numeric import filter_rule, scale_source, scope_span, mgf_scope
    mgf_rule = filter_rule(manifest) if "paper_numerics" in manifest else "not applicable"
    mgf_units = scale_source(manifest) if "paper_numerics" in manifest else "not applicable"
    post_filter_bft = roster_consensus.enabled(manifest)
    from trustlessfl.aion_source_aggregate import enabled as aggregate_validation_enabled, check_validations
    aggregate_validation = aggregate_validation_enabled(manifest)
    result = json.loads((root / "results.json").read_text())
    if (root / "staging.json").exists():
        staged_app = json.loads((root / "staging.json").read_text())
        actual = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (root / "app/trustlessfl").glob("*.py")}
        if actual != staged_app["source_sha256"]:
            raise ValueError("official staged package changed")
        app_bytes = (root / "app/pyproject.toml").read_bytes()
        if hashlib.sha256(app_bytes).hexdigest() != staged_app["app_config_sha256"]:
            raise ValueError("official staged configuration changed")
        config = tomllib.loads(app_bytes.decode())["tool"]["flwr"]["app"]["config"]
        for name, hash_key in [("aion-source-manifest", "source-manifest-sha256"),
                               ("source-node-configs", "source-node-configs-sha256")]:
            if hashlib.sha256(Path(config[name]).read_bytes()).hexdigest() != config[hash_key]:
                raise ValueError("official staged manifest/catalog changed")
    if source_inventory(manifest["source-root"]) != manifest["source-sha256"]:
        raise ValueError("source snapshot changed")
    workload = manifest.get("workload", "ones")
    if workload not in ("synthetic", "fmnist") or len(result["history"]) != manifest["rounds"]:
        raise ValueError("complete source learning history required")
    setup = OriginalAionHPRF.from_directory(Path(manifest["source-root"]) / "agent/Aion/HPRF").public_setup()
    original_hprf = OriginalAionHPRF.from_public_setup(setup)
    validate_profile(manifest, original_hprf)
    codec = update_codec(manifest, original_hprf)
    centered = isinstance(codec, TransmissionCodec)
    input_hashes = {}
    if workload == "fmnist":
        if inputs is None:
            raise ValueError("FMNIST replay requires staged inputs")
        inputs = Path(inputs)
        names = ["reference.npz", *[f"client-{i}.npz" for i in manifest["clients"]]]
        staged = manifest.get("training", {})
        if staged.get("attack_clients", 0):
            names += ["attack-clean.npz", "attack-poison.npz"]
        input_hashes = {name: hashlib.sha256((inputs / name).read_bytes()).hexdigest() for name in names}
        if staged.get("input_sha256") and staged["input_sha256"] != input_hashes:
            raise ValueError("source learning staged inputs changed")
        if staged and (staged["epochs"] != epochs or staged["seed"] != seed):
            raise ValueError("source learning replay settings differ")
        for name, sha in staged.get("evaluation_sha256", {}).items():
            if hashlib.sha256((inputs / name).read_bytes()).hexdigest() != sha:
                raise ValueError("source learning evaluation inputs changed")
    legal = result["legal_bft"]
    registry = legal["registry"]
    check_source_commit(manifest, legal, registry, 1,
        digest(dict(msg="VALID_CLIENTS", iteration=0, valid_clients=manifest["clients"])))
    previous = np.zeros(manifest["dimension"])
    max_error, calls = 0.0, 0
    paper_history = []
    scaled_range_checks = []
    for r, entry in enumerate(result["history"], 1):
        if entry["round"] != r:
            raise ValueError("source learning history out of order")
        members = entry["selected"]
        cohort = round_clients(manifest, r)
        if "cohort_schedule" in manifest and entry.get("online_clients") != cohort:
            raise ValueError("source learning online cohort differs")
        if (len(members) < 2 or len(set(members)) != len(members)
                or any(i not in cohort for i in members)):
            raise ValueError("invalid source learning survivors")
        from trustlessfl.aion_source_selection import enabled as selection_authorization_enabled, check_authorizations
        if selection_authorization_enabled(manifest):
            check_authorizations(manifest, entry.get("selection_authorizations", []), r,
                members, entry["bound"], parent=digest(previous.tolist()))
        roster_body = (roster_consensus.statement(manifest, r, members,
            vectors_digest=entry["selection_authorizations"][0]["body"]["vectors_digest"]
            if "source_profile" in manifest else None) if post_filter_bft else
            dict(msg="ONLINE_CLIENTS", iteration=r,
                 online_clients=[int(i in cohort) for i in manifest["clients"]]))
        check_source_commit(manifest, entry["online_bft"], registry, 2 * r, digest(roster_body))
        body = dict(msg="FINAL_SUM", iteration=r, task=manifest["task"],
                    final_sum=entry["result"], model=entry["model"])
        if "paper_numerics" in manifest:
            body["paper_numeric"] = entry["paper_numeric"]
        if aggregate_validation:
            check_validations(manifest, entry.get("aggregate_validations", []), r,
                              members, body, parent=digest(previous.tolist()),
                              vectors_digest=entry["selection_authorizations"][0]["body"]["vectors_digest"])
        proof, = entry["source_bft"]
        check_source_commit(manifest, proof, registry, 2 * r + 1, digest(body))
        total = np.zeros(manifest["dimension"], dtype=object if centered else np.int64)
        for i in members:
            if workload == "synthetic":
                from trustlessfl.task import local_delta
                delta = local_delta(previous, i, manifest["learning_rate"])
            else:
                import torch
                from trustlessfl.fmnist import FmnistTrainer
                attack = None
                if i < staged.get("attack_clients", 0):
                    attack = dict(rounds=staged["attack_rounds"],
                        clean_path=str(inputs / "attack-clean.npz"), poison_path=str(inputs / "attack-poison.npz"),
                        steps=staged["attack_steps"], boost=staged["attack_boost"], poison_batch=staged["poison_batch"])
                trainer = FmnistTrainer(inputs / f"client-{i}.npz", inputs / "reference.npz",
                    seed=seed, epochs=epochs, batch_size=64, sampling_policy="author-loader", attack=attack)
                threads = torch.get_num_threads()
                try:
                    torch.set_num_threads(1)
                    delta = trainer(previous, i, manifest["learning_rate"], r)
                finally:
                    torch.set_num_threads(threads)
            total += np.asarray(codec.encode(delta), dtype=object if centered else np.int64)
            calls += 1
        mean = total / (len(members) * codec.scale)
        if "paper_numerics" in manifest:
            from fractions import Fraction
            from trustlessfl.paper_dmc import evolve_bound, public_mgf_term
            from trustlessfl.source_paper_numeric import (paper_codec, descriptor, scale_source,
                                                        SUM_SCALE_SOURCE)
            original_hprf = OriginalAionHPRF.from_public_setup(setup)
            previous_linf = paper_history[-1]["next_linf"] if paper_history else None
            pc = paper_codec(manifest, original_hprf, r, previous_linf)
            # Post-hoc observation only: these replayed sums are NOT available
            # to a runtime decoder and cannot justify a new public SUM bound.
            # A correct quantized lift need not be a centered modular lift.
            observed_sum_linf = Fraction(max(abs(int(x)) for x in total), codec.scale)
            decimal_error = (Fraction(pc.error, pc.denominator) if centered else
                (pc.coefficient * (len(members) - 1) + Fraction(len(members), 2)) / pc.denominator)
            scaled_range_checks.append(dict(round=r,
                selected_count=len(members), sum_linf=str(observed_sum_linf),
                scaled_modulus=str(pc.period), half_period=str(pc.period / 2),
                worst_case_decimal_error=str(decimal_error),
                observed_sum_fits_centered_range=(observed_sum_linf + decimal_error < pc.period / 2)))
            meta = entry["paper_numeric"]
            if ("filter_rule" in manifest["paper_numerics"]
                    and meta.get("filter_rule") != mgf_rule):
                raise ValueError("paper MGF filter rule differs from manifest")
            if (meta["scale"] != descriptor(pc) or meta["selected_count"] != len(members)
                    or meta["aggregate"] != "selected-mean"
                    or meta["removal"] != (CENTERED if centered else "conditional-quantized-lift")):
                raise ValueError("paper aggregate numerical metadata differs")
            if "source_profile" in manifest and meta.get("source_profile") != profile(manifest):
                raise ValueError("source numeric profile differs from manifest")
            if meta.get("mgf_scope", "projection") != mgf_scope(manifest):
                raise ValueError("paper MGF history scope differs from manifest")
            start, stop = scope_span(manifest)
            actual_means = [Fraction(int(x), len(members) * codec.scale) for x in total[start:stop]]
            units = scale_source(manifest)
            historical_update = ([Fraction(int(x), codec.scale) for x in total[start:stop]]
                                 if units == SUM_SCALE_SOURCE else actual_means)
            if "scale_source" in manifest["paper_numerics"]:
                expected_history = ("selected-sum" if units == SUM_SCALE_SOURCE
                                    else "legacy-mean-update-mask-sum")
                if (meta.get("scale_source") != units
                        or meta.get("history_aggregate") != expected_history):
                    raise ValueError("paper scale/history units differ from manifest")
            if Fraction(meta["next_linf"]) != max(abs(x) for x in historical_update):
                raise ValueError("paper next scale differs from independently replayed aggregate")
            if "mask_norm_source" in meta:
                expected_source = ("recovered-selected-transmission-mask-sum" if centered
                                   else "recovered-selected-decimal-mask-sum")
                if meta["mask_norm_source"] != expected_source:
                    raise ValueError("unexpected paper mask-norm semantics")
                mask_linf = Fraction(meta["mask_linf"])
                if not 0 <= mask_linf <= len(members) * pc.period + Fraction(len(members), 2 * pc.denominator):
                    raise ValueError("paper mask norm exceeds wire capacity")
                term = public_mgf_term(historical_update, [0] * len(historical_update), pc) + mask_linf
                if Fraction(meta["history_term"]) != term:
                    raise ValueError("paper history term differs from public aggregate and declared mask norm")
            if r > 3:
                expected_bound = evolve_bound(paper_history[-1]["bound"],
                    older_term=paper_history[-2]["history_term"], newer_term=paper_history[-1]["history_term"])
                if Fraction(meta["bound"]) != expected_bound:
                    raise ValueError("paper bound differs from two committed historical terms")
            paper_history.append(meta)
        expected = previous + mean
        model = np.asarray(entry["model"])
        actual_mean = np.asarray(entry["result"])
        if model.shape != expected.shape or actual_mean.shape != mean.shape:
            raise ValueError("source learning model dimension differs")
        error = max(float(np.max(np.abs(model - expected))), float(np.max(np.abs(actual_mean - mean))))
        if not np.isfinite(model).all() or not np.isfinite(actual_mean).all() or error > 1e-12:
            raise ValueError(f"source learning selected mean differs in round {r} (error={error:.6g})")
        max_error = max(max_error, error)
        previous = model
    if result["key_share_deliveries"] != len(manifest["clients"]) * len(manifest["committee"]):
        raise ValueError("source learning key sharing count differs")
    if result["mask_share_deliveries"] != 0:
        raise ValueError("source learning introduced mask shares")
    if selection_authorization_enabled(manifest) and result.get("selection_authorized_rounds") != manifest["rounds"]:
        raise ValueError("source learning selection authorization count differs")
    if aggregate_validation and result.get("aggregate_validated_rounds") != manifest["rounds"]:
        raise ValueError("source learning aggregate validation count differs")
    return dict(rounds=manifest["rounds"], workload=workload, replayed_training_calls=calls,
        model_max_abs_error=max_error, tolerance=1e-12, key_share_deliveries=result["key_share_deliveries"],
        mask_share_deliveries=0, input_sha256=input_hashes,
        key_reconstruction_threshold=reconstruction_threshold,
        key_reconstruction_threshold_rule=(manifest["sharing_profile"].get(
            "threshold_rule", "historical-max-two-n-div-three")
            if reconstruction_threshold is not None else "original-source-profile"),
        mgf_filter_rule=mgf_rule,
        mgf_scale_source=mgf_units,
        first_bft_subject="post-filter-client-set" if post_filter_bft else "historical-received-client-set",
        selection_authorization_checks=("all committee signed replay receipts, cohort, bound, parent; "
            "masked vector digest agreement, not independent replay of omitted vectors"
            if selection_authorization_enabled(manifest) else "not applicable"),
        input_hash_binding="staged" if manifest.get("training", {}).get("input_sha256") else "verification-time",
        scaled_ring_range_checks=dict(
            scope="post-hoc selected-training SUM observation, not a runtime bound or range proof",
            rounds=scaled_range_checks),
        aggregate_validation_checks=("all committee signed local aggregate replay receipts, selected set, parent, body and vector digest"
            if aggregate_validation else "historical profile: not applicable"),
        paper_metadata_checks=(("scale, next-linf, declared aggregate/history units; mask norm locally replayed by committee, "
            "receipts verified offline; omitted masked vectors/opening not independently reconstructed offline")
            if aggregate_validation else "scale, next-linf, declared aggregate/history units; mask norm itself BFT-bound not independently reconstructed"
            if paper_history else "not applicable"),
        scope="offline selected training replay + normal-path BFT certificates; not an input privacy proof")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    result = verify_learning(args.run, inputs=args.inputs, epochs=args.epochs, seed=args.seed)
    with (args.run / "verification.json").open("xb") as stream:
        stream.write(canonical(result))
    print(json.dumps({k: v for k, v in result.items() if k != "input_sha256"}, indent=2))


if __name__ == "__main__":
    main()
