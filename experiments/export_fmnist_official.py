"""Export a sanitized, hash-linked summary of official Flower FMNIST runs."""

import argparse
import hashlib
import json
import math
from pathlib import Path

from trustlessfl.crypto import canonical


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def author_trainer_summary(curve: list[dict]) -> dict:
    """Author trainer.py mean ASR/TER/MAX-ASR, excluding checkpoint round 0.

    Values remain fractions rather than percentages. This is a summary of the
    supplied port run, not evidence that an unspecified paper figure used it.
    """
    if not isinstance(curve, list) or len(curve) < 2:
        raise ValueError("author summary requires checkpoint and trained rounds")
    for index, row in enumerate(curve):
        if (not isinstance(row, dict) or type(row.get("round")) is not int
                or row["round"] != index
                or any(type(row.get(field)) not in (int, float)
                       or not math.isfinite(row[field]) or not 0 <= row[field] <= 1
                       for field in ("accuracy", "attack_success_rate"))):
            raise ValueError("invalid author summary curve")
    trained = curve[1:]
    attacks = [row["attack_success_rate"] for row in trained]
    return {"first_round": 1, "last_round": len(trained),
            "mean_attack_success_rate": sum(attacks) / len(trained),
            "mean_test_error_rate": 1 - sum(row["accuracy"] for row in trained) / len(trained),
            "max_attack_success_rate": max(attacks)}


def phase_timings(trace: list[dict]) -> dict:
    """Sum coordinator-observed RPC batch durations, not pure crypto CPU time."""
    if not isinstance(trace, list):
        raise ValueError("invalid official Flower timing trace")
    phases = {}
    for row in trace:
        if (not isinstance(row, dict) or not isinstance(row.get("action"), str)
                or not row["action"]
                or type(row.get("requests")) is not int or row["requests"] < 0
                or type(row.get("replies")) is not int or row["replies"] < 0
                or type(row.get("seconds")) not in (int, float)
                or not math.isfinite(row["seconds"]) or row["seconds"] < 0):
            raise ValueError("invalid official Flower timing trace")
        phase = phases.setdefault(row["action"], {"calls": 0, "requests": 0,
                                                 "replies": 0, "seconds": 0.0})
        phase["calls"] += 1
        phase["requests"] += row["requests"]
        phase["replies"] += row["replies"]
        phase["seconds"] += row["seconds"]
        if not math.isfinite(phase["seconds"]):
            raise ValueError("official Flower timing sum overflow")
    return phases


def export(source: Path, output: Path) -> dict:
    source = source.resolve()
    provenance_path = source / "provenance.json"
    verification_path = source / "verification.json"
    provenance = json.loads(provenance_path.read_text())
    if "author_reference" in provenance:
        from trustlessfl.aion_author_reference import verify_author_reference
        verify_author_reference(source, provenance["author_reference"])
    verification = json.loads(verification_path.read_text())
    modes = provenance["modes"]
    baseline_pair = "aion" in modes and "quantized" in modes
    oracle_pair = "aion_mgf_oracle" in modes and "mgf" in modes
    bounded_mgf = "aion_mgf_beta" in modes
    author_pair = (provenance.get("author_mgf") is True and "mgf" in modes
                   and "quantized" in modes)
    if not baseline_pair and not oracle_pair and not bounded_mgf and not author_pair:
        raise ValueError("official export needs AION controls or a bounded-MGF run")
    if baseline_pair and verification["aion_quantized_max_abs_error"] != 0:
        raise ValueError("AION and quantized Flower models differ")
    if oracle_pair:
        control = verification.get("oracle_mgf_control")
        agreement = control.get("selected_equal_by_round") if isinstance(control, dict) else None
        if (not isinstance(agreement, list) or len(agreement) != provenance["rounds"]
                or any(value is not True for value in agreement)):
            raise ValueError("oracle AION and plaintext MGF differ in their selection trace")
    runs = {}
    for mode in modes:
        paths = list((source / mode / "runtime-results").glob("run-*/results.json"))
        if len(paths) != 1:
            raise ValueError(f"expected exactly one official {mode} run")
        raw = json.loads(paths[0].read_text())
        if (raw["run_id"] != verification[mode]["run_id"]
                or raw["config"]["mode"] != mode or len(raw["cases"]) != 1
                or raw["cases"][0]["status"] != "completed"):
            raise ValueError(f"official Flower result does not match verification: {mode}")
        model_path = paths[0].parent / f"{provenance['case']}-models.npz"
        item = verification[mode]
        policy = provenance.get("training", {}).get("sampling_policy", "legacy")
        if mode in ("aion", "aion_mgf_oracle", "aion_mgf_beta") and policy != "legacy":
            audit = item.get("training_sampling_audit")
            expected_calls = (sum(len(cohort) for cohort in provenance["schedule"].values())
                              if provenance.get("schedule") is not None
                              else provenance["population"] * provenance["rounds"])
            if (not isinstance(audit, dict) or audit.get("sampling_policy") != policy
                    or type(audit.get("training_calls")) is not int
                    or audit["training_calls"] != expected_calls):
                raise ValueError("missing secure training sampling audit")
        if mode in ("mgf", "quantized", "plain") and policy != "legacy":
            metadata = raw["cases"][0].get("training_meta")
            if (not isinstance(metadata, list) or not metadata
                    or any(meta.get("sampling_policy", "legacy") != policy for meta in metadata)):
                raise ValueError("actual training sampling policy differs from provenance")
        runs[mode] = {"run_id": item["run_id"], "seconds": item["seconds"],
                      "curve": item["curve"], "model_sha256": sha256(model_path),
                      "result_sha256": sha256(paths[0])}
        if provenance.get("author_mgf"):
            runs[mode]["author_trainer_summary"] = author_trainer_summary(item["curve"])
        if "training_sampling_audit" in item:
            runs[mode]["training_sampling_audit"] = item["training_sampling_audit"]
        if "masked_wire_audit" in item:
            runs[mode]["masked_wire_audit"] = item["masked_wire_audit"]
        if "masked_round_state" in item:
            runs[mode]["masked_round_state"] = item["masked_round_state"]
        if "selected_replay" in item:
            replay = item["selected_replay"]
            rosters = raw["cases"][0].get("certified_rosters", [])
            expected_calls = sum(len(roster["body"]["members"]) for roster in rosters)
            if (mode != "aion_mgf_beta" or not isinstance(replay, dict)
                    or type(replay.get("rounds")) is not int
                    or replay["rounds"] != provenance["rounds"]
                    or len(rosters) != provenance["rounds"]
                    or type(replay.get("replayed_training_calls")) is not int
                    or replay["replayed_training_calls"] != expected_calls
                    or type(replay.get("model_max_abs_error")) not in (int, float)
                    or not math.isfinite(replay["model_max_abs_error"])
                    or not 0 <= replay["model_max_abs_error"] <= 1e-12
                    or replay.get("tolerance") != 1e-12):
                raise ValueError("selected-client replay is incomplete or differs from certified models")
            runs[mode]["selected_replay"] = replay
        if "trace" in raw["cases"][0]:
            runs[mode]["phase_timings"] = phase_timings(raw["cases"][0]["trace"])
        if mode in ("mgf", "aion_mgf_oracle"):
            runs[mode]["selection"] = [{
                "round": selection["round"],
                "selected_count": selection["selected_count"],
                "selected_attackers": [name for name in selection["selected"]
                                       if int(name.removeprefix("client-")) < provenance["attack_clients"]],
                "small_cohort_floor_override": selection["small_cohort_floor_override"],
            } for selection in item["selections"]]
        elif mode == "aion_mgf_beta":
            runs[mode]["selection"] = [{"round": selection["round"],
                "selected_count": selection["selected_count"],
                **({"bound": selection["bound"],
                    "small_cohort_floor_override": selection["small_cohort_floor_override"]}
                   if provenance.get("mgf_percentile") else {}),
                "selected_attackers": [name for name in selection["selected"]
                                       if int(name.removeprefix("client-")) < provenance["attack_clients"]]}
                for selection in item["selections"]]
    result = {
        "scope": ("official Flower SuperLink/Ray; oracle MGF exposes plaintext classifier updates"
                  if oracle_pair else
                  "official Flower SuperLink/Ray; MGF is a separate plaintext control"),
        "case": provenance["case"], "population": provenance["population"],
        "participants": provenance["participants"], "aggregators": provenance["aggregators"],
        "rounds": provenance["rounds"], "seed": provenance["seed"],
        "hotstuff": provenance.get("hotstuff", False),
        "attack_clients": provenance["attack_clients"],
        "attack_rounds": provenance["attack_rounds"],
        **({"attack_round_rng_policy": provenance["attack_round_rng_policy"]}
           if "attack_round_rng_policy" in provenance else {}),
        "assigned_rows": provenance["assigned_rows"],
        **({"poison_indices_sha256": provenance["poison_indices_sha256"]}
           if "poison_indices_sha256" in provenance else {}),
        **({"partition_rng_policy": provenance["partition_rng_policy"]}
           if "partition_rng_policy" in provenance else {}),
        **({"poison_rng_policy": provenance["poison_rng_policy"]}
           if "poison_rng_policy" in provenance else {}),
        **({"cohort_sampling": provenance["cohort_sampling"]}
           if "cohort_sampling" in provenance else {}),
        "checkpoint_sha256": provenance["checkpoint_sha256"],
        "versions": provenance.get("versions"),
        **({"author_reference": provenance["author_reference"]} if "author_reference" in provenance else {}),
        **({"training": provenance["training"]} if "training" in provenance else {}),
        "provenance_sha256": sha256(provenance_path),
        "verification_sha256": sha256(verification_path),
        "runs": runs,
    }
    if baseline_pair:
        result["aion_quantized_max_abs_error"] = verification["aion_quantized_max_abs_error"]
    if oracle_pair:
        result["oracle_mgf_control"] = verification["oracle_mgf_control"]
    if bounded_mgf:
        result["scope"] = ("official Flower SuperLink/Ray; bounded masked MGF "
                           + ("classifier projection" if provenance.get("mgf_projection") else "full vector")
                           + "; no proven input privacy or individual mask/probe/ASR consistency proof")
        result["mgf_projection"] = provenance.get("mgf_projection", False)
        result["mgf_single_view"] = provenance.get("mgf_single_view", False)
        result["mgf_percentile"] = provenance.get("mgf_percentile", False)
        result["mgf_artifact_bound"] = provenance.get("mgf_artifact_bound", False)
        result["mgf_beta"] = provenance.get("mgf_beta")
    if author_pair:
        result["scope"] = ("official Flower SuperLink/Ray; author SHPRG/MGF torch.float32 CPU "
                           "plaintext experiment, compared with quantized no-filter control; "
                           "not a secure ASR run or GPU bitwise reproduction")
        result["author_mgf"] = True
    if provenance.get("author_mgf") and oracle_pair:
        result["scope"] = ("official Flower SuperLink/Ray; author SHPRG/MGF classifier-plaintext "
                           "selection linked to masked ASR; not private MGF or GPU bitwise reproduction")
        result["author_mgf"] = True
    if "original_hprf_setup_sha256" in provenance:
        result["original_hprf_setup_sha256"] = provenance["original_hprf_setup_sha256"]
        result["original_hprf_sha256"] = provenance["original_hprf_sha256"]
    output.mkdir(parents=True, exist_ok=False)
    (output / "results.json").write_bytes(canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = export(args.source, args.output)
    print(json.dumps({"output": str(args.output), "case": result["case"],
                      "rounds": result["rounds"], "modes": list(result["runs"])}, indent=2))


if __name__ == "__main__":
    main()
