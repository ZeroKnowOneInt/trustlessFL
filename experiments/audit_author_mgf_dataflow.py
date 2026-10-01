"""Reproducible source audit separating author ASR-MMF from training MGF.

This is a structural audit of the public author tree.  It does not execute
training and does not infer a private network protocol from the ML artifact.
"""

import argparse
import ast
import hashlib
import json
from pathlib import Path


def _function(tree, name, class_name=None):
    nodes = tree.body
    if class_name is not None:
        owner = next((n for n in nodes if isinstance(n, ast.ClassDef) and n.name == class_name), None)
        if owner is None:
            raise ValueError(f"missing class {class_name}")
        nodes = owner.body
    found = [n for n in nodes if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]
    if len(found) != 1:
        raise ValueError(f"expected exactly one {class_name or 'module'}.{name}")
    return found[0]


def _source(path):
    raw = Path(path).read_bytes()
    text = raw.decode("utf-8")
    return raw, text, ast.parse(text, filename=str(path))


def _segment(text, node):
    value = ast.get_source_segment(text, node)
    if value is None:
        raise ValueError("unable to recover audited source segment")
    return value


def _normalized_hash(node):
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def _has_call(node, suffix):
    for item in ast.walk(node):
        if not isinstance(item, ast.Call):
            continue
        current, parts = item.func, []
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        if ".".join(reversed(parts)).endswith(suffix):
            return True
    return False


def _contains_names(node, *names):
    actual = {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}
    return set(names) <= actual


def _assignment(node, target_name):
    for item in ast.walk(node):
        if isinstance(item, (ast.Assign, ast.AnnAssign)):
            targets = item.targets if isinstance(item, ast.Assign) else [item.target]
            if any(isinstance(target, ast.Name) and target.id == target_name for target in targets):
                return item
    raise ValueError(f"missing assignment to {target_name}")


def audit(source_root):
    root = Path(source_root).resolve()
    client_path = root / "agent/Aion/SA_ClientAgent.py"
    aggregator_path = root / "agent/Aion/SA_Aggregator.py"
    artifact_path = root / "input_validation/FL_Backdoor_CV/roles/aggregation_rules.py"
    launcher_path = root / "input_validation/FL_Backdoor_CV/roles/attack3_fmnist.py"
    files = {}
    parsed = {}
    for name, path in (("asr_client", client_path), ("asr_aggregator", aggregator_path),
                       ("training_mgf", artifact_path), ("fmnist_launcher", launcher_path)):
        raw, text, tree = _source(path)
        files[name] = {"path": str(path.relative_to(root)),
                       "sha256": hashlib.sha256(raw).hexdigest()}
        parsed[name] = (text, tree)

    client_text, client_tree = parsed["asr_client"]
    aggregator_text, aggregator_tree = parsed["asr_aggregator"]
    artifact_text, artifact_tree = parsed["training_mgf"]
    launcher_text, _ = parsed["fmnist_launcher"]
    send = _function(client_tree, "sendVectors", "SA_ClientAgent")
    report = _function(aggregator_tree, "report_process", "SA_AggregatorAgent")
    reconstruct = _function(aggregator_tree, "reconstruction_process", "SA_AggregatorAgent")
    mmf = _function(aggregator_tree, "MMF", "SA_AggregatorAgent")
    mgf = _function(artifact_tree, "aion")

    last_layer = _assignment(mgf, "last_layer_updates")
    seeds = _assignment(mgf, "seeds")
    masked = _assignment(mgf, "masked_updates")
    global_assignments = [item for item in ast.walk(mgf) if isinstance(item, ast.Assign)
                          and any(isinstance(target, ast.Subscript)
                                  and isinstance(target.value, ast.Name)
                                  and target.value.id == "global_update" for target in item.targets)]

    checks = {
        "asr_client_generates_original_hprf": _has_call(send, "hprf.hprf"),
        "asr_client_shares_key_only_in_round_one":
            "if self.current_iteration == 1:" in _segment(client_text, send)
            and "self.share_mask_seed()" in _segment(client_text, send),
        "asr_client_sends_only_masked_vector":
            '"masked_vector": masked_vec' in _segment(client_text, send),
        "asr_mmf_receives_network_masked_vectors":
            "self.MMF(self.user_masked_vectors" in _segment(aggregator_text, report),
        "asr_selected_sum_is_mod_p":
            "self.vec_sum_partial += self.user_masked_vectors[id]" in _segment(aggregator_text, report)
            and "self.vec_sum_partial %= self.hprf_prime" in _segment(aggregator_text, report),
        "asr_reconstructs_sum_key_hprf": _has_call(reconstruct, "hprf.hprf"),
        "asr_subtracts_aggregate_hprf":
            "self.vec_sum_partial - self.seed_sum_hprf" in _segment(aggregator_text, reconstruct),
        "asr_mmf_min_30_max_80_inclusive":
            "MIN_THRESHOLD = 0.3" in _segment(aggregator_text, mmf)
            and "int(0.8 * cnt)" in _segment(aggregator_text, mmf)
            and "if v <= b:" in _segment(aggregator_text, mmf),
        "training_mgf_starts_from_plain_model_updates":
            _contains_names(last_layer.value, "model_updates"),
        "training_mgf_generates_seeds_inside_server_function":
            _has_call(seeds, "shprg.generate_seeds"),
        "training_mgf_filters_plain_plus_shprg_mask":
            _contains_names(masked.value, "last_layer_updates", "vector"),
        "training_mgf_computes_individual_mask_sum": _has_call(mgf, "shprg.client_sum_hprg"),
        "training_mgf_averages_selected_plain_updates":
            any(_contains_names(item.value, "model_updates", "indices_selected")
                and _has_call(item.value, "mean") for item in global_assignments),
        "training_mgf_left_boundary_min_10_max_80":
            "torch.searchsorted(sorted_l2_norm, b)" in _segment(artifact_text, mgf)
            and "args.min_threshold * cnt" in _segment(artifact_text, mgf)
            and "int(0.8 * cnt)" in _segment(artifact_text, mgf)
            and '"--min_threshold=0.1"' in launcher_text,
        "training_mgf_has_no_hprf_dmc_dmr_reference":
            not ({"HPRF", "DMC", "DMR"} & {item.id for item in ast.walk(mgf)
                                               if isinstance(item, ast.Name)}),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise ValueError("author data-flow audit failed: " + ", ".join(failed))
    return {
        "scope": "public-author-source structural audit; not paper-wire completeness or a security proof",
        "files": files,
        "checks": checks,
        "normalized_function_sha256": {
            "SA_ClientAgent.sendVectors": _normalized_hash(send),
            "SA_AggregatorAgent.report_process": _normalized_hash(report),
            "SA_AggregatorAgent.reconstruction_process": _normalized_hash(reconstruct),
            "SA_AggregatorAgent.MMF": _normalized_hash(mmf),
            "aggregation_rules.aion": _normalized_hash(mgf),
        },
        "conclusion": {
            "asr_path": "client HPRF-masked vector -> masked MMF -> selected modular sum -> aggregate-key HPRF removal",
            "training_artifact_path": "server-held plaintext update -> server-generated SHPRG mask for classifier selection -> selected plaintext mean",
            "not_present_in_training_artifact": "client-side scaled-HPRF-only Algorithm 6/7/8 network path",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
