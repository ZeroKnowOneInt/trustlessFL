"""Comparisons must match actual training catalogs, not only result labels."""

import copy
import json

import pytest

from experiments.compare_fmnist_official import CONDITION_FIELDS, compare, conditions, require_matching


def stage(tmp_path, name, mode):
    source = tmp_path / name
    root = source / mode / "provision"
    (root / "case").mkdir(parents=True)
    provenance = {field: "same" for field in CONDITION_FIELDS}
    provenance.update(case="case", population=2, seed=0, attack_clients=1,
                      rounds=1, attack_rounds=[1],
                      source_sha256={"trustlessfl/fmnist.py": "a", "trustlessfl/numeric.py": "b"})
    (source / "provenance.json").write_text(json.dumps(provenance))
    (root / "case/manifest.json").write_text(json.dumps({"parameters": {
        "learning_rate": 0.001, "decimals": 6}}))
    nodes = {str(index): {"fmnist-shard": str(source / "inputs" / f"client-{index}.npz"),
        "fmnist-reference": str(source / "inputs/reference.npz"),
        "fmnist-seed": 0, "fmnist-epochs": 2, "fmnist-batch-size": 64, "fmnist-device": "cpu"}
        for index in range(2)}
    nodes["0"]["fmnist-attack"] = {"rounds": [1], "steps": 120, "boost": 20,
        "poison_batch": 6, "clean_path": str(source / "inputs/attack-clean.npz"),
        "poison_path": str(source / "inputs/attack-poison.npz")}
    (root / "catalog.json").write_text(json.dumps({"case": nodes}))
    return source, root, nodes


def test_comparison_normalizes_roots_but_rejects_training_changes(tmp_path):
    defense, _, _ = stage(tmp_path, "defense", "aion_mgf_beta")
    control, root, nodes = stage(tmp_path, "control", "quantized")
    settings = conditions(defense, "aion_mgf_beta")
    require_matching(settings, conditions(control, "quantized"))
    nodes["1"]["fmnist-epochs"] = 3
    (root / "catalog.json").write_text(json.dumps({"case": nodes}))
    with pytest.raises(ValueError, match="training_profiles"):
        require_matching(settings, conditions(control, "quantized"))
    changed = copy.deepcopy(settings)
    changed["input_sha256"] = "different dataset"
    with pytest.raises(ValueError, match="input_sha256"):
        require_matching(settings, changed)


def test_comparison_rejects_unstaged_path_and_wrong_training_seed(tmp_path):
    source, root, nodes = stage(tmp_path, "run", "aion_mgf_beta")
    original = nodes["0"]["fmnist-shard"]
    nodes["0"]["fmnist-shard"] = str(tmp_path / "unrelated.npz")
    (root / "catalog.json").write_text(json.dumps({"case": nodes}))
    with pytest.raises(ValueError, match="training path"):
        conditions(source, "aion_mgf_beta")
    nodes["0"]["fmnist-shard"] = original
    nodes["0"]["fmnist-seed"] = 1
    (root / "catalog.json").write_text(json.dumps({"case": nodes}))
    with pytest.raises(ValueError, match="training seed"):
        conditions(source, "aion_mgf_beta")


def test_comparison_reverifies_both_runs_before_export(tmp_path, monkeypatch):
    defense, _, _ = stage(tmp_path, "defense", "aion_mgf_beta")
    control, _, _ = stage(tmp_path, "control", "quantized")
    checked = []
    monkeypatch.setattr("experiments.compare_fmnist_official.verify", lambda path: checked.append(path))
    curve = [{"round": 0, "accuracy": 0.8, "attack_success_rate": 0.1},
             {"round": 1, "accuracy": 0.9, "attack_success_rate": 0.05}]
    for source, mode in ((defense, "aion_mgf_beta"), (control, "quantized")):
        (source / "verification.json").write_text(json.dumps({mode: {
            "curve": curve, "run_id": 1, "seconds": 2,
            "selections": [{"round": 1, "selected_count": 2,
                            "selected": ["client-0", "client-1"]}] if mode == "aion_mgf_beta" else []}}))
    result = compare(defense, control, tmp_path / "comparison")
    assert checked == [defense.resolve(), control.resolve()]
    assert result["masked_selection"][0]["selected_attackers"] == ["client-0"]
    assert (tmp_path / "comparison/results.json").exists()
