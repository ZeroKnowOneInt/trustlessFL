"""Simulation metadata audit covers every candidate, not only MGF survivors."""

import json

import pytest

from experiments.run_fmnist_official import verify_secure_training_sampling
from trustlessfl.crypto import digest
from trustlessfl.protocol import Parameters


@pytest.fixture
def audit_input(tmp_path):
    p = Parameters("training-audit", ("client-0", "client-1"), ("a0", "a1", "a2", "a3"))
    cohorts = {1: set(p.clients), 2: {"client-1"}}
    catalog, paths = {}, []
    for index, name in enumerate(p.clients):
        folder = tmp_path / name
        folder.mkdir()
        catalog[str(index)] = {"aion-identity": str(folder / "identity.json"),
                               "fmnist-sampling-policy": "author-loader"}
        path = folder / f"state-{digest({'task': p.task, 'party': name})}.json"
        paths.append(path)
        path.write_text(json.dumps({"training_meta": {str(r): {"round": r,
            "partition": index, "sampling_policy": "author-loader"}
            for r, cohort in cohorts.items() if name in cohort}}))
    (tmp_path / "catalog.json").write_text(json.dumps({"case": catalog}))
    return tmp_path, p, cohorts, paths


def test_audit_confirms_all_candidate_training_calls(audit_input):
    root, p, cohorts, _ = audit_input
    audit = verify_secure_training_sampling(root, "case", p, cohorts, "author-loader")
    assert audit["training_calls"] == 3 and audit["sampling_policy"] == "author-loader"
    assert "not verifiable training" in audit["scope"]


@pytest.mark.parametrize("field,value", [("sampling_policy", "legacy"),
    ("round", True), ("round", 2), ("partition", True), ("partition", 1)])
def test_audit_rejects_wrong_actual_policy_or_identity(audit_input, field, value):
    root, p, cohorts, paths = audit_input
    state = json.loads(paths[0].read_text())
    state["training_meta"]["1"][field] = value
    paths[0].write_text(json.dumps(state))
    with pytest.raises(ValueError, match="actual secure training"):
        verify_secure_training_sampling(root, "case", p, cohorts, "author-loader")


def test_audit_rejects_missing_training_or_wrong_catalog(audit_input):
    root, p, cohorts, paths = audit_input
    original = paths[0].read_text()
    paths[0].write_text("{}")
    with pytest.raises(ValueError, match="staged cohort"):
        verify_secure_training_sampling(root, "case", p, cohorts, "author-loader")
    paths[0].write_text(original)
    catalog = json.loads((root / "catalog.json").read_text())
    catalog["case"]["0"]["fmnist-sampling-policy"] = "legacy"
    (root / "catalog.json").write_text(json.dumps(catalog))
    with pytest.raises(ValueError, match="catalog training"):
        verify_secure_training_sampling(root, "case", p, cohorts, "author-loader")
