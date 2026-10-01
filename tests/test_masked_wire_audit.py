"""Offline auditing must inspect rejected candidates without exporting values."""

import json

import pytest

from experiments.audit_masked_wire import audit_masked_wire, replay_selected_aggregate
from trustlessfl.crypto import Identity, ProtocolError, digest
from trustlessfl.protocol import Parameters, Party, certificate


@pytest.fixture(params=["full", "dual", "single"])
def audit_case(tmp_path, request):
    projection = request.param != "full"
    p = Parameters("masked-audit", ("c0", "c1", "c2"), ("a0", "a1", "a2", "a3"),
        dimension=4, decimals=3, mgf_beta="0.2", mgf_initial_alpha="0.2",
        mgf_initial_bound="2", mgf_initial_term="1",
        mgf_projection=(1, 3) if projection else (), mgf_percentile=projection,
        mgf_single_view=request.param == "single")
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry, trainer=lambda *_: [0.1] * 4)
               for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in p.clients]
    votes = [parties[a].initialize({"enrollments": enrollments}) for a in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[c].train({"model": model}) for c in p.clients]
    # This audit checks wire binding, not certificates/selection arithmetic;
    # the official verifier separately verifies both before calling it.
    roster = {"body": {"members": list(p.clients[:2]), "parent": digest(model["body"]),
                        "updates": digest(updates[:2])}}
    if projection:
        roster["mgf_candidates"] = [u["body"]["mgf_probe"] for u in updates]
    catalog, paths = {}, []
    for index, name in enumerate(p.clients):
        directory = tmp_path / name
        directory.mkdir()
        path = directory / f"state-{digest({'task': p.task, 'party': name})}.json"
        path.write_text(json.dumps(parties[name].state))
        catalog[str(index)] = {"aion-identity": str(directory / "identity.json")}
        paths.append(path)
    (tmp_path / "catalog.json").write_text(json.dumps({"case": catalog}))
    args = [tmp_path, "case", p, registry, {1: set(p.clients)}, [model, {}], [roster]]
    return args, paths, identities


def test_signed_candidate_wire_audit(audit_case):
    args, _, _ = audit_case
    result = audit_masked_wire(*args)
    assert result["candidate_updates"] == 3 and result["selected_updates"] == 2
    assert result["plaintext_classifier_fields"] == 0
    assert result["filter_coordinates"] == args[2].mgf_dimension
    expected = {"rounds", "candidate_updates", "selected_updates",
        "plaintext_classifier_fields", "mask_backend", "model_coordinates",
        "filter_coordinates", "scope"}
    if args[2].mgf_single_view:
        expected.add("single_view_coordinates")
        assert result["single_view_coordinates"] == 2
    assert set(result) == expected


def test_single_view_audit_rejects_signed_duplicate_coordinate(audit_case):
    args, paths, identities = audit_case
    if not args[2].mgf_single_view:
        pytest.skip("single-view policy only")
    state = json.loads(paths[-1].read_text())
    body = state["updates"]["1"]["body"]
    body["vector"][1] = 1
    state["updates"]["1"] = identities["c2"].sign(body)
    paths[-1].write_text(json.dumps(state))
    with pytest.raises(ValueError, match="duplicate projection"):
        audit_masked_wire(*args)


@pytest.mark.parametrize("mutation", ["plaintext", "context", "boolean-round", "float-vector", "alpha"])
def test_rejects_signed_bad_wire_even_for_unselected_client(audit_case, mutation):
    args, paths, identities = audit_case
    path = paths[-1]
    state = json.loads(path.read_text())
    body = state["updates"]["1"]["body"]
    if mutation == "plaintext":
        body["oracle_classifier"] = [0.1] * 2
    elif mutation == "context":
        body["task"] = "other-task"
    elif mutation == "boolean-round":
        body["round"] = True
    elif mutation == "float-vector":
        body["vector"][0] = 0.1
    else:
        body["mgf"]["alpha"] = "0.3"
    state["updates"]["1"] = identities["c2"].sign(body)
    path.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="masked wire"):
        audit_masked_wire(*args)


def test_rejects_unsigned_cache_change(audit_case):
    args, paths, _ = audit_case
    state = json.loads(paths[-1].read_text())
    state["updates"]["1"]["body"]["vector"][0] += 1
    paths[-1].write_text(json.dumps(state))
    with pytest.raises(ProtocolError):
        audit_masked_wire(*args)


def test_rejects_missing_round_and_changed_roster_digest(audit_case):
    args, paths, _ = audit_case
    roster = args[-1][0]
    roster["body"]["updates"] = "0" * 64
    with pytest.raises(ValueError, match="certified roster"):
        audit_masked_wire(*args)
    state = json.loads(paths[-1].read_text())
    state["updates"] = {}
    paths[-1].write_text(json.dumps(state))
    with pytest.raises(ValueError, match="staged cohort"):
        audit_masked_wire(*args)


def test_rejects_reordered_percentile_witnesses(audit_case):
    args, _, _ = audit_case
    if not args[2].mgf_percentile:
        return
    args[-1][0]["mgf_candidates"].reverse()
    with pytest.raises(ValueError, match="candidate witnesses"):
        audit_masked_wire(*args)


def test_rejects_incomplete_history(audit_case):
    args, _, _ = audit_case
    args[-2] = args[-2][:1]
    with pytest.raises(ValueError, match="incomplete"):
        audit_masked_wire(*args)


def test_selected_replay_matches_quantized_mean_and_rejects_wrong_model(audit_case):
    args, _, _ = audit_case
    root, case, p, _, _, history, rosters = args
    history[1] = {"body": {"model": [0.101] * p.dimension}}
    factory = lambda node: lambda weights, index, rate, round_id: [0.1006] * p.dimension
    report = replay_selected_aggregate(root, case, p, history, rosters, trainer_factory=factory)
    assert report["replayed_training_calls"] == 2 and report["model_max_abs_error"] == 0
    history[1]["body"]["model"][0] += 0.001
    with pytest.raises(ValueError, match="quantized mean"):
        replay_selected_aggregate(root, case, p, history, rosters, trainer_factory=factory)


def test_selected_replay_tracks_changed_roster_and_previous_model(audit_case):
    args, _, _ = audit_case
    root, case, p, _, _, history, rosters = args
    rosters.append({"body": {"members": ["c1", "c2"]}})
    calls = []

    def delta(weights, index, round_id):
        return [0.1 * round_id + index * 0.001 + weights[0] * 0.01] * p.dimension

    def factory(node):
        def trainer(weights, index, rate, round_id):
            assert node["aion-identity"].endswith(f"c{index}/identity.json")
            calls.append((index, round_id, float(weights[0])))
            return delta(weights, index, round_id)
        return trainer

    for r, roster in enumerate(rosters, 1):
        previous = history[r - 1]["body"]["model"]
        encoded = [p.codec.encode(delta(previous, p.clients.index(name), r))
                   for name in roster["body"]["members"]]
        model = [w + sum(values) / (2 * p.codec.scale)
                 for w, values in zip(previous, zip(*encoded, strict=True), strict=True)]
        if r < len(history):
            history[r] = {"body": {"model": model}}
        else:
            history.append({"body": {"model": model}})
    report = replay_selected_aggregate(root, case, p, history, rosters, trainer_factory=factory)
    assert report["rounds"] == 2 and report["replayed_training_calls"] == 4
    assert report["model_max_abs_error"] == 0
    assert calls == [(0, 1, 0.0), (1, 1, 0.0), (1, 2, 0.1005), (2, 2, 0.1005)]


@pytest.mark.parametrize("enabled", [False, True])
def test_verifier_cli_forwards_explicit_replay_option(tmp_path, monkeypatch, enabled):
    import sys
    from experiments import run_fmnist_official
    calls = []
    monkeypatch.setattr(run_fmnist_official, "verify",
        lambda output, *, replay_selected=False: calls.append((output, replay_selected)))
    argv = ["run_fmnist_official", "--output", str(tmp_path), "--phase", "verify"]
    if enabled:
        argv.append("--replay-selected")
    monkeypatch.setattr(sys, "argv", argv)
    run_fmnist_official.main()
    assert calls == [(tmp_path.resolve(), enabled)]


@pytest.mark.parametrize("provenance", [{"modes": ["aion_mgf_oracle"],
                                        "model_certificate_trace_version": 1},
                                       {"modes": ["aion_mgf_beta"]}])
def test_verifier_replay_requires_masked_mode_and_complete_certificates(tmp_path, provenance):
    from experiments.run_fmnist_official import verify
    (tmp_path / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(ValueError, match="full model certificates"):
        verify(tmp_path, replay_selected=True)


def test_native_replay_matches_worker_threads_and_restores_host(audit_case, monkeypatch):
    torch = pytest.importorskip("torch")
    import trustlessfl.fmnist as fmnist
    args, _, _ = audit_case
    root, case, p, _, _, history, rosters = args
    catalog_path = root / "catalog.json"
    catalog = json.loads(catalog_path.read_text())
    for node in catalog[case].values():
        node.update({"fmnist-shard": "unused", "fmnist-reference": "unused"})
    catalog_path.write_text(json.dumps(catalog))
    history[1] = {"body": {"model": [0.1] * p.dimension}}

    class Trainer:
        def __init__(self, *args, **kwargs):
            pass

        def __call__(self, *args):
            assert torch.get_num_threads() == 1
            return [0.1] * p.dimension

    monkeypatch.setattr(fmnist, "FmnistTrainer", Trainer)
    original = torch.get_num_threads()
    try:
        torch.set_num_threads(2)
        report = replay_selected_aggregate(root, case, p, history, rosters)
        assert report["cpu_intraop_threads"] == 1
        assert torch.get_num_threads() == 2
        history[1]["body"]["model"][0] += 0.01
        with pytest.raises(ValueError, match="quantized mean"):
            replay_selected_aggregate(root, case, p, history, rosters)
        assert torch.get_num_threads() == 2
    finally:
        torch.set_num_threads(original)
