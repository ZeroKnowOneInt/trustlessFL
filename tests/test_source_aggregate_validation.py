import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")

from trustlessfl.aion_source_asr import source_request
from trustlessfl.aion_source_aggregate import check_validations
from trustlessfl.aion_source_roster import statement
from trustlessfl.aion_source_server import AuthorASRWorkflow, provision_source
from trustlessfl.crypto import (ORDER, ProtocolError, aggregate_commitments, canonical, digest,
                               pedersen_reconstruct_pair, pedersen_split,
                               pedersen_verify_opening, sum_pedersen_shares)
from trustlessfl.local_grid import PooledProcessGrid


def source_root():
    root = Path(__file__).resolve().parents[2] / "Aion"
    if not (root / "agent/Aion/HPRF/matrix").is_file():
        pytest.skip("author source required")
    return root


def test_existing_shares_open_only_the_aggregate_commitment():
    first, a = pedersen_split(17, 2, 4)
    second, b = pedersen_split(29, 2, 4)
    combined = {i: sum_pedersen_shares([first[i], second[i]]) for i in (1, 3)}
    commitment = aggregate_commitments([a, b])
    key, blind = pedersen_reconstruct_pair(combined, commitment)
    assert key == 46 and pedersen_verify_opening((key, blind), commitment)
    assert not pedersen_verify_opening((key + 1, blind), commitment)
    assert not pedersen_verify_opening((key, (blind + 1) % ORDER), commitment)
    assert not pedersen_verify_opening((key, blind), a)
    assert not pedersen_verify_opening((key, True), commitment)
    with pytest.raises(ProtocolError, match="insufficient"):
        pedersen_reconstruct_pair({1: combined[1]}, commitment)
    damaged = {**combined, 3: ((combined[3][0] + 1) % ORDER, combined[3][1])}
    with pytest.raises(ProtocolError, match="invalid Pedersen"):
        pedersen_reconstruct_pair(damaged, commitment)


@pytest.fixture
def aggregate_case(tmp_path, make_source_commit):
    manifest_path, nodes = provision_source(tmp_path / "run", source_root(), clients=20,
        committee=4, committee_members=[0, 1, 2, 3], dimension=8, rounds=2, workload="synthetic",
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0, 8]))
    manifest = json.loads(manifest_path.read_text())
    states = {actor: {} for actor in range(21)}
    proof = make_source_commit(manifest, states)
    def call(actor, action, round_id=1, **kwargs):
        return source_request(nodes[actor + 1], states[actor],
                              dict(action=action, task=manifest["task"], round=round_id, **kwargs))
    previous = dict(round=0, model=[0.0] * 8, commit=proof(1, digest(dict(
        msg="VALID_CLIENTS", iteration=0, valid_clients=manifest["clients"]))))
    for actor in manifest["clients"]:
        for event in call(actor, "enroll")["outbox"]:
            call(event["recipient"], "deliver-share", body=event["body"])
    vectors = [call(actor, "mask", model=previous)["outbox"][0]["body"]
               for actor in manifest["clients"]]
    selected = call(20, "select", vectors=vectors)["selected"]
    authorizations = [call(actor, "authorize-selection", vectors=vectors, model=previous, members=selected)
                      for actor in manifest["committee"]]
    commit = proof(2, digest(statement(manifest, 1, selected)))
    shares = [dict(sender=actor, **call(actor, "sum-shares", members=selected, selection_commit=commit))
              for actor in manifest["committee"]]
    final = call(20, "reconstruct", shares=shares)
    return dict(manifest=manifest, nodes=nodes, states=states, proof=proof, call=call,
                previous=previous, vectors=vectors, selected=selected,
                authorizations=authorizations, final=final, path=manifest_path)


def validation_args(case):
    return dict(body=case["final"]["outbox"][0]["body"], opening=case["final"]["aggregate_opening"])


def test_model_bft_requires_own_numeric_replay_and_opening_not_exported(aggregate_case):
    c = aggregate_case
    body = validation_args(c)["body"]
    args = dict(sequence=3, registry=c["proof"](3, "unused")["registry"], value=digest(body))
    with pytest.raises(ProtocolError, match="requires local aggregate validation"):
        c["call"](0, "bft-prepare", **args)
    assert "3" not in c["states"][0]["source-bft"].get("values", {})
    response = c["call"](0, "validate-aggregate", **validation_args(c))
    assert response["verified"] and response["value"] == digest(body)
    assert c["call"](0, "validate-aggregate", **validation_args(c)) == response
    assert c["call"](0, "bft-prepare", **args)["response"]["value"] == digest(body)
    raw = json.dumps(response)
    assert '"key"' not in raw and '"blind"' not in raw and "opening" not in raw
    assert "aggregate_opening" not in body
    assert c["states"][0]["source-selection"]["pending"]["total"] == c["states"][20]["pending"]["total"]


@pytest.mark.parametrize("field", ["final_sum", "model", "next_linf", "mask_linf", "history_term",
                                   "modular_mask_linf", "bound", "selected_count", "filter_rule",
                                   "scale_source", "history_aggregate", "task", "iteration"])
def test_aggregator_cannot_forge_model_or_history_before_second_bft(aggregate_case, field):
    c = aggregate_case
    args = copy.deepcopy(validation_args(c))
    body = args["body"]
    if field in ("final_sum", "model"):
        body[field][0] += 0.01
    elif field in ("scale_source", "history_aggregate"):
        body["paper_numeric"][field] = "forged-units"
    elif field == "task":
        body[field] = "other-task"
    elif field == "iteration":
        body[field] = 2
    elif field == "selected_count":
        body["paper_numeric"][field] += 1
    else:
        body["paper_numeric"][field] = "999"
    with pytest.raises(ProtocolError, match="differs from local replay"):
        c["call"](0, "validate-aggregate", **args)
    assert "source-aggregate-validation" not in c["states"][0]
    assert c["call"](0, "validate-aggregate", **validation_args(c))["verified"]


@pytest.mark.parametrize("field,value", [("key", 0), ("key", True), ("blind", -1), ("blind", ORDER)])
def test_invalid_aggregate_opening_rejected(aggregate_case, field, value):
    c = aggregate_case
    args = copy.deepcopy(validation_args(c))
    args["opening"][field] = value
    with pytest.raises(ProtocolError, match="opening"):
        c["call"](0, "validate-aggregate", **args)
    assert "source-aggregate-validation" not in c["states"][0]


def test_wrong_opening_pinned_commitment_and_conflicting_retry_rejected(aggregate_case):
    c = aggregate_case
    args = copy.deepcopy(validation_args(c))
    args["opening"]["key"] += 1
    with pytest.raises(ProtocolError, match="pinned selected commitments"):
        c["call"](0, "validate-aggregate", **args)
    c["call"](0, "validate-aggregate", **validation_args(c))
    with pytest.raises(ProtocolError, match="conflicting"):
        c["call"](0, "validate-aggregate", **args)


def test_no_unapproved_release_or_plaintext_payload_accepted(aggregate_case):
    c = aggregate_case
    with pytest.raises(ProtocolError, match="schema"):
        c["call"](0, "validate-aggregate", **validation_args(c), plaintext_updates=[[0]])
    del c["states"][0]["source-key-releases"]
    with pytest.raises(ProtocolError, match="locally authorized key release"):
        c["call"](0, "validate-aggregate", **validation_args(c))
    assert "source-aggregate-validation" not in c["states"][0]


def test_signed_aggregate_receipts_bound_to_selection_body_and_parent(aggregate_case):
    c = aggregate_case
    receipts = [c["call"](actor, "validate-aggregate", **validation_args(c))["authorization"]
                for actor in c["manifest"]["committee"]]
    parent = digest(c["previous"]["model"])
    tag = digest(c["vectors"])
    args = (c["manifest"], receipts, 1, c["selected"], validation_args(c)["body"])
    check_validations(*args, parent=parent, vectors_digest=tag)
    for changed in (dict(parent="wrong"), dict(vectors_digest="wrong")):
        with pytest.raises(ProtocolError, match="context mismatch"):
            check_validations(*args, **{**dict(parent=parent, vectors_digest=tag), **changed})
    with pytest.raises(ProtocolError, match="incomplete"):
        check_validations(c["manifest"], receipts[:-1], 1, c["selected"], args[-1], parent=parent)
    with pytest.raises(ProtocolError, match="context mismatch"):
        check_validations(c["manifest"], [receipts[0]] * 4, 1, c["selected"], args[-1], parent=parent)
    changed = copy.deepcopy(receipts)
    changed[0]["body"]["value"] = "forged-model"
    with pytest.raises(ProtocolError, match="signature"):
        check_validations(c["manifest"], changed, 1, c["selected"], args[-1], parent=parent)


def test_second_round_only_uses_locally_replayed_first_round_history(aggregate_case):
    c = aggregate_case
    body = validation_args(c)["body"]
    for actor in c["manifest"]["committee"]:
        c["call"](actor, "validate-aggregate", **validation_args(c))
    previous = dict(round=1, model=body["model"], body=body, commit=c["proof"](3, digest(body)))
    vectors = [c["call"](actor, "mask", 2, model=previous)["outbox"][0]["body"]
               for actor in c["manifest"]["clients"]]
    selected = c["call"](20, "select", 2, vectors=vectors)["selected"]
    changed = copy.deepcopy(previous)
    changed["body"]["paper_numeric"]["history_term"] = "999"
    changed["commit"] = c["proof"](3, digest(changed["body"]))
    with pytest.raises(ProtocolError, match="requires local aggregate validation"):
        c["call"](0, "authorize-selection", 2, model=changed, vectors=vectors, members=selected)
    reply = c["call"](0, "authorize-selection", 2, model=previous, vectors=vectors, members=selected)
    assert reply["selected"] == selected
    assert c["states"][0]["source-selection"]["paper_terms"] == [body["paper_numeric"]["history_term"]]
    # Flower persists Context as canonical JSON between requests. The parsed
    # Fraction must not be left in the snapshot after round-two authorization.
    assert isinstance(c["states"][0]["source-selection"]["previous_linf"], str)
    canonical(c["states"][0])


def test_ambiguous_numeric_replay_never_authorizes_model_vote(aggregate_case):
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.paper_dmc import QuantizedLiftError
    from trustlessfl.source_paper_numeric import paper_codec, mask_integer_wire
    c = aggregate_case
    # Unit fixture only: change the public bootstrap to a commensurate period
    # and build a trusted local snapshot from zero-update fixture masks. No
    # runtime algorithm reads individual keys to perform this replay.
    c["manifest"]["paper_numerics"]["initial_linf"] = "0.1"
    c["path"].write_text(json.dumps(c["manifest"]))
    hprf = OriginalAionHPRF.from_directory(Path(c["manifest"]["source-root"]) / "agent/Aion/HPRF")
    codec = paper_codec(c["manifest"], hprf, 1)
    masks = [mask_integer_wire(codec, [0] * 8, hprf.hprf(c["states"][i]["mask_seed"], 1, 8))
             for i in c["selected"]]
    selection = c["states"][0]["source-selection"]
    selection["pending"]["total"] = [sum(v[j] for v in masks) for j in range(8)]
    with pytest.raises(QuantizedLiftError) as exc:
        c["call"](0, "validate-aggregate", **validation_args(c))
    assert exc.value.code == "ambiguous"
    assert "source-aggregate-validation" not in c["states"][0]
    args = dict(sequence=3, registry=c["proof"](3, "unused")["registry"],
                value=digest(validation_args(c)["body"]))
    with pytest.raises(ProtocolError, match="requires local aggregate validation"):
        c["call"](0, "bft-prepare", **args)
    assert "3" not in c["states"][0]["source-bft"].get("values", {})


@pytest.mark.parametrize("profile", [None, {}, {"kind": "unknown"}])
def test_unknown_profile_does_not_silently_downgrade(aggregate_case, profile):
    c = aggregate_case
    c["manifest"]["aggregation_validation"] = profile
    c["path"].write_text(json.dumps(c["manifest"]))
    before = copy.deepcopy(c["states"][0])
    with pytest.raises(ProtocolError, match="unsupported source aggregation"):
        c["call"](0, "validate-aggregate", **validation_args(c))
    assert c["states"][0] == before


@pytest.mark.parametrize("official", [False, True])
@pytest.mark.parametrize("code", ["history-unverified", "model-unverified", "selection-mismatch"])
def test_validation_failures_export_only_closed_public_codes(monkeypatch, official, code):
    from flwr.app import Context, Message, RecordDict
    from trustlessfl.aion_source_aggregate import AggregateValidationError
    from trustlessfl.client_app import handle_source_asr, records
    from trustlessfl.aion_source_official import handle
    def fail(*args):
        raise AggregateValidationError(code, "private-key-blinder-and-coordinate-value")
    if official:
        monkeypatch.setattr("trustlessfl.aion_source_official.actor_config", lambda _: {})
        monkeypatch.setattr("trustlessfl.aion_source_official.flower_source_request", fail)
    else:
        monkeypatch.setattr("trustlessfl.aion_source_asr.flower_source_request", fail)
    ctx = Context(run_id=1, node_id=1, node_config={}, state=RecordDict(), run_config={})
    msg = Message(records(dict(action="validate-aggregate")), dst_node_id=1,
                  message_type="query.aion_source_asr")
    reply = (handle if official else handle_source_asr)(msg, ctx)
    assert reply.has_error()
    assert reply.error.reason == "Author ASR aggregate validation failure: " + code
    assert "private-key" not in reply.error.reason


@pytest.mark.parametrize("legacy", [False, True])
def test_flower_replay_order_and_offline_receipts_without_new_shares(tmp_path, monkeypatch, legacy):
    from experiments.verify_source_learning import verify_learning
    path, nodes = provision_source(tmp_path / "run", source_root(), clients=20, committee=4,
        dimension=8, rounds=1, workload="synthetic",
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0, 8]))
    manifest = json.loads(path.read_text())
    if legacy:
        del manifest["aggregation_validation"]
        path.write_text(json.dumps(manifest))
    actions = []
    original = AuthorASRWorkflow.call
    def observe(self, grid, actors, action, *args, **kwargs):
        actions.append((action, kwargs.get("sequence")))
        return original(self, grid, actors, action, *args, **kwargs)
    monkeypatch.setattr(AuthorASRWorkflow, "call", observe)
    with PooledProcessGrid(nodes, 4) as grid:
        result = AuthorASRWorkflow(manifest).run(grid)
    assert result["key_share_deliveries"] == 80 and result["mask_share_deliveries"] == 0
    assert result["aggregate_validated_rounds"] == (0 if legacy else 1)
    if not legacy:
        assert actions.index(("reconstruct", None)) < actions.index(("validate-aggregate", None))
        assert actions.index(("validate-aggregate", None)) < actions.index(("bft-prepare", 3))
        assert len(result["history"][0]["aggregate_validations"]) == 4
    raw = json.dumps(result)
    assert "aggregate_opening" not in raw and '"blind"' not in raw
    (path.parent / "results.json").write_text(raw)
    assert verify_learning(path.parent)["model_max_abs_error"] == 0
    if not legacy:
        result["history"][0]["aggregate_validations"] = []
        (path.parent / "results.json").write_text(json.dumps(result))
        with pytest.raises(ProtocolError, match="incomplete source aggregate"):
            verify_learning(path.parent)


def test_flower_seven_member_asr_discards_two_bad_received_shares(tmp_path, monkeypatch):
    from experiments.verify_source_learning import verify_learning
    path, nodes = provision_source(tmp_path / "run", source_root(), clients=20, committee=7,
        dimension=8, rounds=1, workload="synthetic",
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0, 8]))
    manifest = json.loads(path.read_text())
    assert manifest["sharing_profile"]["threshold"] == 3
    original = AuthorASRWorkflow.call
    damaged_counts = []
    def inject(self, grid, actors, action, *args, **kwargs):
        replies = original(self, grid, actors, action, *args, **kwargs)
        if action == "sum-shares":
            replies = copy.deepcopy(replies)
            for response in replies[:2]:
                response["sealed_sum"]["signature"] = "00" * 64
            damaged_counts.append(2)
        return replies
    monkeypatch.setattr(AuthorASRWorkflow, "call", inject)
    with PooledProcessGrid(nodes, 4) as grid:
        result = AuthorASRWorkflow(manifest).run(grid)
    assert damaged_counts == [2]
    assert result["key_share_deliveries"] == 140
    assert result["mask_share_deliveries"] == 0
    assert result["aggregate_validated_rounds"] == 1
    assert len(result["history"][0]["aggregate_validations"]) == 7
    (path.parent / "results.json").write_text(json.dumps(result))
    verified = verify_learning(path.parent)
    assert verified["model_max_abs_error"] == 0
    assert verified["key_reconstruction_threshold"] == 3
