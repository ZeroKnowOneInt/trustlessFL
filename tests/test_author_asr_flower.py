"""Author-source computations are unchanged across Flower serialization."""

import json
import logging
from pathlib import Path
from types import MethodType, SimpleNamespace

import numpy as np
import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")
pytest.importorskip("dill")

from Cryptodome.PublicKey import ECC
from trustlessfl.aion_source_asr import load_source, source_request, source_committee
from trustlessfl.aion_source_bft import _module, check_source_commit
from trustlessfl.aion_source_server import AuthorASRWorkflow, provision_source
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.local_grid import ProcessGrid


@pytest.fixture
def source_case(tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/SA_ClientAgent.py").exists():
        pytest.skip("author source required")
    path, nodes = provision_source(tmp_path / "run", source, clients=10, committee=4,
                                   dimension=8, rounds=20, committee_members=[0, 1, 2, 3])
    return json.loads(path.read_text()), nodes, path


def test_default_committee_uses_author_chacha20(source_case, tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    path, _ = provision_source(tmp_path / "selected", source)
    manifest = json.loads(path.read_text())
    assert manifest["committee_selection"] == "author-chacha20"
    assert manifest["committee"] == source_committee(manifest["source-root"],
        bytes.fromhex(manifest["committee_seed"]), 4, 10)


def test_source_one_time_sharing_and_idempotent_retry(source_case):
    manifest, nodes, _ = source_case
    state = {}
    request = dict(action="mask", task=manifest["task"], round=1)
    first = source_request(nodes[1], state, request)
    assert source_request(nodes[1], state, request) == first
    assert sum(e["body"]["msg"] == "SHARED_MASK" for e in first["outbox"]) == 4
    key = state["mask_seed"]
    second = source_request(nodes[1], state, {**request, "round": 2})
    assert state["mask_seed"] == key
    assert [e["body"]["msg"] for e in second["outbox"]] == ["VECTOR"]
    assert not any("mask_packets" in e["body"] for e in first["outbox"] + second["outbox"])
    with pytest.raises(ProtocolError, match="conflicting author retry"):
        source_request(nodes[1], state, {**request, "unexpected": True})


def test_source_hash_mismatch_is_rejected(source_case):
    manifest, nodes, path = source_case
    manifest["source-sha256"]["agent/Aion/SA_ClientAgent.py"] = "0" * 64
    path.write_text(json.dumps(manifest))
    with pytest.raises(ProtocolError, match="hash mismatch"):
        source_request(nodes[1], {}, dict(action="mask", task=manifest["task"], round=1))


def test_source_share_recipient_binding_and_no_reenrollment(source_case):
    manifest, nodes, _ = source_case
    first = source_request(nodes[1], {}, dict(action="mask", task=manifest["task"], round=1))
    event = next(e for e in first["outbox"] if e["body"]["msg"] == "SHARED_MASK")
    request = dict(action="deliver-share", task=manifest["task"], round=1, body=event["body"])
    with pytest.raises(ProtocolError, match="recipient"):
        source_request(nodes[2], {}, request)
    with pytest.raises(ProtocolError, match="one-time"):
        source_request(nodes[1], {}, {**request, "round": 2})


@pytest.mark.parametrize("rounds", [4, 20])
def test_source_flower_rounds_match_direct_author_computations(source_case, rounds):
    manifest, nodes, _ = source_case
    manifest["rounds"] = rounds
    path = Path(nodes[1]["aion-source-manifest"])
    path.write_text(json.dumps(manifest))
    _, aggregator, VSS, _ = load_source(manifest["source-root"],
        json.dumps(manifest["source-sha256"], sort_keys=True))
    reference = SimpleNamespace(vector_len=manifest["dimension"], num_clients=10,
        prime=manifest["prime"], vss=VSS(prime=manifest["prime"]),
        user_committee=manifest["committee"], committee_threshold=2,
        l2_old=[], linf_old=0.1, linf_HPRF_old=0.05, b_old=0.2,
        agent_print=lambda *_: None,
        timings={"Aggregate share reconstruction": [], "Model aggregation": []},
        _bft_broadcast_with_consensus=lambda *_: ({}, 0))
    reference.MMF = MethodType(aggregator.MMF, reference)
    checks = []

    def compare(r, vectors, shares, selection, final):
        reference.current_iteration = r
        reference.user_masked_vectors = {
            v["sender"]: np.asarray(v["masked_vector"], dtype=np.float64) for v in vectors}
        aggregator.report_process(reference)
        assert selection["selected"] == reference.selected_indices
        assert selection["bound"] == reference.b_old
        reference.committee_shares_sum = {e["sender"]: e["sum_shares"] for e in shares}
        aggregator.reconstruction_process(reference)
        np.testing.assert_array_equal(final["result"], reference.final_sum)
        checks.append(r)

    with ProcessGrid(nodes) as grid:
        result = AuthorASRWorkflow(manifest, on_round=compare).run(grid)
    assert checks == list(range(1, rounds + 1))
    assert result["key_share_deliveries"] == 40
    assert result["mask_share_deliveries"] == 0
    assert result["source_bft_completed_events"] == rounds
    assert result["source_bft_committed"] is True
    assert result["legal_bft"]["sequence"] == 1
    module = _module(manifest["source-root"])
    checker = SimpleNamespace(logger=logging.getLogger("author-test"))
    for entry in result["history"]:
        proof, = entry["source_bft"]
        assert entry["online_bft"]["sequence"] == 2 * entry["round"]
        assert proof["sequence"] == 2 * entry["round"] + 1
        assert proof["value"] == digest(dict(msg="FINAL_SUM", iteration=entry["round"],
                                             final_sum=entry["result"]))
        assert len({m["node_id"] for m in proof["commits"]}) == 4
        for body in proof["commits"]:
            message = module.BFTMessage(**{**body, "phase": module.BFTPhase(body["phase"])})
            assert module.BFTProtocol._verify_signature(checker, message,
                ECC.import_key(proof["registry"][str(message.node_id)]))
    proof = result["history"][-1]["source_bft"][0]
    with pytest.raises(ProtocolError, match="quorum"):
        check_source_commit(manifest, {**proof, "commits": proof["commits"][:2]},
                            proof["registry"], proof["sequence"], proof["value"])
    with pytest.raises(ProtocolError, match="voter or phase"):
        check_source_commit(manifest, {**proof, "commits": [proof["commits"][0]] * 4},
                            proof["registry"], proof["sequence"], proof["value"])


def test_source_bft_does_not_count_duplicate_prepare_deliveries(source_case):
    manifest, nodes, _ = source_case
    states = {actor: {} for actor in manifest["committee"]}

    def call(actor, action, **kwargs):
        return source_request(nodes[actor + 1], states[actor],
            dict(action=action, task=manifest["task"], round=1, **kwargs))

    registry = {str(actor): call(actor, "bft-hello")["public"] for actor in states}
    value = digest("public test value")
    prepares = {actor: call(actor, "bft-prepare", registry=registry, value=value)["response"]
                for actor in states}
    for _ in range(5):
        reply = call(1, "bft-deliver", registry=registry, value=value, message=prepares[0])
        assert reply["response"] is None and reply["decided"] is False
    tampered = {**prepares[0], "value": digest("changed value")}
    with pytest.raises(ProtocolError, match="signature or context"):
        call(1, "bft-deliver", registry=registry, value=value, message=tampered)
    reply = call(1, "bft-deliver", registry=registry, value=value, message=prepares[2])
    assert reply["response"] is None
    reply = call(1, "bft-deliver", registry=registry, value=value, message=prepares[3])
    assert reply["response"]["type"] == "precommit"  # Three distinct senders.


def test_existing_serverapp_can_dispatch_source_port(source_case):
    from flwr.app import Context, RecordDict
    from trustlessfl.server_app import app
    manifest, nodes, path = source_case
    manifest["rounds"] = 1
    path.write_text(json.dumps(manifest))
    context = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(),
                      run_config={"aion-source-manifest": str(path)})
    with ProcessGrid(nodes) as grid:
        app(grid, context)
    result = json.loads(context.state["aion-source-result"]["result"])
    assert result["source_bft_committed"] is True
    assert result["key_share_deliveries"] == 40
    assert len(result["history"]) == 1


def test_float64_source_mask_erases_small_learning_update():
    large_mask = np.float64(14760426300877770769 // 2)
    assert large_mask + 0.001 == large_mask


@pytest.mark.parametrize("rounds", [4, 20])
def test_source_learning_preserves_quantized_selected_mean(source_case, rounds):
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.numeric import FixedPoint
    from trustlessfl.task import local_delta
    manifest, nodes, path = source_case
    manifest.update(workload="synthetic", rounds=rounds, learning_rate=0.1)
    path.write_text(json.dumps(manifest))
    codec = FixedPoint(manifest["decimals"], manifest["max_abs"], 10,
        mask_backend="aion-original", original_hprf_setup=OriginalAionHPRF.from_directory(
            Path(manifest["source-root"]) / "agent/Aion/HPRF").public_setup())
    previous = np.zeros(manifest["dimension"])
    checks = []

    def compare(r, vectors, shares, selection, final):
        nonlocal previous
        assert all(all(type(x) is int for x in v["masked_vector"]) for v in vectors)
        assert all(set(v) == {"msg", "iteration", "sender", "masked_vector", "parent"} for v in vectors)
        members = selection["selected"]
        total = np.sum([codec.encode(local_delta(previous, i, 0.1)) for i in members], axis=0)
        mean = total / (len(members) * codec.scale)
        np.testing.assert_allclose(final["result"], mean, rtol=0, atol=1e-12)
        previous = previous + mean
        np.testing.assert_allclose(final["model"], previous, rtol=0, atol=1e-12)
        checks.append(r)

    with ProcessGrid(nodes) as grid:
        result = AuthorASRWorkflow(manifest, on_round=compare).run(grid)
    assert checks == list(range(1, rounds + 1))
    assert result["key_share_deliveries"] == 40 and result["mask_share_deliveries"] == 0
    assert len(result["history"][-1]["model"]) == manifest["dimension"]
    from experiments.verify_source_learning import verify_learning
    (path.parent / "results.json").write_text(json.dumps(result))
    verification = verify_learning(path.parent)
    assert verification["model_max_abs_error"] == 0
    assert verification["replayed_training_calls"] == sum(len(e["selected"]) for e in result["history"])
    genesis = dict(round=0, model=[0.0] * manifest["dimension"], commit=result["legal_bft"])
    tampered = {**genesis, "model": [0.001] * manifest["dimension"]}
    with pytest.raises(ProtocolError, match="genesis"):
        source_request(nodes[1], {}, dict(action="mask", task=manifest["task"], round=1, model=tampered))
