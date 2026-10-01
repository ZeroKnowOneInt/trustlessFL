import copy
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")

from Cryptodome.PublicKey import ECC
from trustlessfl.aion_source_asr import load_source, source_request
from trustlessfl.aion_source_bft import _module
from trustlessfl.aion_source_inbox import inbox_root
from trustlessfl.aion_source_selection import check_authorizations, sign_vector
from trustlessfl.aion_source_server import provision_source
from trustlessfl.aion_source_sharing import identity_for
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.source_paper_numeric import descriptor, paper_codec, select_masked


@pytest.fixture
def case(tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/HPRF/matrix").exists():
        pytest.skip("author source required")
    path, nodes = provision_source(tmp_path / "run", source, clients=20, committee=4,
        committee_members=[0, 1, 2, 3], dimension=4, rounds=4, workload="synthetic",
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0, 4]))
    manifest = json.loads(path.read_text())
    states = {actor: {} for actor in range(21)}
    module = _module(manifest["source-root"])
    keys = {actor: ECC.generate(curve="P-256") for actor in manifest["committee"]}
    registry = {str(actor): key.public_key().export_key(format="PEM") for actor, key in keys.items()}
    for actor in keys:
        states[actor]["source-bft"] = dict(registry=registry)
    hprf = load_source(manifest["source-root"], json.dumps(manifest["source-sha256"], sort_keys=True))[3]

    def proof(sequence, value):
        commits = []
        for actor, key in keys.items():
            message = module.BFTMessage(type="commit", value=value, phase=module.BFTPhase.COMMIT,
                                        node_id=actor, sequence=sequence)
            message.signature = module.BFTProtocol._sign_message(SimpleNamespace(private_key=key), message)
            commits.append({**asdict(message), "phase": message.phase.value})
        return dict(registry=registry, sequence=sequence, value=value, commits=commits)

    model = [0.0] * 4
    previous = dict(round=0, model=model, commit=proof(1, digest(dict(msg="VALID_CLIENTS",
                    iteration=0, valid_clients=manifest["clients"]))))

    def vectors(round_id=1, linf=None):
        codec = paper_codec(manifest, hprf, round_id, linf)
        return [sign_vector(manifest, identity_for(nodes[actor + 1], manifest),
            dict(msg="VECTOR", iteration=round_id, sender=actor, masked_vector=[actor * 1000] * 4,
                 parent=digest(model), paper_scale=descriptor(codec))) for actor in manifest["clients"]]

    def call(actor, action, round_id=1, **kwargs):
        return source_request(nodes[actor + 1], states[actor],
            dict(action=action, task=manifest["task"], round=round_id, **kwargs))

    return manifest, nodes, states, call, previous, vectors, proof, hprf


def test_committee_replays_filter_before_only_selected_key_sum_release(case):
    manifest, _, states, call, previous, make_vectors, _, _ = case
    for sender in (0, 1, 14, 15):
        for event in call(sender, "enroll")["outbox"]:
            call(event["recipient"], "deliver-share", body=event["body"])
    with pytest.raises(ProtocolError, match="requires masked MGF authorization"):
        call(0, "sum-shares", members=[14, 15])
    vectors = make_vectors()
    with pytest.raises(ProtocolError, match="differs from masked MGF selection"):
        call(0, "authorize-selection", vectors=vectors, model=previous, members=[14, 15])
    assert "source-selection" not in states[0]
    reply = call(0, "authorize-selection", vectors=vectors, model=previous, members=[0, 1])
    assert reply["selected"] == [0, 1]
    assert call(0, "authorize-selection", vectors=vectors, model=previous, members=[0, 1]) == reply
    sealed = call(0, "sum-shares", members=[0, 1])
    assert sealed["sealed_sum"]["members"] == [0, 1]
    with pytest.raises(ProtocolError, match="requires masked MGF authorization"):
        call(0, "sum-shares", members=[14, 15])
    assert states[0]["source-key-releases"] == {"1": digest([0, 1])}
    assert manifest["selection_authorization"]["evidence"].startswith("client-signed")


@pytest.mark.parametrize("change", ["coordinate", "signature", "task", "parent", "scale", "sender", "plaintext"])
def test_relay_cannot_modify_vectors_to_authorize_another_cohort(case, change):
    _, _, states, call, previous, make_vectors, _, _ = case
    vectors = make_vectors()
    if change == "coordinate":
        vectors[0]["masked_vector"][0] += 1
    elif change == "signature":
        vectors[0]["signature"] = "00" * 64
    elif change == "task":
        vectors[0]["task"] = "another-task"
    elif change == "parent":
        vectors[0]["parent"] = "wrong-parent"
    elif change == "scale":
        vectors[0]["paper_scale"]["coefficient"] = "1"
    elif change == "sender":
        vectors[0]["sender"] = vectors[1]["sender"]
    else:
        vectors[0]["plaintext"] = [0] * 4
    with pytest.raises(ProtocolError):
        call(0, "authorize-selection", vectors=vectors, model=previous, members=[0, 1])
    assert "source-selection" not in states[0]
    assert "source-key-releases" not in states[0]
    with pytest.raises(ProtocolError):
        call(20, "select", vectors=vectors)
    assert "pending" not in states[20]


def test_committee_requires_valid_committed_parent_and_local_registry(case):
    _, _, states, call, previous, make_vectors, _, _ = case
    vectors = make_vectors()
    changed = copy.deepcopy(previous)
    changed["commit"]["commits"] = changed["commit"]["commits"][:2]
    with pytest.raises(ProtocolError, match="quorum"):
        call(0, "authorize-selection", vectors=vectors, model=changed, members=[0, 1])
    del states[0]["source-bft"]
    with pytest.raises(ProtocolError, match="locally pinned"):
        call(0, "authorize-selection", vectors=vectors, model=previous, members=[0, 1])
    assert "source-selection" not in states[0]


def test_staged_committee_vectors_are_node_local_and_order_independent(case):
    manifest, nodes, _, call, previous, make_vectors, _, _ = case
    vectors = list(reversed(make_vectors()))
    refs = []
    for vector in vectors:
        refs.extend(call(0, "stage-vectors", vectors=[vector])["vector_refs"])
    reply = call(0, "authorize-selection", vector_refs=refs, model=previous, members=[0, 1])
    aggregator = call(20, "select", vectors=vectors)
    assert reply["selected"] == aggregator["selected"] == [0, 1]
    assert reply["bound"] == aggregator["bound"]
    assert inbox_root(nodes[1], manifest, 1) != inbox_root(nodes[21], manifest, 1)


def test_tied_norms_cannot_be_steered_by_relay_arrival_order(case):
    manifest, nodes, _, call, previous, make_vectors, _, _ = case
    vectors = make_vectors()
    for actor in range(4):
        unsigned = {k: v for k, v in vectors[actor].items() if k not in ("task", "signature")}
        unsigned["masked_vector"] = [0] * 4
        vectors[actor] = sign_vector(manifest, identity_for(nodes[actor + 1], manifest), unsigned)
    vectors.reverse()
    reply = call(0, "authorize-selection", vectors=vectors, model=previous, members=[0, 1])
    assert reply["selected"] == call(20, "select", vectors=vectors)["selected"] == [0, 1]


def test_fourth_round_replay_uses_two_committed_historical_terms(case):
    manifest, _, states, call, previous, make_vectors, proof, hprf = case
    terms = []
    for round_id in range(1, 5):
        linf = None if round_id == 1 else "0.012347"
        vectors = make_vectors(round_id, linf)
        codec = paper_codec(manifest, hprf, round_id, linf)
        history = {} if round_id <= 3 else dict(paper_terms=terms[-2:], paper_bound="1/1000")
        pending = select_masked(manifest, history, codec, vectors, round_id)
        reply = call(0, "authorize-selection", round_id, vectors=vectors, model=previous,
                     members=pending["selected"])
        assert reply["bound"] == pending["bound"]
        term = str(round_id + 1)
        terms.append(term)
        body = dict(msg="FINAL_SUM", iteration=round_id, task=manifest["task"], model=previous["model"],
                    paper_numeric=dict(next_linf="0.012347", bound="1/1000", history_term=term))
        previous = dict(round=round_id, model=body["model"], body=body,
                        commit=proof(2 * round_id + 1, digest(body)))
    assert states[0]["source-selection"]["paper_terms"] == ["3", "4"]


def test_replay_receipts_bind_committee_round_members_parent_and_vectors(case):
    manifest, _, _, call, previous, make_vectors, _, _ = case
    vectors = make_vectors()
    replies = [call(actor, "authorize-selection", vectors=vectors, model=previous, members=[0, 1])
               for actor in manifest["committee"]]
    receipts = [reply["authorization"] for reply in replies]
    args = (manifest, receipts, 1, [0, 1], replies[0]["bound"])
    check_authorizations(*args, parent=digest(previous["model"]), vectors_digest=digest(vectors))
    for round_id, members, bound, parent, vector_tag in (
            (2, [0, 1], replies[0]["bound"], digest(previous["model"]), digest(vectors)),
            (1, [14, 15], replies[0]["bound"], digest(previous["model"]), digest(vectors)),
            (1, [0, 1], 9.0, digest(previous["model"]), digest(vectors)),
            (1, [0, 1], replies[0]["bound"], "wrong-parent", digest(vectors)),
            (1, [0, 1], replies[0]["bound"], digest(previous["model"]), "wrong-vectors")):
        with pytest.raises(ProtocolError, match="context mismatch"):
            check_authorizations(manifest, receipts, round_id, members, bound,
                                 parent=parent, vectors_digest=vector_tag)
    with pytest.raises(ProtocolError, match="incomplete"):
        check_authorizations(manifest, receipts[:3], 1, [0, 1], replies[0]["bound"])
    with pytest.raises(ProtocolError, match="context mismatch"):
        check_authorizations(manifest, [receipts[0]] * 4, 1, [0, 1], replies[0]["bound"])
    changed = copy.deepcopy(receipts)
    changed[0]["body"]["selected"] = [14, 15]
    with pytest.raises(ProtocolError, match="signature"):
        check_authorizations(manifest, changed, 1, [14, 15], replies[0]["bound"])
