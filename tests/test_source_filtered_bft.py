"""The first BFT commits filter survivors BEFORE releasing aggregate-key shares."""

import copy
import json
from pathlib import Path

import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")
pytest.importorskip("dill")

from trustlessfl.aion_source_asr import source_request
from trustlessfl.aion_source_roster import MODE, enabled, statement
from trustlessfl.aion_source_server import AuthorASRWorkflow, provision_source
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.local_grid import PooledProcessGrid


@pytest.fixture
def case(tmp_path, make_source_commit):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/HPRF/matrix").exists():
        pytest.skip("author source required")
    path, nodes = provision_source(tmp_path / "run", source, clients=10, committee=4,
        committee_members=[0, 1, 2, 3], rounds=3, workload="synthetic")
    manifest = json.loads(path.read_text())
    states = {actor: {} for actor in range(11)}
    proof = make_source_commit(manifest, states)

    def call(actor, action, round_id=1, **kwargs):
        return source_request(nodes[actor + 1], states[actor],
            dict(action=action, task=manifest["task"], round=round_id, **kwargs))
    for sender in (4, 5, 6):
        for event in call(sender, "enroll")["outbox"]:
            call(event["recipient"], "deliver-share", body=event["body"])
    return manifest, states, call, proof, path, nodes


def test_key_release_requires_actual_filtered_commit(case):
    manifest, states, call, proof, _, _ = case
    assert enabled(manifest) and manifest["selection_consensus"]["kind"] == MODE
    for malformed in (None, [], {}):
        with pytest.raises(ProtocolError):
            call(0, "sum-shares", members=[4, 5], selection_commit=malformed)
        assert "source-key-releases" not in states[0]
    commit = proof(2, digest(statement(manifest, 1, [4, 5])))
    reply = call(0, "sum-shares", members=[4, 5], selection_commit=commit)
    assert reply["sealed_sum"]["members"] == [4, 5]
    assert states[0]["source-key-releases"] == {"1": digest([4, 5])}
    assert call(0, "sum-shares", members=[4, 5], selection_commit=commit)["sealed_sum"]["members"] == [4, 5]


@pytest.mark.parametrize("change", ["members", "received-set", "task", "round", "phase",
                                    "quorum", "duplicate", "signature", "registry"])
def test_changed_or_uncommitted_roster_cannot_release_keys(case, change):
    manifest, states, call, proof, _, _ = case
    body = statement(manifest, 1, [4, 5])
    if change == "members":
        body = statement(manifest, 1, [4, 6])
    elif change == "received-set":
        body = dict(msg="ONLINE_CLIENTS", iteration=1, online_clients=[1] * 10)
    elif change == "task":
        body["task"] = "another-task"
    sequence = 4 if change == "round" else 2
    commit = proof(sequence, digest(body))
    if change == "phase":
        commit = proof(3, digest(body))  # Model BFT is not roster BFT.
    elif change == "quorum":
        commit["commits"] = commit["commits"][:2]
    elif change == "duplicate":
        commit["commits"] = [commit["commits"][0]] * 4
    elif change == "signature":
        commit["commits"][0]["signature"] = "00" * 64
    elif change == "registry":
        commit["registry"] = {}
    with pytest.raises(ProtocolError):
        call(0, "sum-shares", members=[4, 5], selection_commit=commit)
    assert "source-key-releases" not in states[0]


def test_filtered_proposal_hash_must_bind_members_before_voting(case):
    manifest, states, call, proof, _, _ = case
    registry = proof(2, "unused")["registry"]
    with pytest.raises(ProtocolError, match="proposal differs"):
        call(0, "bft-prepare", sequence=2, registry=registry,
             value=digest(statement(manifest, 1, [4, 6])), selection_members=[4, 5])
    assert "2" not in states[0]["source-bft"].get("values", {})
    with pytest.raises(ProtocolError, match="sequence differs"):
        call(0, "bft-prepare", sequence=4, registry=registry,
             value=digest(statement(manifest, 1, [4, 5])), selection_members=[4, 5])
    reply = call(0, "bft-prepare", sequence=2, registry=registry,
                 value=digest(statement(manifest, 1, [4, 5])), selection_members=[4, 5])
    assert reply["response"]["type"] == "prepare"


@pytest.mark.parametrize("members", [[], [4, 4], [True, 5], [4, 10], "4,5"])
def test_invalid_roster_is_rejected(case, members):
    manifest = case[0]
    with pytest.raises(ProtocolError, match="filtered BFT members"):
        statement(manifest, 1, members)


def test_unknown_profile_is_not_silently_downgraded(case):
    manifest = case[0]
    for profile in (None, {}, dict(kind="unrecognized")):
        changed = {**manifest, "selection_consensus": profile}
        with pytest.raises(ProtocolError, match="consensus profile"):
            enabled(changed)


@pytest.mark.parametrize("legacy", [False, True])
def test_flower_order_and_verifier_bind_selected_not_received_clients(case, legacy):
    manifest, _, _, _, path, nodes = case
    if legacy:
        manifest.pop("selection_consensus")
        path.write_text(json.dumps(manifest))
    trace = []
    class RecordingWorkflow(AuthorASRWorkflow):
        def call(self, grid, actors, action, round_id=None, **kwargs):
            trace.append((action, round_id))
            if action == "sum-shares":
                assert ("selection_commit" in kwargs) is not legacy
            return super().call(grid, actors, action, round_id, **kwargs)

        def consensus(self, grid, round_id, value, registry, **kwargs):
            trace.append(("consensus", kwargs["sequence"]))
            return super().consensus(grid, round_id, value, registry, **kwargs)

    with PooledProcessGrid(nodes, 4) as grid:
        result = RecordingWorkflow(manifest).run(grid)
    for entry in result["history"]:
        r, selected = entry["round"], entry["selected"]
        assert len(selected) < len(manifest["clients"])
        select_index, bft_index = trace.index(("select", r)), trace.index(("consensus", 2 * r))
        if legacy:
            assert bft_index < select_index
            body = dict(msg="ONLINE_CLIENTS", iteration=r, online_clients=[1] * 10)
        else:
            assert select_index < bft_index
            body = statement(manifest, r, selected)
        assert bft_index < trace.index(("sum-shares", r)) < trace.index(("reconstruct", r))
        assert trace.index(("reconstruct", r)) < trace.index(("consensus", 2 * r + 1))
        assert entry["online_bft"]["value"] == digest(body)
    from experiments.verify_source_learning import verify_learning
    (path.parent / "results.json").write_text(json.dumps(result))
    verified = verify_learning(path.parent)
    assert verified["model_max_abs_error"] == 0 and result["mask_share_deliveries"] == 0
    assert verified["first_bft_subject"] == (
        "historical-received-client-set" if legacy else "post-filter-client-set")
    if not legacy:
        tampered = copy.deepcopy(result)
        tampered["history"][0]["online_bft"]["value"] = digest(
            dict(msg="ONLINE_CLIENTS", iteration=1, online_clients=[1] * 10))
        (path.parent / "results.json").write_text(json.dumps(tampered))
        with pytest.raises(ProtocolError, match="context mismatch"):
            verify_learning(path.parent)
