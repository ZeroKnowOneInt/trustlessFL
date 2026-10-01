import copy
import json
import secrets
from dataclasses import asdict, replace

import numpy as np
import pytest
from flwr.app import ConfigRecord, Context, Message, RecordDict

from trustlessfl.client_app import app as client_app, payload, records
from trustlessfl.crypto import (
    MODULUS, ORDER, Identity, ProtocolError, aggregate_commitments, digest,
    decrypt_share, encrypt_share, reconstruct, split, verify_share,
)
from trustlessfl.demo import provision
from trustlessfl.local_grid import ProcessGrid, deserialize, serialize
from trustlessfl.numeric import (FixedPoint, HPRF_MODULUS_192, MaskedGradientFilter,
                                 OUTPUT_MODULUS, _lwe_input_bits, artifact_mask,
                                 lwe_reference_mask)
from trustlessfl.protocol import (Parameters, Party, certificate, check_certificate,
                                  check_finalized_model, check_finalized_roster, valid_shares)
from trustlessfl.server_app import app as server_app
from trustlessfl.task import local_delta, loss
from trustlessfl.workflow import AionWorkflow


@pytest.fixture(scope="module")
def initial():
    p = Parameters("unit-task", ("c0", "c1", "c2"), ("a0", "a1", "a2", "a3"))
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identities[name], p, registry) for name in identities}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    votes = [parties[name].initialize({"enrollments": enrollments}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    return p, identities, registry, {n: copy.deepcopy(v.state) for n, v in parties.items()}, model


@pytest.fixture
def system(initial):
    p, identities, registry, states, model = initial
    parties = {n: Party(i, p, registry, copy.deepcopy(states[n])) for n, i in identities.items()}
    return p, registry, parties, copy.deepcopy(model)


def prepared(system):
    p, registry, parties, model = system
    updates = [parties[c].train({"model": model}) for c in p.clients]
    votes = [parties[a].prepare({"model": model, "updates": updates}) for a in p.aggregators]
    roster = certificate(votes[0]["body"], votes, p, registry)
    return updates, roster


def test_feldman_reconstruction_and_tampering():
    shares, commitments = split(123456789, 3, 7)
    for index, value in shares.items():
        assert verify_share(index, value, commitments)
    assert reconstruct({i: shares[i] for i in [2, 4, 7]}, commitments) == 123456789
    with pytest.raises(ProtocolError, match="insufficient"):
        reconstruct({i: shares[i] for i in [1, 2]}, commitments)
    shares[1] = (shares[1] + 1) % ORDER
    with pytest.raises(ProtocolError, match="invalid"):
        reconstruct(shares, commitments)
    assert not verify_share(0, 0, commitments)
    assert not verify_share(1, 1, [MODULUS - 1, 1, 1])


def test_aggregated_commitment():
    a, ca = split(ORDER - 10, 2, 4)
    b, cb = split(20, 2, 4)
    total = {i: (a[i] + b[i]) % ORDER for i in a}
    assert reconstruct(total, aggregate_commitments([ca, cb])) == 10


def test_encryption_is_recipient_and_context_bound():
    recipient, wrong = Identity.generate("recipient"), Identity.generate("wrong")
    aad = {"task": "t", "recipient": "recipient"}
    packet = encrypt_share(42, recipient.public()["encryption"], aad)
    assert decrypt_share(packet, recipient, aad) == 42
    with pytest.raises(ProtocolError):
        decrypt_share(packet, wrong, aad)
    with pytest.raises(ProtocolError):
        decrypt_share(packet, recipient, {**aad, "task": "another"})


def test_oracle_mgf_rotates_key_and_rejects_recipient_swapped_share():
    p = Parameters("oracle-key-test", ("c0", "c1"), ("a0", "a1", "a2", "a3"),
                   dimension=61706, oracle_mgf=True)
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    trainer = lambda _weights, _partition, _rate, _round: np.zeros(p.dimension)
    parties = {name: Party(identity, p, registry, trainer=trainer)
               for name, identity in identities.items()}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    assert all("secret" not in parties[name].state for name in p.clients)
    votes = [parties[name].initialize({"enrollments": enrollments}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[name].train({"model": model}) for name in p.clients]
    assert updates[0]["body"]["oracle_key"]["commitments"] != updates[1]["body"]["oracle_key"]["commitments"]
    forged = copy.deepcopy(updates[0]["body"])
    forged["oracle_key"]["packets"]["a0"] = forged["oracle_key"]["packets"]["a1"]
    replaced = identities["c0"].sign(forged)
    with pytest.raises(ProtocolError):
        parties["a0"].prepare({"model": model, "updates": [replaced, updates[1]]})
    parties["a0"].prepare({"model": model, "updates": updates})


@pytest.mark.parametrize("count", [2, 3, 5, 10, 20])
def test_modular_homomorphism_rounding_and_wrap(count):
    codec = FixedPoint(decimals=4, max_clients=count)
    rng = np.random.default_rng(32 + count)
    keys = [secrets.randbelow(ORDER) for _ in range(count)]
    for round_id in [1, 2, 999]:
        values = [rng.uniform(-99, 99, 16) for _ in keys]
        masks = [codec.mask(v, k, "numeric-task", round_id) for v, k in zip(values, keys)]
        total = [sum(column) % OUTPUT_MODULUS for column in zip(*masks)]
        actual = codec.unmask(total, sum(keys) % ORDER, "numeric-task", round_id, count)
        expected = [sum(column) for column in zip(*(codec.encode(v) for v in values))]
        assert actual == expected
    assert artifact_mask(keys[0], "task", 1, 5) != artifact_mask(keys[0], "task", 2, 5)


@pytest.mark.parametrize("count", [2, 3, 5])
@pytest.mark.parametrize("backend,modulus", [("lwe-reference", ORDER),
                                              ("lwe-192-reference", HPRF_MODULUS_192)])
@pytest.mark.parametrize("input_bits", [32, 128])
def test_vector_lwe_reference_mask_roundtrip(count, backend, modulus, input_bits):
    codec = FixedPoint(max_clients=count, mask_backend=backend, hprf_width=8,
                       hprf_input_bits=input_bits)
    rng = np.random.default_rng(300 + count)
    keys = [[secrets.randbelow(modulus) for _ in range(8)] for _ in range(count)]
    values = [rng.uniform(-10, 10, 11) for _ in keys]
    for round_id in (1, 2):
        masked = [codec.mask(v, k, "lwe-math", round_id) for v, k in zip(values, keys)]
        total = [sum(column) % OUTPUT_MODULUS for column in zip(*masked, strict=True)]
        aggregate_key = [sum(key[i] for key in keys) % modulus for i in range(8)]
        assert codec.unmask(total, aggregate_key, "lwe-math", round_id, count) == [
            sum(column) for column in zip(*(codec.encode(v) for v in values), strict=True)]
    assert lwe_reference_mask(keys[0], "lwe-math", 1, 8, modulus,
                              input_bits=input_bits) != lwe_reference_mask(
        keys[0], "lwe-math", 2, 8, modulus, input_bits=input_bits)


def test_lwe_128_bit_input_is_injective_where_legacy_32_bit_input_collides():
    task = "lwe-domain-collision"
    first, second = 24581, 47098
    assert _lwe_input_bits(task, 1, first, ORDER, 32) == _lwe_input_bits(
        task, 1, second, ORDER, 32)
    assert _lwe_input_bits(task, 1, first, ORDER, 128) != _lwe_input_bits(
        task, 1, second, ORDER, 128)
    assert _lwe_input_bits(task, 1, first, ORDER, 128) != _lwe_input_bits(
        task, 2, first, ORDER, 128)
    with pytest.raises(ProtocolError, match="injective input domain"):
        _lwe_input_bits(task, 1 << 64, 0, ORDER, 128)
    with pytest.raises(ProtocolError, match="injective input domain"):
        _lwe_input_bits(task, 1, 1 << 64, ORDER, 128)


def test_lwe_input_length_is_bound_to_protocol_configuration():
    p = Parameters("lwe-input-length", ("c0", "c1"), ("a0", "a1", "a2", "a3"),
                   mask_backend="lwe-reference")
    legacy = replace(p, hprf_input_bits=32)
    assert p.codec.effective_hprf_input_bits == 128
    assert FixedPoint(mask_backend="lwe-192-reference").effective_hprf_input_bits == 128
    assert FixedPoint().effective_hprf_input_bits == 32
    assert p.config_digest == replace(p, hprf_input_bits=128).config_digest
    assert p.config_digest != legacy.config_digest
    old_claim = asdict(legacy)
    old_claim.pop("original_hprf_setup")
    old_claim.pop("hprf_input_bits")
    old_claim.pop("hotstuff")
    old_claim.pop("oracle_mgf")
    old_claim.pop("mgf_projection")
    old_claim.pop("mgf_single_view")
    old_claim.pop("mgf_percentile")
    old_claim.pop("mgf_artifact_bound")
    old_claim.pop("mgf_mask_sum_norm")
    for field in ("mgf_beta", "mgf_initial_alpha", "mgf_initial_bound", "mgf_initial_term"):
        old_claim.pop(field)
    assert legacy.config_digest == digest(old_claim)
    key = [1] * p.hprf_width
    assert lwe_reference_mask(key, p.task, 1, p.dimension) == lwe_reference_mask(
        key, p.task, 1, p.dimension, input_bits=128)
    assert Parameters.from_dict({**vars(legacy), "clients": list(legacy.clients),
                                 "aggregators": list(legacy.aggregators)}) == legacy
    with pytest.raises(ProtocolError, match="research HPRF input length"):
        replace(p, hprf_input_bits=64)


@pytest.mark.parametrize("values", [[float("nan")], [float("inf")], [101.0], [[1.0]], ["1"]])
def test_invalid_encoding(values):
    with pytest.raises(ProtocolError):
        FixedPoint().encode(values)


def test_numeric_bound_and_mgf():
    assert FixedPoint(max_clients=5).padding == 10
    with pytest.raises(ProtocolError):
        FixedPoint(max_abs=1e100)
    mgf = MaskedGradientFilter(2.0)
    assert mgf.accepts(np.array([1.0, 1.0]))
    assert not mgf.accepts(np.array([2.0, 2.0]))
    assert not mgf.accepts(np.array([np.nan]))
    assert mgf.alpha(np.array([1.0]), 2.0) == 0.1
    assert mgf.evolve(np.array([1.0]), np.array([2.0]), np.array([1.0]), np.array([1.0]), 0.1, 0.2) == 1.0
    with pytest.raises(ProtocolError):
        mgf.evolve(np.zeros(1), np.zeros(1), np.zeros(1), np.zeros(1), 0, 0)


def test_single_malicious_aggregator_configuration_rejected():
    with pytest.raises(ProtocolError, match="3f"):
        Parameters("t", ("c0", "c1"), ("a0",), faults=1)


def test_duplicate_votes_are_not_a_quorum(system):
    p, registry, _, model = system
    with pytest.raises(ProtocolError):
        certificate(model["body"], [model["votes"][0]] * 10, p, registry)
    forged = copy.deepcopy(model)
    forged["body"]["model"][0] = 99
    with pytest.raises(ProtocolError):
        check_certificate(forged, p, registry)


def test_wrong_task_and_wrong_round(system):
    p, registry, parties, model = system
    with pytest.raises(ProtocolError):
        check_certificate(model, replace(p, task="new-task"), registry)
    with pytest.raises(ProtocolError, match="another task"):
        check_certificate(model, replace(p, mask_backend="lwe-reference"), registry)
    altered = {**model["body"], "round": 5}
    cert = certificate(altered, [parties[a].identity.sign(altered) for a in p.aggregators], p, registry)
    committed = p.claim("committed", 5, model=digest(altered))
    cert["commits"] = certificate(committed,
        [parties[a].identity.sign(committed) for a in p.aggregators], p, registry)
    with pytest.raises(ProtocolError, match="invalid signed model ancestry"):
        parties[p.clients[0]].train({"model": cert})
    # A valid legacy certificate without ancestry still needs full history.
    altered.pop("ancestry")
    cert = certificate(altered, [parties[a].identity.sign(altered) for a in p.aggregators], p, registry)
    committed = p.claim("committed", 5, model=digest(altered))
    cert["commits"] = certificate(committed,
        [parties[a].identity.sign(committed) for a in p.aggregators], p, registry)
    with pytest.raises(ProtocolError, match="catch-up history"):
        parties[p.clients[0]].train({"model": cert})


def test_client_rejects_certified_model_off_its_training_history(system):
    p, registry, parties, model = system
    client = parties[p.clients[0]]
    client.train({"model": model})
    # Even a signed model for the next round cannot skip the model this client
    # actually used. This also covers a coordinator replaying a divergent fork.
    divergent = p.claim("model", 1, model=[0.0] * p.dimension,
                        enrollment=model["body"]["enrollment"], parent="wrong-parent")
    cert = certificate(divergent,
                       [parties[a].identity.sign(divergent) for a in p.aggregators], p, registry)
    committed = p.claim("committed", 1, model=digest(divergent))
    cert["commits"] = certificate(committed,
        [parties[a].identity.sign(committed) for a in p.aggregators], p, registry)
    with pytest.raises(ProtocolError, match="training history"):
        client.train({"model": cert})
    assert client.state["last_round"] == 1


def test_client_rejects_uncommitted_or_wrong_commit_quorum(system):
    p, registry, parties, model = system
    parties[p.clients[0]].train({"model": model})
    proposal = p.claim("model", 1, model=[0.0] * p.dimension,
                       enrollment=model["body"]["enrollment"], parent=digest(model["body"]))
    cert = certificate(proposal,
        [parties[a].identity.sign(proposal) for a in p.aggregators], p, registry)
    with pytest.raises(ProtocolError, match="commit certificate"):
        parties[p.clients[0]].train({"model": cert})
    committed = p.claim("committed", 1, model=digest(proposal))
    cert["commits"] = certificate(committed,
        [parties[a].identity.sign(committed) for a in p.aggregators], p, registry)
    cert["commits"]["votes"] = cert["commits"]["votes"][:p.quorum - 1]
    with pytest.raises(ProtocolError, match="insufficient"):
        check_finalized_model(cert, p, registry)
    with pytest.raises(ProtocolError, match="insufficient"):
        parties[p.clients[0]].train({"model": cert})
    wrong = copy.deepcopy(cert)
    wrong["commits"]["body"]["model"] = "other-model"
    with pytest.raises(ProtocolError, match="mismatched"):
        check_finalized_model(wrong, p, registry)


def test_aggregator_rejects_uncommitted_previous_model(system):
    p, registry, parties, model = system
    _, roster = prepared(system)
    shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
    votes = [parties[a].finalize({"roster": roster, "shares": shares}) for a in p.aggregators]
    result = certificate(votes[0]["body"], votes, p, registry)
    for a in p.aggregators:
        parties[a].commit({"model": result})
    with pytest.raises(ProtocolError, match="commit certificate"):
        parties[p.aggregators[0]].prepare({"model": result, "updates": []})


def test_default_mode_does_not_advance_on_local_commit_vote(system):
    p, registry, parties, _ = system
    _, roster = prepared(system)
    shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
    votes = [parties[a].finalize({"roster": roster, "shares": shares}) for a in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    commits = [parties[a].commit({"model": model}) for a in p.aggregators]
    assert all(parties[a].state["last_model"]["round"] == 0 for a in p.aggregators)
    assert all("1" not in parties[a].state.get("committed_members", {}) for a in p.aggregators)
    model["commits"] = certificate(commits[0]["body"], commits, p, registry)
    damaged = copy.deepcopy(model)
    damaged["commits"]["votes"] = damaged["commits"]["votes"][:p.quorum - 1]
    with pytest.raises(ProtocolError, match="insufficient"):
        parties[p.aggregators[0]].decide({"model": damaged})
    assert parties[p.aggregators[0]].state["last_model"]["round"] == 0
    decisions = [parties[a].decide({"model": model}) for a in p.aggregators]
    assert all(parties[a].state["last_model"]["round"] == 1 for a in p.aggregators)
    assert all(parties[a].state["committed_members"]["1"] == roster["body"]["members"]
               for a in p.aggregators)
    assert parties[p.aggregators[0]].decide({"model": model}) == decisions[0]


def test_fixed_cohort_dropout_aborts_before_share_release(system):
    p, _, parties, model = system
    updates = [parties[c].train({"model": model}) for c in p.clients]
    with pytest.raises(ProtocolError, match="dropout"):
        parties[p.aggregators[0]].prepare({"model": model, "updates": updates[:-1]})


def test_privacy_groups_reject_partial_or_cross_group_key_release():
    p = Parameters("group-task", ("c0", "c1", "c2", "c3"),
                   ("a0", "a1", "a2", "a3"),
                   privacy_groups=(("c0", "c1"), ("c2", "c3")))
    assert p.allowed_members(("c0", "c1"))
    assert p.allowed_members(("c2", "c3"))
    assert p.allowed_members(p.clients)
    assert not p.allowed_members(("c0",))
    assert not p.allowed_members(("c0", "c2"))
    assert not p.allowed_members(("c1", "c0"))
    assert Parameters.from_dict({**p.__dict__, "privacy_groups": [["c0", "c1"], ["c2", "c3"]]}) == p
    with pytest.raises(ProtocolError, match="partition"):
        replace(p, privacy_groups=(("c0", "c1"), ("c1", "c2")))


def test_group_dropout_keeps_only_complete_group_in_aggregate(tmp_path):
    p = Parameters("group-process-task", ("c0", "c1", "c2", "c3"),
                   ("a0", "a1", "a2", "a3"),
                   privacy_groups=(("c0", "c1"), ("c2", "c3")))
    _, nodes = provision(tmp_path / "keys", p)
    class DropOneGroupMember(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            if action == "train":
                names = tuple(name for name in names if name != "c3")
            return super().call(grid, names, action, **kwargs)

    # c3 misses training while the enrolled aggregator/client processes stay alive.
    with ProcessGrid(nodes) as grid:
        history = DropOneGroupMember(p, json.loads((tmp_path / "keys" / "manifest.json").read_text())["registry"],
                                     timeout=45.0).run(grid, 2)
    assert len(history) == 3
    assert all(entry["body"]["roster"] for entry in history[1:])
    expected = np.zeros(p.dimension)
    for entry in history[1:]:
        encoded = [p.codec.encode(local_delta(expected, i, p.learning_rate)) for i in (0, 1)]
        expected += np.sum(encoded, axis=0) / (2 * p.codec.scale)
        np.testing.assert_array_equal(entry["body"]["model"], expected)


@pytest.mark.parametrize("backend", ["artifact", "lwe-reference"])
def test_ema_recovers_only_complete_late_group(tmp_path, backend):
    p = Parameters("ema-process-task", ("c0", "c1", "c2", "c3"),
                   ("a0", "a1", "a2", "a3"),
                   privacy_groups=(("c0", "c1"), ("c2", "c3")), ema_weight=0.25,
                   mask_backend=backend)
    manifest, nodes = provision(tmp_path / "keys", p)
    class DelayOneGroupMember(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            if action == "train" and kwargs["model"]["body"]["round"] == 0:
                # First attempt is late; the next-round recovery call succeeds.
                if not getattr(self, "delayed", False):
                    self.delayed = True
                    names = tuple(name for name in names if name != "c3")
            return super().call(grid, names, action, **kwargs)

    with ProcessGrid(nodes) as grid:
        history = DelayOneGroupMember(p, json.loads(manifest.read_text())["registry"],
                                      timeout=45.0).run(grid, 2)
    initial = np.zeros(p.dimension)
    first_encoded = [p.codec.encode(local_delta(initial, i, p.learning_rate)) for i in (0, 1)]
    first = np.sum(first_encoded, axis=0) / (2 * p.codec.scale)
    np.testing.assert_array_equal(history[1]["body"]["model"], first)
    current_encoded = [p.codec.encode(local_delta(first, i, p.learning_rate)) for i in range(4)]
    late_encoded = [p.codec.encode(local_delta(initial, i, p.learning_rate)) for i in (2, 3)]
    expected = first + np.sum(current_encoded, axis=0) / (4 * p.codec.scale)
    expected += p.ema_weight * np.sum(late_encoded, axis=0) / (2 * p.codec.scale)
    np.testing.assert_allclose(history[2]["body"]["model"], expected, rtol=0, atol=1e-12)


def test_transient_aggregator_vote_loss_recovers_on_retry(tmp_path):
    p = Parameters("retry-process-task", ("c0", "c1", "c2"),
                   ("a0", "a1", "a2", "a3"))
    manifest, nodes = provision(tmp_path / "keys", p)
    class LoseFirstPrepareVotes(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            votes = super().call(grid, names, action, **kwargs)
            if action == "prepare" and not getattr(self, "lost", False):
                self.lost = True
                return votes[:1]
            return votes

    with ProcessGrid(nodes) as grid:
        workflow = LoseFirstPrepareVotes(p, json.loads(manifest.read_text())["registry"],
                                         timeout=45.0, quorum_attempts=2)
        history = workflow.run(grid, 1)
    assert workflow.lost and len(history) == 2
    assert len(history[-1]["commits"]["votes"]) >= p.quorum


def test_server_checkpoint_resumes_certified_round_without_reinitializing(tmp_path):
    p = Parameters("resume-process-task", ("c0", "c1", "c2"),
                   ("a0", "a1", "a2", "a3"), leader_views=True)
    manifest, nodes = provision(tmp_path / "keys", p)
    context = Context(1, 0, {}, RecordDict(), {"aion-manifest": str(manifest),
                      "research-mode": True, "num-server-rounds": 1, "timeout": 45.0})
    with ProcessGrid(nodes) as grid:
        server_app(grid, context)
        checkpoint = json.loads(context.state["aion-checkpoint"]["snapshot"])
        assert len(checkpoint["history"]) == 2
        context.run_config["num-server-rounds"] = 2
        server_app(grid, context)
        history = json.loads(context.state["aion-result"]["history"])
        assert len(history) == 3
        assert all(len(cert["decisions"]["votes"]) >= p.quorum for cert in history[1:])
        invalid = copy.deepcopy(checkpoint)
        invalid["history"][1]["decisions"]["votes"] = []
        context.state["aion-checkpoint"] = ConfigRecord({"snapshot": json.dumps(invalid).encode()})
        with pytest.raises(ProtocolError, match="insufficient"):
            server_app(grid, context)


def test_ema_checkpoint_preserves_omitted_group_for_next_round(tmp_path):
    p = Parameters("ema-resume-task", ("c0", "c1", "c2", "c3"),
                   ("a0", "a1", "a2", "a3"),
                   privacy_groups=(("c0", "c1"), ("c2", "c3")), ema_weight=0.25)
    manifest, nodes = provision(tmp_path / "keys", p)

    class DropC3FirstRound(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            if action == "train" and kwargs["model"]["body"]["round"] == 0:
                names = tuple(name for name in names if name != "c3")
            return super().call(grid, names, action, **kwargs)

    saved = []
    registry = json.loads(manifest.read_text())["registry"]
    with ProcessGrid(nodes) as grid:
        DropC3FirstRound(p, registry, timeout=45.0).run(
            grid, 1, on_checkpoint=lambda snapshot: saved.append(copy.deepcopy(snapshot)))
        assert saved[-1]["omitted"]["c3"] is None
        assert len(saved[-1]["history"][1]["decisions"]["votes"]) >= p.quorum
        uncertified = copy.deepcopy(saved[-1])
        uncertified["history"][1].pop("decisions")
        with pytest.raises(ProtocolError, match="decision quorum"):
            AionWorkflow(p, registry, timeout=45.0).run(grid, 2, checkpoint=uncertified)
        history = AionWorkflow(p, registry, timeout=45.0).run(grid, 2, checkpoint=saved[-1])
    assert len(history) == 3
    assert history[2]["body"]["round"] == 2
    assert history[2]["body"]["model"] != history[1]["body"]["model"]


def test_coordinator_crash_after_decision_resumes_from_saved_checkpoint(tmp_path):
    p = Parameters("crash-resume-task", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), leader_views=True)
    manifest, nodes = provision(tmp_path / "keys", p)
    registry = json.loads(manifest.read_text())["registry"]
    saved = {}

    def crash_after_round_one(snapshot):
        saved["checkpoint"] = copy.deepcopy(snapshot)
        if len(snapshot["history"]) == 2:
            raise RuntimeError("simulated coordinator crash")

    with ProcessGrid(nodes) as grid:
        with pytest.raises(RuntimeError, match="simulated coordinator crash"):
            AionWorkflow(p, registry, timeout=45.0).run(
                grid, 2, on_checkpoint=crash_after_round_one)
        assert len(saved["checkpoint"]["history"]) == 2
        resumed = AionWorkflow(p, registry, timeout=45.0).run(
            grid, 2, checkpoint=saved["checkpoint"])
    assert len(resumed) == 3
    assert resumed[2]["body"]["round"] == 2


def test_signed_view_change_recovers_from_unavailable_leader(tmp_path):
    p = Parameters("leader-failover-task", ("c0", "c1", "c2"),
                   ("a0", "a1", "a2", "a3"), leader_views=True)
    manifest, nodes = provision(tmp_path / "keys", p)
    nodes.pop(4)  # The first leader is unavailable; n-f other aggregators remain.
    context = Context(1, 0, {}, RecordDict(), {"aion-manifest": str(manifest),
                      "research-mode": True, "num-server-rounds": 1, "timeout": 45.0})
    with ProcessGrid(nodes) as grid:
        server_app(grid, context)
    history = json.loads(context.state["aion-result"]["history"])
    assert len(history) == 2
    assert history[1]["consensus"]["view"] == 1
    assert len(history[1]["consensus"]["view_qc"]["votes"]) == p.quorum
    assert len(history[1]["commits"]["votes"]) == p.quorum
    damaged = copy.deepcopy(history[1])
    damaged["consensus"]["view_qc"]["votes"] = damaged["consensus"]["view_qc"]["votes"][:1]
    with pytest.raises(ProtocolError, match="insufficient"):
        check_finalized_model(damaged, p, json.loads(manifest.read_text())["registry"])
    damaged = copy.deepcopy(history[1])
    damaged["roster_certificate"]["commits"]["votes"] = []
    with pytest.raises(ProtocolError, match="insufficient"):
        check_finalized_model(damaged, p, json.loads(manifest.read_text())["registry"])


def test_view_change_rejects_signed_malicious_leader_proposal(tmp_path):
    p = Parameters("bad-leader-task", ("c0", "c1", "c2"),
                   ("a0", "a1", "a2", "a3"), leader_views=True)
    manifest, nodes = provision(tmp_path / "keys", p)
    compromised = Identity.from_private(json.loads((tmp_path / "keys" / "a0" / "identity.json").read_text()))

    class ForgeFirstLeaderProposal(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            result = super().call(grid, names, action, **kwargs)
            if action == "prepare" and names == ("a0",) and result:
                wrong = {**result[0]["body"], "updates": "forged-update-set"}
                return [compromised.sign(wrong)]
            return result

    with ProcessGrid(nodes) as grid:
        history = ForgeFirstLeaderProposal(p, json.loads(manifest.read_text())["registry"],
                                           timeout=45.0).run(grid, 1)
    assert history[1]["body"]["round"] == 1
    assert len(history[1]["commits"]["votes"]) >= p.quorum


def test_view_change_chains_multiple_stalled_leaders(tmp_path):
    p = Parameters("two-stalled-leaders-task", ("c0", "c1", "c2"),
                   ("a0", "a1", "a2", "a3"), leader_views=True)
    manifest, nodes = provision(tmp_path / "keys", p)

    class StallTwoLeaders(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            if action in ("prepare", "finalize") and names in (("a0",), ("a1",)):
                return []
            return super().call(grid, names, action, **kwargs)

    registry = json.loads(manifest.read_text())["registry"]
    with ProcessGrid(nodes) as grid:
        history = StallTwoLeaders(p, registry, timeout=45.0).run(grid, 1)
    evidence = history[1]["consensus"]
    assert evidence["view"] == 2
    assert len(evidence["previous_views"]) == 1
    check_finalized_model(history[1], p, registry)
    damaged = copy.deepcopy(history[1])
    damaged["consensus"]["previous_views"] = []
    with pytest.raises(ProtocolError, match="incomplete view-change"):
        check_finalized_model(damaged, p, registry)


def test_view_change_requires_quorum_and_correct_leader_proposal():
    p = Parameters("view-evidence-task", ("c0", "c1"),
                   ("a0", "a1", "a2", "a3"), leader_views=True)
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry) for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in p.clients]
    votes = [parties[a].initialize({"enrollments": enrollments}) for a in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[c].train({"model": model}) for c in p.clients]
    request = {"model": model, "updates": updates}
    with pytest.raises(ProtocolError, match="leader consensus"):
        parties["a1"].prepare(request)
    proposal = parties["a0"].prepare({**request, "consensus": {"view": 0, "view_qc": None}})
    with pytest.raises(ProtocolError, match="leader proposal"):
        parties["a1"].prepare({**request, "consensus": {"view": 0, "view_qc": None,
                                                        "proposal": identities["a2"].sign(proposal["body"])}})
    context = digest(model["body"])
    new_view = {"phase": "roster", "round": 1, "view": 1, "context": context}
    view_votes = [parties[a].view_vote(new_view) for a in p.aggregators]
    qc = certificate(view_votes[0]["body"], view_votes, p, registry)
    short_qc = {**qc, "votes": qc["votes"][:p.quorum - 1]}
    with pytest.raises(ProtocolError, match="insufficient"):
        parties["a1"].prepare({**request, "consensus": {"view": 1, "view_qc": short_qc}})
    proposal1 = parties["a1"].prepare({**request, "consensus": {"view": 1, "view_qc": qc}})
    assert proposal1["body"] == proposal["body"]
    with pytest.raises(ProtocolError, match="incomplete prior view-change"):
        parties["a2"].view_vote({**new_view, "view": 2})
    second_view = {**new_view, "view": 2, "previous_views": [qc]}
    votes2 = [parties[a].view_vote(second_view) for a in p.aggregators]
    qc2 = certificate(votes2[0]["body"], votes2, p, registry)
    proposal2 = parties["a2"].prepare({**request, "consensus": {
        "view": 2, "view_qc": qc2, "previous_views": [qc]}})
    assert proposal2["body"] == proposal["body"]
    evidence = {"view": 2, "view_qc": qc2, "previous_views": [qc], "proposal": proposal2}
    roster_votes = [parties[a].prepare({**request, "consensus": evidence})
                    for a in p.aggregators]
    roster = certificate(proposal2["body"], roster_votes, p, registry)
    roster["consensus"] = evidence
    with pytest.raises(ProtocolError, match="roster commit"):
        parties["a0"].share({"roster": roster})
    commits = [parties[a].roster_commit({"roster": roster}) for a in p.aggregators]
    roster["commits"] = certificate(commits[0]["body"], commits, p, registry)
    assert check_finalized_roster(roster, p, registry) == proposal2["body"]
    assert parties["a0"].share({"roster": roster})["body"]["kind"] == "aggregate-share"
    damaged = copy.deepcopy(roster)
    damaged["commits"]["votes"] = damaged["commits"]["votes"][:1]
    with pytest.raises(ProtocolError, match="insufficient"):
        check_finalized_roster(damaged, p, registry)
    shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
    first_model = parties["a0"].finalize({"roster": roster, "shares": shares,
                                            "consensus": {"view": 0, "view_qc": None}})
    model_evidence = {"view": 0, "view_qc": None, "proposal": first_model}
    model_votes = [parties[a].finalize({"roster": roster, "shares": shares,
                                       "consensus": model_evidence}) for a in p.aggregators]
    model = certificate(first_model["body"], model_votes, p, registry)
    model["consensus"] = model_evidence
    model["roster_certificate"] = roster
    model_commits = [parties[a].commit({"model": model}) for a in p.aggregators]
    assert all(parties[a].state["last_model"]["round"] == 0 for a in p.aggregators)
    model["commits"] = certificate(model_commits[0]["body"], model_commits, p, registry)
    assert check_finalized_model(model, p, registry)["round"] == 1
    damaged_model = copy.deepcopy(model)
    damaged_model["commits"]["votes"] = damaged_model["commits"]["votes"][:1]
    with pytest.raises(ProtocolError, match="insufficient"):
        parties["a0"].decide({"model": damaged_model})
    assert parties["a0"].state["last_model"]["round"] == 0
    decisions = [parties[a].decide({"model": model}) for a in p.aggregators]
    assert len(decisions) == len(p.aggregators)
    assert all(parties[a].state["last_model"]["round"] == 1 for a in p.aggregators)
    assert parties["a0"].decide({"model": model}) == decisions[0]


def test_ema_refuses_released_or_partial_privacy_group():
    p = Parameters("ema-replay-task", ("c0", "c1", "c2", "c3"),
                   ("a0", "a1", "a2", "a3"),
                   privacy_groups=(("c0", "c1"), ("c2", "c3")), ema_weight=0.25)
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry) for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in p.clients]
    votes = [parties[a].initialize({"enrollments": enrollments}) for a in p.aggregators]
    genesis = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[c].train({"model": genesis}) for c in p.clients]
    roster_votes = [parties[a].prepare({"model": genesis, "updates": updates[:2]}) for a in p.aggregators]
    roster = certificate(roster_votes[0]["body"], roster_votes, p, registry)
    shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
    model_votes = [parties[a].finalize({"roster": roster, "shares": shares}) for a in p.aggregators]
    current = certificate(model_votes[0]["body"], model_votes, p, registry)
    commits = [parties[a].commit({"model": current}) for a in p.aggregators]
    current["commits"] = certificate(commits[0]["body"], commits, p, registry)
    for a in p.aggregators:
        parties[a].decide({"model": current})
    request = {"current": current, "previous": genesis}
    with pytest.raises(ProtocolError, match="overlaps"):
        parties["a0"].late_prepare({**request, "updates": updates[:2]})
    with pytest.raises(ProtocolError, match="splits"):
        parties["a0"].late_prepare({**request, "updates": updates[2:3]})


@pytest.mark.parametrize("backend", ["lwe-reference", "lwe-192-reference"])
@pytest.mark.parametrize("input_bits", [32, 128])
def test_vector_lwe_reference_backend_runs_across_flower_processes(
        tmp_path, backend, input_bits):
    p = Parameters(f"{backend}-process-task", ("c0", "c1"), ("a0", "a1", "a2", "a3"),
                   mask_backend=backend, hprf_width=8, hprf_input_bits=input_bits)
    manifest, nodes = provision(tmp_path / "keys", p)
    context = Context(1, 0, {}, RecordDict(), {"aion-manifest": str(manifest),
                      "research-mode": True, "num-server-rounds": 1, "timeout": 45.0})
    with ProcessGrid(nodes) as grid:
        server_app(grid, context)
    history = json.loads(context.state["aion-result"]["history"])
    encoded = [p.codec.encode(local_delta(np.zeros(p.dimension), i, p.learning_rate)) for i in range(2)]
    expected = np.sum(encoded, axis=0) / (2 * p.codec.scale)
    np.testing.assert_array_equal(history[1]["body"]["model"], expected)


def test_vector_vss_rejects_one_corrupt_coordinate():
    p = Parameters("vector-vss-task", ("c0", "c1"), ("a0", "a1", "a2", "a3"),
                   mask_backend="lwe-reference", hprf_width=8)
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry) for name, identity in identities.items()}
    enrollments = [parties[c].enroll({}) for c in p.clients]
    bad = copy.deepcopy(enrollments[0]["body"])
    aad = {"task": p.task, "sender": "c0", "recipient": "a0",
           "commitments": digest(bad["commitments"]), "coordinate": 0}
    original = decrypt_share(bad["packets"]["a0"][0], identities["a0"], aad)
    bad["packets"]["a0"][0] = encrypt_share((original + 1) % ORDER,
                                               registry["a0"]["encryption"], aad)
    enrollments[0] = identities["c0"].sign(bad)
    with pytest.raises(ProtocolError, match="vector VSS share"):
        parties["a0"].initialize({"enrollments": enrollments})


def test_client_retry_and_signed_equivocation(system):
    p, _, parties, model = system
    updates, roster = prepared(system)
    assert parties[p.clients[0]].train({"model": model}) == updates[0]
    altered = copy.deepcopy(updates)
    altered[0]["body"]["vector"][0] += 1
    altered[0] = parties[p.clients[0]].identity.sign(altered[0]["body"])
    with pytest.raises(ProtocolError, match="equivocation"):
        parties[p.aggregators[0]].prepare({"model": model, "updates": altered})


def test_malformed_signed_update_rejected(system):
    p, _, parties, model = system
    updates = [parties[c].train({"model": model}) for c in p.clients]
    updates[0]["body"]["vector"][0] = OUTPUT_MODULUS
    updates[0] = parties[p.clients[0]].identity.sign(updates[0]["body"])
    with pytest.raises(ProtocolError, match="invalid masked"):
        parties[p.aggregators[0]].prepare({"model": model, "updates": updates})


def test_malicious_aggregate_share_ignored(system):
    p, registry, parties, _ = system
    _, roster = prepared(system)
    envelopes = [parties[a].share({"roster": roster}) for a in p.aggregators]
    envelopes[0]["body"]["value"] = (envelopes[0]["body"]["value"] + 1) % ORDER
    envelopes[0] = parties[p.aggregators[0]].identity.sign(envelopes[0]["body"])
    com = aggregate_commitments([parties[p.aggregators[1]].state["commitments"][c] for c in p.clients])
    valid = valid_shares(envelopes, roster["body"], com, p, registry)
    assert 1 not in valid and len(valid) == 3
    with pytest.raises(ProtocolError):
        valid_shares(envelopes[:2], roster["body"], com, p, registry)
    votes = [parties[a].finalize({"roster": roster, "shares": envelopes}) for a in p.aggregators]
    certificate(votes[0]["body"], votes, p, registry)


def test_share_release_requires_valid_roster_quorum(system):
    p, _, parties, _ = system
    _, roster = prepared(system)
    roster["votes"] = roster["votes"][:1]
    with pytest.raises(ProtocolError, match="insufficient"):
        parties[p.aggregators[0]].share({"roster": roster})


def test_altered_enrollment_is_rejected_without_changing_state(system):
    p, _, parties, _ = system
    enrollments = [parties[c].enroll({}) for c in p.clients]
    enrollments = copy.deepcopy(enrollments)
    enrollments[0]["body"]["commitments"][0] = 1
    before = copy.deepcopy(parties[p.aggregators[0]].state)
    with pytest.raises(ProtocolError, match="signature"):
        parties[p.aggregators[0]].initialize({"enrollments": enrollments})
    assert parties[p.aggregators[0]].state == before


def test_finalization_and_commit_are_idempotent(system):
    p, registry, parties, _ = system
    _, roster = prepared(system)
    shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
    request = {"roster": roster, "shares": shares}
    votes = [parties[a].finalize(request) for a in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    for a, vote in zip(p.aggregators, votes):
        assert parties[a].finalize(request) == vote
        first = parties[a].commit({"model": model})
        assert parties[a].commit({"model": model}) == first
        assert parties[a].finalize(request) == vote


def test_multiple_rounds_match_clear_fixed_point_fedavg(system):
    p, registry, parties, model = system
    expected = np.zeros(p.dimension)
    for _ in range(3):
        _, roster = prepared((p, registry, parties, model))
        shares = [parties[a].share({"roster": roster}) for a in p.aggregators]
        votes = [parties[a].finalize({"roster": roster, "shares": shares}) for a in p.aggregators]
        model = certificate(votes[0]["body"], votes, p, registry)
        commits = [parties[a].commit({"model": model}) for a in p.aggregators]
        model["commits"] = certificate(commits[0]["body"], commits, p, registry)
        assert all(parties[a].state["last_model"]["round"] == model["body"]["round"] - 1
                   for a in p.aggregators)
        for a in p.aggregators:
            parties[a].decide({"model": model})
        updates = [p.codec.encode(local_delta(expected, i, p.learning_rate)) for i in range(len(p.clients))]
        expected += np.sum(updates, axis=0) / (len(p.clients) * p.codec.scale)
        np.testing.assert_array_equal(model["body"]["model"], expected)


def test_flower_wire_preserves_big_integers():
    original = Message(records({"value": ORDER - 1}), dst_node_id=2, message_type="query.aion")
    assert payload(deserialize(serialize(original))) == {"value": ORDER - 1}


def test_state_survives_clientapp_instances(tmp_path):
    p = Parameters("durable-task", ("c0", "c1"), ("a0", "a1", "a2", "a3"))
    _, nodes = provision(tmp_path / "keys", p)
    message = Message(records({"action": "enroll"}), dst_node_id=1, message_type="query.aion")
    context = lambda: Context(1, 1, nodes[1], RecordDict(), {})
    first = client_app(message, context())
    second = client_app(message, context())
    assert not first.has_error() and payload(first) == payload(second)
    assert list((tmp_path / "keys" / "c0").glob("state-*.json"))[0].stat().st_mode & 0o777 == 0o600


def test_actual_flower_apps_in_independent_processes(tmp_path):
    p = Parameters("process-task", ("c0", "c1", "c2"), ("a0", "a1", "a2", "a3"))
    manifest, nodes = provision(tmp_path / "keys", p)
    # One unavailable aggregator still leaves n-f honest votes and f+1 shares.
    nodes.pop(max(nodes))
    context = Context(1, 0, {}, RecordDict(), {"aion-manifest": str(manifest),
                      "research-mode": True, "num-server-rounds": 2, "timeout": 45.0})
    with ProcessGrid(nodes) as grid:
        assert len({process.pid for process in grid.processes.values()}) == len(nodes)
        server_app(grid, context)
    history = json.loads(context.state["aion-result"]["history"])
    assert len(history) == 3
    assert loss(np.asarray(history[-1]["body"]["model"]), 3) < loss(np.zeros(3), 3)
    assert "secret" not in context.state and "shares" not in context.state


def test_no_production_fallback():
    context = Context(1, 0, {}, RecordDict(), {"research-mode": False})
    with pytest.raises(ProtocolError, match="research-mode"):
        server_app(None, context)
