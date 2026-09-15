import copy
import json
import secrets
from dataclasses import replace

import numpy as np
import pytest
from flwr.app import Context, Message, RecordDict

from trustlessfl.client_app import app as client_app, payload, records
from trustlessfl.crypto import (
    MODULUS, ORDER, Identity, ProtocolError, aggregate_commitments,
    decrypt_share, encrypt_share, reconstruct, split, verify_share,
)
from trustlessfl.demo import provision
from trustlessfl.local_grid import ProcessGrid, deserialize, serialize
from trustlessfl.numeric import FixedPoint, MaskedGradientFilter, OUTPUT_MODULUS, artifact_mask
from trustlessfl.protocol import Parameters, Party, certificate, check_certificate, valid_shares
from trustlessfl.server_app import app as server_app
from trustlessfl.task import local_delta, loss


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
    altered = {**model["body"], "round": 5}
    cert = certificate(altered, [parties[a].identity.sign(altered) for a in p.aggregators], p, registry)
    with pytest.raises(ProtocolError, match="out-of-order"):
        parties[p.clients[0]].train({"model": cert})


def test_fixed_cohort_dropout_aborts_before_share_release(system):
    p, _, parties, model = system
    updates = [parties[c].train({"model": model}) for c in p.clients]
    with pytest.raises(ProtocolError, match="dropout"):
        parties[p.aggregators[0]].prepare({"model": model, "updates": updates[:-1]})


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
        for a in p.aggregators:
            parties[a].commit({"model": model})
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
