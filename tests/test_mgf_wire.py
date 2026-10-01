"""End-to-end bounded masked-gradient filtering through certified ASR rounds."""

import copy
import json
import random
from dataclasses import replace
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest

from trustlessfl.crypto import Identity, ORDER, ProtocolError, digest, verify
from trustlessfl.demo import provision
from trustlessfl.local_grid import ProcessGrid
from trustlessfl.peer_party import PeerParty
from trustlessfl.protocol import (Parameters, Party, certificate, check_finalized_model,
                                  valid_mgf_shares, _mgf_aggregate_commitments,
                                  _mgf_update_material)
from trustlessfl.mgf_wire import check_mgf_aggregate_mask
from trustlessfl.numeric import HPRF_MODULUS_192, MGFIntegerCodec, OUTPUT_MODULUS
from trustlessfl.task import local_delta
from trustlessfl.workflow import AionWorkflow


def _parameters(backend="artifact"):
    return Parameters("mgf-wire-" + backend, ("c0", "c1", "c2"),
                      ("a0", "a1", "a2", "a3"), dimension=2, decimals=3,
                      max_abs=10.0, mask_backend=backend,
                      mgf_beta="0.2", mgf_initial_alpha="0.2",
                      mgf_initial_bound="2", mgf_initial_term="1")


@pytest.mark.parametrize("backend", ["artifact", "lwe-reference", "lwe-192-reference"])
def test_local_mgf_validation_cache_is_recipient_bound_and_restart_safe(backend, monkeypatch):
    import trustlessfl.protocol as protocol
    from trustlessfl.crypto import canonical

    p = _parameters(backend)
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry,
                           trainer=lambda *_: [0.1, 0.0])
               for name, identity in identities.items()}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    votes = [parties[name].initialize({"enrollments": enrollments}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    update = parties["c0"].train({"model": model})
    admitted = parties["a0"].mgf_admit({"model": model, "update": update})
    assert admitted["body"]["update"] == digest(update)
    saved = json.loads(canonical(parties["a0"].state))
    restored = Party(identities["a0"], p, registry, copy.deepcopy(saved))
    original = protocol._mgf_local_material
    calls = []
    def counted_material(*args, **kwargs):
        calls.append(True)
        return original(*args, **kwargs)
    monkeypatch.setattr(protocol, "_mgf_local_material", counted_material)
    state = model["body"]["mgf_state"]
    _, key, masks = restored._validate_mgf_update(update, model["body"], state)
    assert not calls  # Uses the local proof after JSON serialization/restart.
    masks[0][0] += 1
    _, second_key, second_masks = restored._validate_mgf_update(update, model["body"], state)
    assert key == second_key and masks != second_masks
    assert not calls  # Returned lists cannot mutate cached secret shares.

    tampered = Party(identities["a0"], p, registry, copy.deepcopy(saved))
    tampered.state["mgf_local_material"]["entries"][0]["values"]["mask"][0][0] += 1
    with pytest.raises(ProtocolError, match="local MGF material cache"):
        tampered._validate_mgf_update(update, model["body"], state)
    other_recipient = Party(identities["a1"], p, registry, copy.deepcopy(saved))
    with pytest.raises(ProtocolError, match="local MGF material cache"):
        other_recipient._validate_mgf_update(update, model["body"], state)

    changed_body = copy.deepcopy(update["body"])
    changed_body["vector"][0] += 1
    changed = identities["c0"].sign(changed_body)
    preview = Party(identities["a0"], p, registry, saved.copy())
    preview._consensus_preview = True
    before_preview = copy.deepcopy(saved)
    preview._validate_mgf_update(changed, model["body"], state)
    assert preview.state == before_preview and saved == before_preview
    calls.clear()
    restored._validate_mgf_update(changed, model["body"], state)
    assert len(calls) == 1  # Exact signed-update digest, not just sender/round.
    broken_body = copy.deepcopy(update["body"])
    broken_body["mgf"]["mask_packets"]["a0"] = []
    broken = identities["c0"].sign(broken_body)
    with pytest.raises(ProtocolError, match="mask material"):
        restored._validate_mgf_update(broken, model["body"], state)
    assert len(calls) == 2

    bounded = Party(identities["a0"], p, registry, copy.deepcopy(saved))
    for offset in range(1, 35):
        variant = copy.deepcopy(update["body"])
        variant["vector"][0] += offset
        bounded._validate_mgf_update(identities["c0"].sign(variant), model["body"], state)
    assert len(bounded.state["mgf_local_material"]["entries"]) == 32
    before = len(calls)
    bounded._validate_mgf_update(update, model["body"], state)
    assert len(calls) == before  # Overflow does not evict the first admitted input.

    # Oversized material is still validated, but is not retained in the cache.
    fresh = Party(identities["a0"], p, registry, copy.deepcopy(saved))
    fresh.state.pop("mgf_local_material")
    monkeypatch.setattr(protocol, "canonical", lambda _: b"x" * (2 * 1024 * 1024 + 1))
    fresh._validate_mgf_update(update, model["body"], state)
    assert fresh.state["mgf_local_material"]["entries"] == []


def test_clientapp_persists_admission_material_for_transient_prepare(tmp_path, monkeypatch):
    from trustlessfl.client_app import process_local_request as execute_request
    import trustlessfl.protocol as protocol

    p = _parameters()
    manifest, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    registry = json.loads(manifest.read_text())["registry"]
    enrollments = [execute_request(configs[name], {"action": "enroll"}) for name in p.clients]
    votes = [execute_request(configs[name], {"action": "initialize", "enrollments": enrollments})
             for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [execute_request(configs[name], {"action": "train", "model": model})
               for name in p.clients[:2]]
    for update in updates:
        execute_request(configs["a0"], {"action": "mgf_admit", "model": model, "update": update})
    state_path = Path(configs["a0"]["aion-identity"]).parent / (
        "state-" + digest({"task": p.task, "party": "a0"}) + ".json")
    state = json.loads(state_path.read_text())
    assert len(state["mgf_local_material"]["entries"]) == 2
    assert state_path.stat().st_mode & 0o777 == 0o600
    def unexpected_full_validation(*_args, **_kwargs):
        raise AssertionError("exact admitted material should survive ClientApp reload")
    monkeypatch.setattr(protocol, "_mgf_local_material", unexpected_full_validation)
    prepared = execute_request(configs["a0"], {"action": "prepare", "model": model, "updates": updates})
    assert prepared["body"]["members"] == list(p.clients[:2])
    assert "mgf_mask_shares" in json.loads(state_path.read_text())["pending"]


def test_mgf_mask_vector_packets_retain_legacy_coordinate_decoder():
    from trustlessfl.crypto import decrypt_pedersen_vector_shares, encrypt_pedersen_share
    from trustlessfl.protocol import _mgf_local_material
    p = _parameters()
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    material = _mgf_update_material(p, identities["c0"], registry, 17, [3, 7], 1, "0.2")
    for recipient in p.aggregators:
        identity = identities[recipient]
        context = {"task": p.task, "sender": "c0", "round_id": 1,
                   "commitments": material["mask_commitments"]}
        pairs = decrypt_pedersen_vector_shares(material["mask_packets"][recipient],
                                               identity, **context)
        batch_result = _mgf_local_material(p, identity, "c0", material, 1)
        material["mask_packets"][recipient] = [
            encrypt_pedersen_share(pair, registry[recipient]["encryption"],
                                    task=p.task, sender="c0", recipient=recipient,
                                    round_id=1, coordinate=i,
                                    commitments=material["mask_commitments"][i])
            for i, pair in enumerate(pairs)]
        assert _mgf_local_material(p, identity, "c0", material, 1) == batch_result


@pytest.mark.parametrize("backend", ["artifact", "lwe-reference", "lwe-192-reference"])
@pytest.mark.parametrize("projection", [False, True])
def test_mgf_wire_filters_outlier_and_recovers_only_certified_masks(backend, projection, monkeypatch):
    p = _parameters(backend)
    if projection:
        p = replace(p, dimension=4, mgf_projection=(1, 3))
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    deltas = ([0.3, -0.1], [0.2, 0.1], [8.0, 8.0])
    if projection:
        deltas = [[0.7, *delta, 0.9] for delta in deltas]
    parties = {name: Party(identity, p, registry,
                           trainer=(lambda _weights, index, _rate, _round: deltas[index])
                           if name in p.clients else None)
               for name, identity in identities.items()}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    votes = [parties[name].initialize({"enrollments": enrollments}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)

    for round_id in (1, 2):
        updates = [parties[name].train({"model": model}) for name in p.clients]
        accepted = [update for update in updates if p.mgf_codec.accepts(
            update["body"]["mgf_vector" if projection else "vector"], model["body"]["mgf_state"]["bound"])]
        assert [update["sender"] for update in accepted] == ["c0", "c1"]
        with pytest.raises(ProtocolError, match="MGF rejected"):
            parties["a0"].prepare({"model": model, "updates": updates})
        roster_votes = [parties[name].prepare({"model": model, "updates": accepted})
                        for name in p.aggregators]
        roster = certificate(roster_votes[0]["body"], roster_votes, p, registry)
        shares = [parties[name].share({"roster": roster}) for name in p.aggregators]
        assert all(share["body"]["kind"] == "mgf-aggregate-share" for share in shares)
        key_com, mask_com = _mgf_aggregate_commitments(accepted, p)
        damaged = copy.deepcopy(shares[0])
        damaged["body"]["value"]["mask"][0][0] += 1
        damaged = identities["a0"].sign(damaged["body"])
        key_parts, mask_parts = valid_mgf_shares(
            [damaged, *shares[1:]], roster["body"], key_com, mask_com, p, registry)
        assert 1 not in key_parts and 1 not in mask_parts
        from trustlessfl.crypto import pedersen_reconstruct
        import trustlessfl.protocol as protocol
        expected_mask = [pedersen_reconstruct(
            {index: parts[coordinate] for index, parts in mask_parts.items()},
            mask_com[coordinate]) for coordinate in range(p.mgf_dimension)]
        optimized_keys, optimized_mask = valid_mgf_shares(
            [damaged, *shares[1:]], roster["body"], key_com, mask_com, p, registry,
            reconstruct_masks=True)
        assert optimized_keys == key_parts
        assert optimized_mask == expected_mask
        # A valid envelope's coordinates are checked once, not twice. This
        # asserts the real finalization path's optimization without timing.
        calls = []
        original_verify = protocol.pedersen_verify_share
        def counted_verify(index, pair, commitments):
            calls.append(index)
            return original_verify(index, pair, commitments)
        with monkeypatch.context() as patch:
            patch.setattr(protocol, "pedersen_verify_share", counted_verify)
            valid_mgf_shares(shares, roster["body"], key_com, mask_com, p, registry,
                             reconstruct_masks=True)
        assert len(calls) == len(shares) * p.mgf_dimension
        mutable_envelopes = copy.deepcopy(shares)
        changed = []
        def mutate_caller_input(index, pair, commitments):
            if index == 1 and not changed:
                mutable_envelopes[0]["body"]["value"]["mask"][0][0] += 1
                changed.append(True)
            return original_verify(index, pair, commitments)
        with monkeypatch.context() as patch:
            patch.setattr(protocol, "pedersen_verify_share", mutate_caller_input)
            _, snapshot_mask = valid_mgf_shares(
                mutable_envelopes, roster["body"], key_com, mask_com, p, registry,
                reconstruct_masks=True)
        # Caller mutation after signature verification cannot alter the local
        # snapshot used for either Pedersen checks or subsequent interpolation.
        _, reference_mask = valid_mgf_shares(
            shares, roster["body"], key_com, mask_com, p, registry,
            reconstruct_masks=True)
        assert changed and snapshot_mask == reference_mask
        with pytest.raises(ProtocolError, match="not enough valid MGF"):
            valid_mgf_shares([damaged, shares[1]], roster["body"], key_com, mask_com, p, registry,
                             reconstruct_masks=True)
        with pytest.raises(ProtocolError, match="not enough valid MGF"):
            valid_mgf_shares([shares[0]] * p.threshold, roster["body"], key_com, mask_com, p, registry,
                             reconstruct_masks=True)
        wrong_degree = [com[:-1] for com in mask_com]
        with pytest.raises(ProtocolError, match="reconstruction commitments"):
            valid_mgf_shares(shares, roster["body"], key_com, wrong_degree, p, registry,
                             reconstruct_masks=True)
        with pytest.raises(ProtocolError, match="not enough valid MGF"):
            valid_mgf_shares([damaged, shares[1]], roster["body"], key_com, mask_com, p, registry)
        proposals = [parties[name].finalize({"roster": roster, "shares": shares})
                     for name in p.aggregators]
        result = certificate(proposals[0]["body"], proposals, p, registry)
        commits = [parties[name].commit({"model": result}) for name in p.aggregators]
        result["commits"] = certificate(commits[0]["body"], commits, p, registry)
        check_finalized_model(result, p, registry)
        for name in p.aggregators:
            parties[name].decide({"model": result})
            assert "mgf_local_material" not in parties[name].state
        expected = [round_id * 0.25, 0.0]
        if projection:
            expected = [round_id * 0.7, *expected, round_id * 0.9]
            assert all("oracle_classifier" not in update["body"] for update in updates)
            assert len(mask_com) == 2 and len(result["body"]["model"]) == 4
        np.testing.assert_array_equal(result["body"]["model"], expected)
        assert result["body"]["mgf_state"]["alpha"] == "0.05"
        model = result


def test_mgf_projection_rejects_probe_that_differs_from_full_asr_update():
    p = replace(_parameters(), dimension=4, mgf_projection=(1, 3))
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry,
                           trainer=lambda *_: [0.7, 0.3, -0.1, 0.9])
               for name, identity in identities.items()}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    votes = [parties[name].initialize({"enrollments": enrollments}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[name].train({"model": model}) for name in p.clients[:2]]
    body = copy.deepcopy(updates[0]["body"])
    body["mgf_vector"][0] += 1
    updates[0] = identities["c0"].sign(body)
    roster_votes = [parties[name].prepare({"model": model, "updates": updates})
                    for name in p.aggregators]
    roster = certificate(roster_votes[0]["body"], roster_votes, p, registry)
    shares = [parties[name].share({"roster": roster}) for name in p.aggregators]
    with pytest.raises(ProtocolError, match="projection differs"):
        parties["a0"].finalize({"roster": roster, "shares": shares})


@pytest.mark.parametrize("hotstuff", [False, True])
def test_flower_mgf_filters_poisoned_update_before_roster(tmp_path, hotstuff):
    p = replace(_parameters(), hotstuff=hotstuff)
    manifest, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    attacker = Identity.from_private(json.loads(Path(configs["c2"]["aion-identity"]).read_text()))

    class PoisonOneClient(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            replies = super().call(grid, names, action, **kwargs)
            if action == "train":
                return [attacker.sign({**reply["body"], "vector": [8000, 8000]})
                        if reply["sender"] == "c2" else reply for reply in replies]
            return replies

    with ProcessGrid(nodes) as grid:
        history = PoisonOneClient(p, json.loads(manifest.read_text())["registry"],
                                  timeout=45.0).run(grid, 1)
    assert history[1]["body"]["round"] == 1
    expected = np.mean([p.codec.encode(
        local_delta(np.zeros(p.dimension), index, p.learning_rate))
        for index in (0, 1)], axis=0) / p.mgf_codec.scale
    np.testing.assert_allclose(history[1]["body"]["model"], expected, rtol=0, atol=1e-12)


@pytest.mark.parametrize("hotstuff", [False, True])
def test_flower_mgf_admission_drops_client_with_invalid_recipient_shares(tmp_path, hotstuff):
    p = replace(_parameters(), hotstuff=hotstuff)
    manifest, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    attacker = Identity.from_private(json.loads(Path(configs["c2"]["aion-identity"]).read_text()))

    class BreakTwoRecipientShares(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            replies = super().call(grid, names, action, **kwargs)
            if action != "train":
                return replies
            damaged = []
            for reply in replies:
                if reply["sender"] != "c2":
                    damaged.append(reply)
                    continue
                body = copy.deepcopy(reply["body"])
                for recipient in p.aggregators[:2]:
                    body["mgf"]["mask_packets"][recipient] = []
                damaged.append(attacker.sign(body))
            return damaged

    with ProcessGrid(nodes) as grid:
        history = BreakTwoRecipientShares(
            p, json.loads(manifest.read_text())["registry"], timeout=45.0).run(grid, 1)
    assert history[1]["body"]["round"] == 1
    expected = np.mean([p.codec.encode(
        local_delta(np.zeros(p.dimension), index, p.learning_rate))
        for index in (0, 1)], axis=0) / p.mgf_codec.scale
    np.testing.assert_allclose(history[1]["body"]["model"], expected, rtol=0, atol=1e-12)


def test_mgf_signed_bounded_update_reaches_optional_peer_inbox(tmp_path):
    p = _parameters()
    manifest, nodes = provision(tmp_path / "identities", p)
    configs = {name: nodes[index] for index, name in enumerate(p.clients + p.aggregators, 1)}
    identities = {name: Identity.from_private(json.loads(Path(configs[name]["aion-identity"]).read_text()))
                  for name in p.clients + p.aggregators}
    registry = json.loads(manifest.read_text())["registry"]
    parties = {name: Party(identity, p, registry) for name, identity in identities.items()}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    votes = [parties[name].initialize({"enrollments": enrollments}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    update = parties["c0"].train({"model": model})
    peer = PeerParty(configs["a0"], {name: ("127.0.0.1", 1) for name in p.aggregators[1:]})
    ack = peer._store_client_update("c0", {"action": "deliver_update", "update": update})
    assert verify(ack, registry, sender="a0")["update"] == digest(update)
    assert peer._read_inbox(1, digest(model["body"])) == [update]


def test_mgf_aggregate_consistency_allows_ring_carry_but_rejects_false_mask():
    modulus = OUTPUT_MODULUS
    outputs = [3 * modulus // 4, 3 * modulus // 4]
    observed = [150 + 150]
    aggregate = [sum(outputs) % modulus]
    check_mgf_aggregate_mask(observed, aggregate, "0.2", 2, 1000)
    # The aggregate HPRF itself may be off by a few output-ring units.
    check_mgf_aggregate_mask(observed, [(aggregate[0] + 2) % modulus], "0.2", 2, 1000)
    with pytest.raises(ProtocolError, match="inconsistent with HPRF"):
        check_mgf_aggregate_mask([0], aggregate, "0.2", 2, 1000)


@pytest.mark.parametrize("backend", ["artifact", "lwe-reference", "lwe-192-reference"])
@pytest.mark.parametrize("alpha", ["0.2", "3.3"])
def test_mgf_aggregate_consistency_accepts_random_honest_hprf_sums(backend, alpha):
    p = _parameters(backend)
    rng = random.Random(1937)
    fraction = Fraction(alpha)
    scale = p.mgf_codec.scale
    for count in (2, 3):
        for round_id in range(1, 21):
            modulus = HPRF_MODULUS_192 if backend == "lwe-192-reference" else ORDER
            keys = ([rng.randrange(modulus) for _ in range(count)]
                    if backend == "artifact" else
                    [[rng.randrange(modulus) for _ in range(p.hprf_width)]
                     for _ in range(count)])
            outputs = [p.codec._mask(key, p.task, round_id, p.dimension) for key in keys]
            combined = (sum(keys) % modulus if backend == "artifact" else
                        [sum(key[coordinate] for key in keys) % modulus
                         for coordinate in range(p.hprf_width)])
            aggregate_hprf = p.codec._mask(combined, p.task, round_id, p.dimension)
            mask_total = [sum(MGFIntegerCodec._round_ratio(
                fraction.numerator * scale * output[coordinate],
                fraction.denominator * OUTPUT_MODULUS)
                for output in outputs)
                for coordinate in range(p.dimension)]
            check_mgf_aggregate_mask(mask_total, aggregate_hprf, alpha, count, scale)


def test_mgf_rejects_client_signed_false_mask_shares_after_asr():
    p = _parameters()
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    parties = {name: Party(identity, p, registry) for name, identity in identities.items()}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    genesis_votes = [parties[name].initialize({"enrollments": enrollments})
                     for name in p.aggregators]
    model = certificate(genesis_votes[0]["body"], genesis_votes, p, registry)
    honest = parties["c1"].train({"model": model})
    alpha = model["body"]["mgf_state"]["alpha"]
    for key in range(1, 100):
        hprf = p.codec._mask(key, p.task, 1, p.dimension)
        _, expected_mask = p.mgf_codec.mask([0.0] * p.dimension, hprf, alpha)
        if any(20 <= value <= 180 for value in expected_mask):
            break
    else:
        raise AssertionError("no suitable deterministic HPRF test key")
    false_material = _mgf_update_material(p, identities["c0"], registry,
                                          key, [0] * p.dimension, 1, alpha)
    forged = identities["c0"].sign(p.claim(
        "update", 1, parent=digest(model["body"]), vector=[0] * p.dimension,
        mgf=false_material))
    updates = [forged, honest]
    roster_votes = [parties[name].prepare({"model": model, "updates": updates})
                    for name in p.aggregators]
    roster = certificate(roster_votes[0]["body"], roster_votes, p, registry)
    shares = [parties[name].share({"roster": roster}) for name in p.aggregators]
    with pytest.raises(ProtocolError, match="inconsistent with HPRF"):
        parties["a0"].finalize({"roster": roster, "shares": shares})
