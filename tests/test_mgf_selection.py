"""Artifact percentile arithmetic and independent, signed candidate validation."""

from dataclasses import asdict, replace

import pytest

from trustlessfl.crypto import Identity, ProtocolError, digest
from trustlessfl.mgf_selection import select_probes
from trustlessfl.protocol import Parameters, Party, certificate


def setup(count=100):
    p = Parameters("masked-percentile", tuple(f"c{i}" for i in range(count)),
                   ("a0", "a1", "a2", "a3"), dimension=4, decimals=3,
                   max_abs=10, mgf_beta="0.2", mgf_initial_alpha="0.2",
                   mgf_initial_bound="2", mgf_initial_term="1",
                   mgf_projection=(1, 3), mgf_percentile=True)
    identities = {name: Identity.generate(name) for name in p.clients + p.aggregators}
    registry = {name: identity.public() for name, identity in identities.items()}
    return p, identities, registry


@pytest.mark.parametrize("round_id,bound,retained", [(1, "2", 10), (2, "2", 10),
    (3, "2", 10), (4, "0.5", 50), (4, "10", 80), (4, "0.0001", 10)])
def test_q100_masked_percentile_counts(round_id, bound, retained):
    p, identities, registry = setup()
    probes = [identities[name].sign(p.claim("mgf-probe", round_id,
               parent="b" * 64, vector=[index * 10, 0], update="a" * 64))
              for index, name in enumerate(p.clients)]
    selected, trace = select_probes(p, registry, probes, "b" * 64, round_id, bound)
    assert selected == list(p.clients[:retained])
    assert trace["selected_count"] == retained and not trace["small_cohort_floor_override"]
    if round_id <= 3:
        assert trace["bound"] == {"squared_integer": 10000}


def test_artifact_bound_uses_both_history_norms_and_certified_current_cohort():
    from trustlessfl.mgf_selection import artifact_selection_bound
    p, identities, registry = setup(20)
    p = replace(p, mgf_artifact_bound=True)
    probes = [identities[name].sign(p.claim("mgf-probe", 4,
              parent="b" * 64, vector=[100, 0], update="a" * 64)) for name in p.clients]
    claim = p.claim("mgf-cohort-norm", 4, parent="b" * 64,
                    candidates=digest(probes), mask_linf="0.4")
    votes = [identities[name].sign(claim) for name in p.aggregators]
    proof = certificate(claim, votes, p, registry)
    state = {"alpha": "0.1", "bound": "3", "term": "1",
             "norms": ["0.2", "0.8"], "mask_linf": "0.1"}
    assert artifact_selection_bound(p, registry, state, proof, probes, "b" * 64, 4) == "12"
    for parent, candidates, round_id in (("c" * 64, probes, 4),
                                         ("b" * 64, probes[:10], 4),
                                         ("b" * 64, probes, 5)):
        with pytest.raises(ProtocolError, match="differs"):
            artifact_selection_bound(p, registry, state, proof, candidates, parent, round_id)
    with pytest.raises(ProtocolError, match="insufficient"):
        artifact_selection_bound(p, registry, state, {**proof, "votes": votes[:2]},
                                  probes, "b" * 64, 4)
    assert Parameters.from_dict(asdict(p)).config_digest == p.config_digest
    assert replace(p, mgf_artifact_bound=False).config_digest != p.config_digest


def test_percentile_rejects_reordered_repeated_and_forged_probes():
    p, identities, registry = setup(20)
    probes = [identities[name].sign(p.claim("mgf-probe", 1, parent="b" * 64,
               vector=[0, 0], update="a" * 64)) for name in p.clients]
    for invalid in (probes[::-1], [probes[0], probes[0]],
                    [{**probes[0], "signature": "00" * 64}, *probes[1:]]):
        with pytest.raises(ProtocolError):
            select_probes(p, registry, invalid, "b" * 64, 1, "2")


def test_each_aggregator_rejects_non_percentile_roster_and_unbound_update():
    p, identities, registry = setup(20)
    parties = {name: Party(identity, p, registry,
               trainer=lambda _w, index, *_: [0.5, index * 0.01, 0.02, 0.3])
               for name, identity in identities.items()}
    enrollments = [parties[name].enroll({}) for name in p.clients]
    votes = [parties[name].initialize({"enrollments": enrollments}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[name].train({"model": model}) for name in p.clients]
    probes = [update["body"]["mgf_probe"] for update in updates]
    chosen, trace = select_probes(p, registry, probes, digest(model["body"]), 1, "2")
    selected = [update for update in updates if update["sender"] in chosen]
    bad = [selected[0], next(update for update in updates if update["sender"] not in chosen)]
    bad.sort(key=lambda update: p.clients.index(update["sender"]))
    request = {"model": model, "mgf_candidates": probes}
    for name in p.aggregators:
        with pytest.raises(ProtocolError, match="percentile selection"):
            parties[name].prepare({**request, "updates": bad})
        vote = parties[name].prepare({**request, "updates": selected})
        assert vote["body"]["mgf_selection"] == trace
    altered = {**selected[0]["body"], "vector": list(selected[0]["body"]["vector"])}
    altered["vector"][0] += 1
    forged = identities[selected[0]["sender"]].sign(altered)
    with pytest.raises(ProtocolError, match="not bound"):
        parties["a0"].mgf_admit({"model": model, "update": forged})
    assert Parameters.from_dict(asdict(p)).config_digest == p.config_digest
    assert replace(p, mgf_percentile=False).config_digest != p.config_digest


@pytest.mark.parametrize("backend", ["artifact", "lwe-reference", "lwe-192-reference"])
def test_cohort_mask_norm_encrypts_shares_and_pins_one_cohort(monkeypatch, backend):
    import copy
    from fractions import Fraction
    from trustlessfl.crypto import ORDER, verify
    from trustlessfl.mgf_wire import _decimal
    from trustlessfl.numeric import HPRF_MODULUS_192, OUTPUT_MODULUS
    p, identities, registry = setup(20)
    p = replace(p, mask_backend=backend)
    modulus = HPRF_MODULUS_192 if backend == "lwe-192-reference" else ORDER
    unit = modulus // 1024
    keys = ([unit * (index + 1) for index in range(20)] if backend == "artifact" else
            [[unit * (index + coordinate + 1) for coordinate in range(p.hprf_width)]
             for index in range(20)])
    iterator = iter(keys)
    monkeypatch.setattr("trustlessfl.protocol._mgf_new_key", lambda _: next(iterator))
    parties = {name: Party(identity, p, registry,
                          trainer=lambda *_: [0.1, 0.2, 0.3, 0.4])
               for name, identity in identities.items()}
    enrolled = [parties[name].enroll({}) for name in p.clients]
    votes = [parties[name].initialize({"enrollments": enrolled}) for name in p.aggregators]
    model = certificate(votes[0]["body"], votes, p, registry)
    updates = [parties[name].train({"model": model}) for name in p.clients]
    probes = [update["body"]["mgf_probe"] for update in updates]
    request = {"model": model, "mgf_candidates": probes}
    with pytest.raises(ProtocolError, match="approval certificate"):
        parties["a0"].mgf_cohort_share(request)
    approvals = [parties[name].mgf_cohort_vote(request) for name in p.aggregators]
    with pytest.raises(ProtocolError, match="insufficient"):
        parties["a0"].mgf_cohort_share({**request, "cohort_certificate": {
            "body": approvals[0]["body"], "votes": approvals[:p.quorum - 1]}})
    request["cohort_certificate"] = certificate(approvals[0]["body"], approvals, p, registry)
    shares = [parties[name].mgf_cohort_share(request) for name in p.aggregators]
    assert all(set(share["body"]) == {"protocol", "task", "config", "kind", "round",
                                     "context", "packets"} for share in shares)
    assert all(isinstance(packet["ciphertext"], str) for share in shares
               for packets in share["body"]["packets"].values() for packet in packets)
    secret = sum(keys) if backend == "artifact" else [sum(key[k] for key in keys)
                                                      for k in range(p.hprf_width)]
    mask = p.codec._mask(secret, p.task, 1, p.dimension)[p.mgf_slice]
    expected = _decimal(Fraction(p.mgf_initial_alpha) * max(mask) / OUTPUT_MODULUS)
    norms = [parties[name].mgf_cohort_norm({**request, "cohort_shares": shares})
             for name in p.aggregators]
    claim = verify(norms[0], registry)
    assert claim["mask_linf"] == expected and claim["candidates"] == digest(probes)
    assert certificate(claim, norms, p, registry)["body"] == claim
    corrupted = copy.deepcopy(shares[0]["body"])
    corrupted["packets"]["a0"][0]["ciphertext"] = "00"
    bad = identities["a0"].sign(corrupted)
    assert parties["a0"].mgf_cohort_norm({**request, "cohort_shares": [bad, *shares[1:]]})["body"] == claim
    with pytest.raises(ProtocolError, match="insufficient"):
        parties["a0"].mgf_cohort_norm({**request, "cohort_shares": [bad, shares[1], shares[1]]})
    for name in p.aggregators:
        with pytest.raises(ProtocolError, match="conflicting"):
            parties[name].mgf_cohort_vote({**request, "mgf_candidates": probes[:10]})
        with pytest.raises(ProtocolError, match="conflicting"):
            parties[name].mgf_cohort_share({**request, "mgf_candidates": probes[:10]})
    with pytest.raises(ProtocolError, match="share decryption"):
        from trustlessfl.crypto import decrypt_share
        # A ciphertext to a1 cannot be decrypted using a0's private identity.
        decrypt_share(shares[0]["body"]["packets"]["a1"][0], identities["a0"], {})
