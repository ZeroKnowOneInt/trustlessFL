"""Hiding VSS groundwork for bounded per-round masks in a future MGF wire path."""

import pytest

from trustlessfl.crypto import (Identity, ORDER, ProtocolError, aggregate_commitments,
                                canonical, decrypt_pedersen_vector_shares,
                                decrypt_pedersen_share, encrypt_pedersen_share,
                                encrypt_pedersen_vector_shares,
                                pedersen_reconstruct, pedersen_split,
                                pedersen_verify_share, sum_pedersen_shares)
from trustlessfl.numeric import MGFIntegerCodec, OUTPUT_MODULUS


def test_optional_native_group_arithmetic_preserves_commitments(monkeypatch):
    import trustlessfl.crypto as crypto
    gmpy2 = pytest.importorskip("gmpy2")
    # Same polynomial coefficients and blinders must produce exactly the same
    # serialized commitments with either arithmetic implementation.
    samples = (ORDER - 7, ORDER - 11, 29)

    def run(native):
        values = iter(samples)
        monkeypatch.setattr(crypto, "_native_powmod", native)
        monkeypatch.setattr(crypto.secrets, "randbelow", lambda _: next(values))
        return crypto.pedersen_split(17, 2, 4)

    python_result = run(None)
    assert run(gmpy2.powmod) == python_result
    shares, commitments = python_result
    assert all(crypto.pedersen_verify_share(i, pair, commitments)
               for i, pair in shares.items())
    assert crypto.pedersen_reconstruct({1: shares[1], 3: shares[3]}, commitments) == 17


@pytest.mark.parametrize("small_mask", [0, 1, 17, ORDER - 1])
def test_pedersen_randomized_commitments_and_threshold_recovery(small_mask):
    shares, commitments = pedersen_split(small_mask, 2, 4)
    assert all(pedersen_verify_share(index, pair, commitments)
               for index, pair in shares.items())
    assert pedersen_reconstruct({1: shares[1], 4: shares[4]}, commitments) == small_mask
    assert pedersen_reconstruct({2: shares[2], 3: shares[3]}, commitments) == small_mask
    # Random blinders make equal bounded secrets produce different public commitments.
    _, second = pedersen_split(small_mask, 2, 4)
    assert commitments != second


def test_pedersen_rejects_corrupted_share_and_missing_quorum():
    shares, commitments = pedersen_split(3, 2, 4)
    damaged = {**shares, 1: ((shares[1][0] + 1) % ORDER, shares[1][1])}
    assert not pedersen_verify_share(1, damaged[1], commitments)
    with pytest.raises(ProtocolError, match="invalid Pedersen"):
        pedersen_reconstruct(damaged, commitments)
    with pytest.raises(ProtocolError, match="insufficient Pedersen"):
        pedersen_reconstruct({1: shares[1]}, commitments)


def test_public_interpolation_cache_never_bypasses_share_validation():
    import trustlessfl.crypto as crypto

    crypto._lagrange_at_zero.cache_clear()
    shares, commitments = pedersen_split(17, 2, 4)
    selected = {1: shares[1], 3: shares[3]}
    assert pedersen_reconstruct(selected, commitments) == 17
    assert pedersen_reconstruct(selected, commitments) == 17
    assert crypto._lagrange_at_zero.cache_info().hits == 1
    damaged = {**selected, 3: ((shares[3][0] + 1) % ORDER, shares[3][1])}
    with pytest.raises(ProtocolError, match="invalid Pedersen"):
        pedersen_reconstruct(damaged, commitments)
    # The cache key contains only the public participant indices.
    assert crypto._lagrange_at_zero.cache_info().hits == 1
    assert crypto._lagrange_at_zero.cache_info().maxsize == 256


@pytest.mark.parametrize("indices", [(1, 2), (2, 4), (1, 3, 4), (2, 5, 7, 9)])
def test_cached_interpolation_matches_uncached_polynomial(indices):
    import trustlessfl.crypto as crypto

    coefficients = [17, 23, 41, 59][:len(indices)]
    shares = {i: sum(a * pow(i, degree, ORDER)
                     for degree, a in enumerate(coefficients)) % ORDER
              for i in indices}
    weights = crypto._lagrange_at_zero(indices)
    assert sum(weights[k] * shares[i] for k, i in enumerate(indices)) % ORDER == 17


def test_pedersen_aggregate_of_bounded_mask_shares():
    first, first_commitments = pedersen_split(2, 2, 4)
    second, second_commitments = pedersen_split(5, 2, 4)
    commitments = aggregate_commitments([first_commitments, second_commitments])
    combined = {index: sum_pedersen_shares([first[index], second[index]])
                for index in first}
    assert all(pedersen_verify_share(index, pair, commitments)
               for index, pair in combined.items())
    assert pedersen_reconstruct({1: combined[1], 3: combined[3]}, commitments) == 7


def test_pedersen_share_encryption_binds_identity_round_and_commitment():
    aggregator = Identity.generate("a0")
    wrong_aggregator = Identity.generate("a1")
    shares, commitments = pedersen_split(5, 2, 4)
    packet = encrypt_pedersen_share(shares[1], aggregator.public()["encryption"],
                                    task="t", sender="c0", recipient="a0",
                                    round_id=2, coordinate=3, commitments=commitments)
    context = {"task": "t", "sender": "c0", "round_id": 2,
               "coordinate": 3, "commitments": commitments}
    assert decrypt_pedersen_share(packet, aggregator, **context) == shares[1]
    assert pedersen_verify_share(1, decrypt_pedersen_share(packet, aggregator, **context),
                                 commitments)
    for invalid in ({"round_id": 3}, {"coordinate": 4}, {"sender": "c1"},
                    {"task": "other"}, {"commitments": commitments[::-1]}):
        with pytest.raises(ProtocolError, match="decryption failed"):
            decrypt_pedersen_share(packet, aggregator, **{**context, **invalid})
    with pytest.raises(ProtocolError, match="decryption failed"):
        decrypt_pedersen_share(packet, wrong_aggregator, **context)
    replacement = "00" if packet["ciphertext"][:2] != "00" else "01"
    corrupted = {**packet, "ciphertext": replacement + packet["ciphertext"][2:]}
    with pytest.raises(ProtocolError, match="decryption failed"):
        decrypt_pedersen_share(corrupted, aggregator, **context)


def test_pedersen_vector_packet_preserves_coordinates_and_binds_context():
    aggregator = Identity.generate("a0")
    components = [pedersen_split(value, 2, 4) for value in (0, 1, 17)]
    commitments = [com for _, com in components]
    pairs = [shares[1] for shares, _ in components]
    context = {"task": "vector-test", "sender": "c0", "round_id": 2,
               "commitments": commitments}
    packet = encrypt_pedersen_vector_shares(pairs, aggregator.public()["encryption"],
                                             recipient="a0", **context)
    assert decrypt_pedersen_vector_shares(packet, aggregator, **context) == pairs
    legacy = [encrypt_pedersen_share(pair, aggregator.public()["encryption"],
                                     task=context["task"], sender="c0", recipient="a0",
                                     round_id=2, coordinate=i, commitments=commitments[i])
              for i, pair in enumerate(pairs)]
    assert len(canonical(packet)) < len(canonical(legacy))
    for change in ({"task": "other"}, {"sender": "c1"}, {"round_id": 3},
                   {"commitments": commitments[::-1]}, {"commitments": commitments[:-1]}):
        with pytest.raises(ProtocolError):
            decrypt_pedersen_vector_shares(packet, aggregator, **{**context, **change})
    with pytest.raises(ProtocolError):
        decrypt_pedersen_vector_shares(packet, Identity.generate("a1"), **context)
    replacement = "A" if packet["ciphertext"][0] != "A" else "B"
    corrupted = {**packet, "ciphertext": replacement + packet["ciphertext"][1:]}
    with pytest.raises(ProtocolError):
        decrypt_pedersen_vector_shares(corrupted, aggregator, **context)
    with pytest.raises(ProtocolError):
        decrypt_pedersen_vector_shares({**packet, "ciphertext": packet["ciphertext"][:-4]},
                                        aggregator, **context)


def test_bounded_mask_mgf_arithmetic_recovers_selected_clients_only():
    codec = MGFIntegerCodec(decimals=3, max_abs=10.0, max_clients=3, max_alpha="0.5")
    updates = ([0.2, -0.3], [0.4, 0.1], [8.0, 8.0])
    hprf_outputs = ([OUTPUT_MODULUS // 4, OUTPUT_MODULUS // 2],
                    [OUTPUT_MODULUS // 3, OUTPUT_MODULUS // 5],
                    [OUTPUT_MODULUS // 7, OUTPUT_MODULUS // 9])
    masked, shares, commitments = [], [], []
    for values, h in zip(updates, hprf_outputs, strict=True):
        y, mask = codec.mask(values, list(h), "0.2")
        masked.append(y)
        per_coordinate = [pedersen_split(value, 2, 4) for value in mask]
        shares.append([item[0] for item in per_coordinate])
        commitments.append([item[1] for item in per_coordinate])
    accepted = [index for index, vector in enumerate(masked)
                if codec.accepts(vector, "1")]
    assert accepted == [0, 1]
    aggregate_mask = []
    for coordinate in range(2):
        combined_commitments = aggregate_commitments(
            [commitments[index][coordinate] for index in accepted])
        combined_shares = {party: sum_pedersen_shares(
            [shares[index][coordinate][party] for index in accepted])
            for party in (1, 3)}
        aggregate_mask.append(pedersen_reconstruct(combined_shares, combined_commitments))
    total = [sum(masked[index][coordinate] for index in accepted)
             for coordinate in range(2)]
    assert codec.recover(total, aggregate_mask, len(accepted)) == [600, -200]
    with pytest.raises(ProtocolError, match="outside declared bounds"):
        codec.recover(total, [ORDER - 1, aggregate_mask[1]], len(accepted))


def test_bounded_mask_support_can_expose_distinct_client_inputs():
    codec = MGFIntegerCodec(decimals=3, max_abs=10.0, max_clients=2, max_alpha="0.2")
    low = [codec.mask([-1.0], [h], "0.2")[0][0]
           for h in (OUTPUT_MODULUS // 2, OUTPUT_MODULUS - 1)]
    high = [codec.mask([1.0], [h], "0.2")[0][0]
            for h in (OUTPUT_MODULUS // 2, OUTPUT_MODULUS - 1)]
    assert max(low) < min(high)


def test_mgf_recovery_enforces_the_certified_round_alpha_not_just_setup_maximum():
    codec = MGFIntegerCodec(decimals=3, max_abs=10.0, max_clients=2, max_alpha="10")
    assert codec.recover([0], [500], 2) == [-500]
    with pytest.raises(ProtocolError, match="outside declared bounds"):
        codec.recover([0], [500], 2, alpha="0.2")
