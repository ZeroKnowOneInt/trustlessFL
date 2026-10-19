"""Independent arithmetic/framing witnesses; native MPC is exercised by runner."""
from dataclasses import replace
import random

import pytest

from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_wire import RoundContext, aes_blocks, encode_update, mask_words, pack_wire, unpack_wire, reference_aggregate

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def test_nist_aes_known_answer():
    assert aes_blocks(KEY, [bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")]).hex() == "3ad77bb40d7a3660a89ecaf32466ef97"


@pytest.mark.parametrize("bits", [16, 32])
def test_chunk_counter_matches_full_stream_across_block_boundary(bits):
    full = mask_words(KEY, 7, 25, bits)
    assert mask_words(KEY, 7, 10, bits, offset=3) == full[3:13]
    assert mask_words(KEY, 7, 12, bits, offset=13) == full[13:]
    assert mask_words(KEY, 8, 25, bits) != full


def test_large_sum_never_reduced_to_wire_modulus():
    p = SeedMPCPolicy(2, 4, 20000, 400000000)
    keys = [bytes([i])*16 for i in range(1, 5)]
    rows = [encode_update(p, k, 1, [20000, 0]) for k in keys]
    assert reference_aggregate(p, keys, 1, rows) == {"status": "ok", "count": 4, "sum": [80000, 0]}
    assert 80000 % p.modulus == 14464


def test_wire_bytes_are_fixed_width_big_endian_and_reject_partial_words():
    p = SeedMPCPolicy(3, 4, 20000, 25)
    values = (1, 65535, 256)
    payload = pack_wire(p, values)
    assert payload == bytes.fromhex('0001ffff0100')
    assert unpack_wire(p, payload) == values
    with pytest.raises(ProtocolError): unpack_wire(p, payload[:-1])
    with pytest.raises(ProtocolError): unpack_wire(p, payload[:2])
    assert unpack_wire(p, payload[2:], offset=1, full=False) == values[1:]


def test_range_failure_rejects_entire_client_even_after_sanitize():
    p = SeedMPCPolicy(2, 4, 20000, 25)
    keys = [bytes([i])*16 for i in range(1, 5)]
    updates = [[3, 4], [-3, -4], [20001, 1], [3, 5]]
    rows = [tuple((u + m) % p.modulus for u, m in zip(v, mask_words(k, 2, 2)))
            for k, v in zip(keys, updates)]
    assert reference_aggregate(p, keys, 2, rows) == {"status": "ok", "count": 2, "sum": [0, 0]}
    assert reference_aggregate(p, keys[:1], 2, rows[:1]) == {"status": "abort"}


@pytest.mark.parametrize("bits", [16, 32])
def test_random_result_matches_original_integer_updates(bits):
    rng = random.Random(10411)
    for r in range(1, 61):
        p = SeedMPCPolicy(9, 4, 20000, rng.randrange(9*20000**2 + 1), word_bits=bits)
        keys = [rng.randbytes(16) for _ in range(4)]
        updates = [[rng.randint(-30000, 30000) for _ in range(9)] for _ in range(4)]
        rows = [tuple((v+m) % p.modulus for v,m in zip(u,mask_words(k,r,9,bits)))
                for k,u in zip(keys,updates)]
        selected = [all(abs(v)<=p.coordinate_cap for v in u) and sum(v*v for v in u)<=p.squared_threshold for u in updates]
        expected = {"status": "abort"} if sum(selected)<2 else {"status": "ok", "count": sum(selected),
                    "sum": [sum(u[j] for u,keep in zip(updates,selected) if keep) for j in range(9)]}
        assert reference_aggregate(p, keys, r, rows) == expected


def test_capacity_uses_full_norm_and_threshold_not_accepted_values():
    p = SeedMPCPolicy(61706, 4, 20000, 2500000000)
    assert p.widths() == {"wire": 18, "norm": 47, "sum": 19, "count": 5}
    p.validate_backend(p.backend_prime(), 47)
    with pytest.raises(ProtocolError): p.validate_backend(101, 47)
    with pytest.raises(ProtocolError): p.validate_backend(p.backend_prime(), 16)
    huge = replace(p, squared_threshold=2**300)
    with pytest.raises(ProtocolError): huge.backend_prime()


def test_signed_payload_binds_policy_model_handle_and_chunk_offset():
    p = SeedMPCPolicy(9, 4, 20000, 25)
    c = RoundContext("session", 1, 1, digest([0]*9), p.policy_hash)
    body = c.payload(p, client_id="c1", key_handle="h1", values=[1,2], offset=7)
    assert body["offset"] == 7 and body["dimension"] == 9
    assert digest(body) != digest({**body,"key_handle":"h2"})
    assert digest(body) != digest({**body,"offset":0})
    with pytest.raises(ProtocolError): c.payload(replace(p,squared_threshold=24),client_id="c1",key_handle="h1",values=[1])
    with pytest.raises(ProtocolError): c.payload(p,client_id="c1",key_handle="h1",values=[65536])


@pytest.mark.parametrize("change", [{"coordinate_cap":32768}, {"dimension":True}, {"minimum_accepted":5}, {"word_bits":8}])
def test_invalid_policy_rejected(change):
    with pytest.raises(ProtocolError): replace(SeedMPCPolicy(2,4,20000,25), **change)


@pytest.mark.parametrize("r", [0, -1, 2**64, True])
def test_invalid_counter_rejected(r):
    with pytest.raises(ProtocolError): mask_words(KEY, r, 2)
