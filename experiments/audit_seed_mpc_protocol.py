"""Plaintext arithmetic/AES oracle for the seed-MPC protocol design.

This does not implement secret sharing, MPC, durable key reuse, BFT, or Flower.
Private keys/updates exist in clear here; use only synthetic public fixtures.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def masks(key, round_id, dimension, word_bits=16):
    if len(key) != 16 or not 0 <= round_id < 2**64:
        raise ValueError('invalid AES key or round id')
    if word_bits not in (16, 32) or dimension < 1:
        raise ValueError('unsupported framing')
    per_block = 128 // word_bits
    blocks = (dimension + per_block - 1) // per_block
    aes = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    addresses = b''.join(round_id.to_bytes(8, 'big') + b.to_bytes(8, 'big')
                         for b in range(blocks))
    # ECB here evaluates distinct counter blocks; it does not encrypt updates.
    stream = aes.update(addresses) + aes.finalize()
    size = word_bits // 8
    return tuple(int.from_bytes(stream[j*size:(j+1)*size], 'big')
                 for j in range(dimension))


def decode(y, mask, q, cap):
    if not 0 <= y < q or not 0 <= mask < q or not 2*cap < q:
        raise ValueError('noncanonical wire/mask or invalid cap')
    z = y - mask
    r = z + q * int(z < 0)
    assert 0 <= r < q
    positive = r <= cap
    negative = r >= q - cap
    valid = positive or negative
    # Sanitize before any square; invalid values are never truncated to fit cap.
    u = int(valid) * (r - q * int(negative))
    assert abs(u) <= cap
    return bool(valid), u


def evaluate(rows, key_rows, *, round_id, cap, threshold, word_bits=16, minimum=1):
    dimension = len(rows[0]); q = 1 << word_bits
    if len(rows) != len(key_rows) or any(len(row) != dimension for row in rows):
        raise ValueError('invalid shape')
    count = 0; total = [0] * dimension
    for row, key in zip(rows, key_rows):
        mask = masks(key, round_id, dimension, word_bits)
        checked = [decode(y, m, q, cap) for y, m in zip(row, mask)]
        valid = all(ok for ok, _ in checked)
        u = [v for _, v in checked]
        norm = sum(v*v for v in u)
        assert norm <= dimension * cap**2
        accepted = valid and norm <= threshold
        count += int(accepted)
        total = [a + int(accepted)*b for a, b in zip(total, u)]
    assert all(abs(v) <= len(rows) * cap for v in total)
    return {'status': 'ok', 'count': count, 'sum': total} if count >= minimum else {'status': 'abort'}


def audit():
    # NIST SP 800-38A AES block test, also cited by MP-SPDZ aes_circuit example.
    enc = Cipher(algorithms.AES(bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')),
                 modes.ECB()).encryptor()
    assert (enc.update(bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')) + enc.finalize()).hex() == '3ad77bb40d7a3660a89ecaf32466ef97'
    exhaustive = 0
    for w in range(2, 7):
        q = 1 << w
        for cap in range(1, min(4, q//2 - 1) + 1):
            for y, m in itertools.product(range(q), repeat=2):
                r = (y-m) % q
                ideal = r if r < q//2 else r-q
                ok, u = decode(y, m, q, cap)
                assert ok == (abs(ideal) <= cap)
                assert u == (ideal if ok else 0)
                exhaustive += 1
    seed = random.Random(20261010)
    random_rounds = 0
    for word_bits in (16, 32):
        q = 1 << word_bits
        for round_id in range(1, 151):
            n, d, cap = 4, 9, 20000
            keys = [seed.randbytes(16) for _ in range(n)]
            updates = [[seed.randint(-30000, 30000) for _ in range(d)] for _ in range(n)]
            threshold = seed.randrange(d*cap*cap + 1)
            mask_rows = [masks(k, round_id, d, word_bits) for k in keys]
            rows = [[(v+m) % q for v, m in zip(u, mask)] for u, mask in zip(updates, mask_rows)]
            accepted = [all(abs(v) <= cap for v in u) and sum(v*v for v in u) <= threshold for u in updates]
            expected = {'status': 'ok', 'count': sum(accepted),
                        'sum': [sum(int(ok)*u[j] for ok, u in zip(accepted, updates)) for j in range(d)]}
            if not any(accepted): expected = {'status': 'abort'}
            assert evaluate(rows, keys, round_id=round_id, cap=cap, threshold=threshold,
                            word_bits=word_bits) == expected
            random_rounds += 1
    keys = [bytes([i])*16 for i in range(1, 5)]
    mm = [masks(k, 1000, 1)[0] for k in keys]
    rows = [[(20000+m) % 65536] for m in mm]
    output = evaluate(rows, keys, round_id=1000, cap=20000, threshold=400000000)
    assert output['sum'] == [80000]
    aggregate_wire_residue = (sum(row[0] for row in rows)-sum(mm)) % 65536
    aggregate_wire_center = aggregate_wire_residue if aggregate_wire_residue < 32768 else aggregate_wire_residue-65536
    assert aggregate_wire_center == 14464
    # Exact norm boundary and whole-client invalidity despite coordinate sanitation.
    kk = [keys[0]]; mask = masks(kk[0], 1001, 2)
    fixtures = ([3,4], [3,5], [20001,0], [-20000,0], [20000,0])
    statuses = []
    for u in fixtures:
        row = [[(v+m) % 65536 for v, m in zip(u, mask)]]
        result = evaluate(row, kk, round_id=1001, cap=20000, threshold=25)
        statuses.append(result['status'])
    assert statuses == ['ok', 'abort', 'abort', 'abort', 'abort']
    try: decode(65536, 0, 65536, 20000)
    except ValueError: pass
    else: raise AssertionError('noncanonical Y accepted')
    alias_ok, alias_u = decode((65536+7) % 65536, 0, 65536, 20000)
    assert alias_ok and alias_u == 7
    same_mask = masks(keys[0], 2000, 2)
    a = [(v+m) % 65536 for v,m in zip([3,4], same_mask)]
    b = [(v+m) % 65536 for v,m in zip([5,9], same_mask)]
    assert [(bb-aa) % 65536 for aa,bb in zip(a,b)] == [2,5]
    # No cryptographic claim from different fixture masks: uniqueness is by counter.
    assert len({r.to_bytes(8,'big')+j.to_bytes(8,'big') for r in range(20) for j in range(30)}) == 600
    return {'scope': 'synthetic plaintext oracle; no native MPC/security/performance validation',
            'aes_known_answer': 'passed', 'exhaustive_coordinate_checks': exhaustive,
            'random_aes_rounds': random_rounds, 'norm_boundary_and_invalid_client': 'passed',
            'canonical_wire_rejection': 'passed', 'counter_address_uniqueness_cases': 600,
            'reused_mask_difference_leak': [2,5],
            'malicious_modular_alias': {'claimed_raw':65543, 'effective_input':alias_u},
            'sum_exceeds_wire_modulus': {'wire_q':65536, 'true_sum':80000,
                                         'mpc_integer_sum':output['sum'][0],
                                         'wrong_aggregate_wire_decode':aggregate_wire_center},
            'fmnist_cost_counts': {'dimension':61706, 'clients':4, 'mask_word_bits':16,
                                   'wire_bytes_per_client':61706*2, 'aes_blocks_per_client':(61706+7)//8,
                                   'aes_blocks_per_round':4*((61706+7)//8),
                                   'squares_per_round':4*61706, 'norm_cap':61706*20000**2,
                                   'norm_bits':(61706*20000**2).bit_length(),
                                   'sum_cap':4*20000},
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--output', type=Path)
    args = parser.parse_args(); result = audit()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('x', encoding='utf-8') as out:
            json.dump(result, out, ensure_ascii=False, indent=2); out.write('\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
