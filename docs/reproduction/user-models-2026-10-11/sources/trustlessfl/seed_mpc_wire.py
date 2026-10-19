"""Client-side AES counter masks; reference unmasking is test-only.

Legacy mode generates masks on secret keys inside MPC. The seeded-component
adapter expands only a recipient's three components locally (seed_mpc_prss).
Never call reference_aggregate with real client keys on a server.
"""
from dataclasses import asdict, dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .crypto import ProtocolError, digest
from .seed_mpc_policy import SeedMPCPolicy


def aes_blocks(key, counters):
    if type(key) is not bytes or len(key) != 16:
        raise ProtocolError("AES-128 key must be 16 bytes")
    if not counters or any(type(c) is not bytes or len(c) != 16 for c in counters):
        raise ProtocolError("invalid AES counter blocks")
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    # Independent counter evaluations; updates are not ECB-encrypted.
    return enc.update(b"".join(counters)) + enc.finalize()


def mask_words(key, round_id, dimension, word_bits=16, *, offset=0):
    if (type(round_id) is not int or not 1 <= round_id < 2**64
            or type(dimension) is not int or dimension < 1
            or type(offset) is not int or offset < 0
            or type(word_bits) is not int or word_bits not in (16, 32)):
        raise ProtocolError("invalid counter framing")
    per_block = 128 // word_bits
    first, last = offset // per_block, (offset + dimension - 1) // per_block
    if last >= 2**64:
        raise ProtocolError("counter block index exhausted")
    counters = [round_id.to_bytes(8, "big") + b.to_bytes(8, "big")
                for b in range(first, last + 1)]
    stream = aes_blocks(key, counters)
    size = word_bits // 8
    start = (offset % per_block) * size
    return tuple(int.from_bytes(stream[start+j*size:start+(j+1)*size], "big")
                 for j in range(dimension))


def encode_update(policy, key, round_id, update):
    policy.validate_update(update)
    masks = mask_words(key, round_id, policy.dimension, policy.word_bits)
    return tuple((v + m) % policy.modulus for v, m in zip(update, masks, strict=True))


def pack_wire(policy, values, *, offset=0, full=True):
    """Canonical big-endian fixed-width payload (2*D bytes for 16-bit words)."""
    policy.validate_wire(values, offset=offset, full=full)
    size = policy.word_bits // 8
    return b''.join(v.to_bytes(size, 'big') for v in values)


def unpack_wire(policy, payload, *, offset=0, full=True):
    size = policy.word_bits // 8
    if type(payload) is not bytes or not payload or len(payload) % size:
        raise ProtocolError('noncanonical wire bytes')
    values = tuple(int.from_bytes(payload[j:j+size], 'big')
                   for j in range(0, len(payload), size))
    policy.validate_wire(values, offset=offset, full=full)
    return values


@dataclass(frozen=True)
class RoundContext:
    session_id: str
    committee_epoch: int
    round_id: int
    model_hash: str
    policy_hash: str

    def __post_init__(self):
        if (type(self.session_id) is not str or not 1 <= len(self.session_id) <= 128
                or type(self.committee_epoch) is not int or not 1 <= self.committee_epoch < 2**64
                or type(self.round_id) is not int or not 1 <= self.round_id < 2**64):
            raise ProtocolError("invalid round context")
        for value in (self.model_hash, self.policy_hash):
            if (type(value) is not str or len(value) != 64
                    or any(c not in "0123456789abcdef" for c in value)):
                raise ProtocolError("invalid context hash")

    def payload(self, policy, *, client_id, key_handle, values, offset=0):
        if self.policy_hash != policy.policy_hash:
            raise ProtocolError("context policy mismatch")
        if any(type(v) is not str or not v or len(v) > 128 for v in (client_id, key_handle)):
            raise ProtocolError("invalid client identity/key handle")
        policy.validate_wire(values, offset=offset, full=False)
        return {"protocol": "seed-mpc-v1", "context": asdict(self),
                "client_id": client_id, "key_handle": key_handle,
                "dimension": policy.dimension, "word_bits": policy.word_bits,
                "offset": offset, "values": list(values)}


def reference_aggregate(policy, keys, round_id, rows):
    """Plaintext synthetic oracle, never a production aggregation fallback."""
    if len(keys) != len(rows) or len(rows) > policy.max_clients:
        raise ProtocolError("invalid reference roster")
    count = 0
    total = [0] * policy.dimension
    for key, row in zip(keys, rows, strict=True):
        policy.validate_wire(row)
        masks = mask_words(key, round_id, policy.dimension, policy.word_bits)
        valid = True
        values = []
        for y, m in zip(row, masks, strict=True):
            r = (y - m) % policy.modulus
            positive, negative = r <= policy.coordinate_cap, r >= policy.modulus - policy.coordinate_cap
            ok = positive or negative
            values.append(r - policy.modulus * int(negative) if ok else 0)
            valid = valid and ok
        accepted = valid and sum(v*v for v in values) <= policy.squared_threshold
        count += int(accepted)
        for j, v in enumerate(values):
            total[j] += int(accepted) * v
    if count < policy.minimum_accepted:
        return {"status": "abort"}
    return {"status": "ok", "count": count, "sum": total}
