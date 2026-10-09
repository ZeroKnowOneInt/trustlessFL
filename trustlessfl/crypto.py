"""Feldman VSS and authenticated, recipient-bound protocol envelopes.

Scalar arithmetic uses the prime-order subgroup of RFC 3526 group 14.
This Python implementation is variable-time and intended for research.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from functools import lru_cache
from math import prod

try:
    from gmpy2 import powmod as _native_powmod
except ImportError:
    _native_powmod = None

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ProtocolError(ValueError):
    """An invalid transcript or unavailable quorum must abort aggregation."""


MODULUS = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF"
    "9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485"
    "B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386B"
    "FB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A"
    "163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3"
    "AD961C62F356208552BB9ED529077096966D670C354E4ABC9804"
    "F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B"
    "2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995"
    "497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
ORDER = (MODULUS - 1) // 2
GENERATOR = 2


def _group_power(base: int, exponent: int) -> int:
    """Use optional GMP arithmetic without changing the VSS group or wire values."""
    if _native_powmod is not None:
        return int(_native_powmod(base, exponent, MODULUS))
    return pow(base, exponent, MODULUS)


# A domain-separated, deterministically derived second subgroup generator.
# Its discrete logarithm relative to GENERATOR is not known to this program.
PEDERSEN_GENERATOR = pow(int.from_bytes(
    hashlib.sha512(b"trustlessfl/aion/pedersen-generator/v1").digest(), "big"),
    2, MODULUS)
if PEDERSEN_GENERATOR in (1, GENERATOR):
    raise RuntimeError("invalid Pedersen generator")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def scalar(value: object) -> int:
    if type(value) is not int or not 0 <= value < ORDER:
        raise ProtocolError("invalid scalar")
    return value


# Fit one 61,706-coordinate commitment matrix at common MGF thresholds so
# vector encryption does not re-check the same subgroup once per recipient.
@lru_cache(maxsize=262144)
def group_element(value: int) -> int:
    if type(value) is not int or not 1 <= value < MODULUS:
        raise ProtocolError("invalid group element")
    if _group_power(value, ORDER) != 1:
        raise ProtocolError("element outside subgroup")
    return value


def split(secret: int, threshold: int, count: int) -> tuple[dict[int, int], list[int]]:
    scalar(secret)
    if not 2 <= threshold <= count < ORDER:
        raise ProtocolError("VSS requires 2 <= threshold <= count")
    coefficients = [secret] + [secrets.randbelow(ORDER) for _ in range(threshold - 1)]
    shares = {}
    for index in range(1, count + 1):
        result = 0
        for coefficient in reversed(coefficients):
            result = (result * index + coefficient) % ORDER
        shares[index] = result
    return shares, [_group_power(GENERATOR, coefficient) for coefficient in coefficients]


def verify_share(index: int, value: int, commitments: list[int]) -> bool:
    try:
        scalar(value)
        if type(index) is not int or not 0 < index < ORDER or len(commitments) < 2:
            return False
        rhs = 1
        for power, commitment in enumerate(commitments):
            rhs = rhs * _group_power(group_element(commitment), pow(index, power, ORDER)) % MODULUS
        return _group_power(GENERATOR, value) == rhs
    except (ValueError, TypeError):
        return False


def aggregate_commitments(commitments: list[list[int]]) -> list[int]:
    if not commitments or len({len(c) for c in commitments}) != 1:
        raise ProtocolError("inconsistent commitment degrees")
    return [prod(group_element(c[k]) for c in commitments) % MODULUS
            for k in range(len(commitments[0]))]


@lru_cache(maxsize=256)
def _lagrange_at_zero(indices: tuple[int, ...]) -> tuple[int, ...]:
    """Cache only public interpolation weights, never shares or verdicts."""
    coefficients = []
    for i in indices:
        coefficient = 1
        for j in indices:
            if j != i:
                coefficient = coefficient * j * pow(j - i, -1, ORDER) % ORDER
        coefficients.append(coefficient)
    return tuple(coefficients)


def reconstruct(shares: dict[int, int], commitments: list[int]) -> int:
    if len(shares) < len(commitments):
        raise ProtocolError("insufficient shares")
    if any(not verify_share(i, value, commitments) for i, value in shares.items()):
        raise ProtocolError("invalid reconstruction share")
    selected = tuple(sorted(shares)[:len(commitments)])
    return sum(coefficient * shares[i] for i, coefficient in
               zip(selected, _lagrange_at_zero(selected), strict=True)) % ORDER


def pedersen_split(secret: int, threshold: int, count: int) -> tuple[dict[int, tuple[int, int]], list[int]]:
    """Hide even a small scalar while allowing each share to be verified.

    Unlike Feldman commitments, these commitments must not expose a bounded
    mask by brute-force enumeration. This is a research primitive, not an
    audited range proof or a complete MGF protocol.
    """
    scalar(secret)
    if not 2 <= threshold <= count < ORDER:
        raise ProtocolError("Pedersen VSS requires 2 <= threshold <= count")
    values = [secret] + [secrets.randbelow(ORDER) for _ in range(threshold - 1)]
    blinds = [secrets.randbelow(ORDER) for _ in range(threshold)]
    commitments = [(_group_power(GENERATOR, a) * _group_power(PEDERSEN_GENERATOR, b)) % MODULUS
                   for a, b in zip(values, blinds, strict=True)]
    shares = {}
    for index in range(1, count + 1):
        value = blind = 0
        for coefficient in reversed(values):
            value = (value * index + coefficient) % ORDER
        for coefficient in reversed(blinds):
            blind = (blind * index + coefficient) % ORDER
        shares[index] = (value, blind)
    return shares, commitments


def pedersen_verify_share(index: int, share: tuple[int, int], commitments: list[int]) -> bool:
    try:
        if (type(index) is not int or not 0 < index < ORDER
                or not isinstance(share, (tuple, list)) or len(share) != 2
                or not isinstance(commitments, list) or len(commitments) < 2):
            return False
        value, blind = scalar(share[0]), scalar(share[1])
        lhs = _group_power(GENERATOR, value) * _group_power(PEDERSEN_GENERATOR, blind) % MODULUS
        rhs = 1
        for power, commitment in enumerate(commitments):
            rhs = rhs * _group_power(group_element(commitment), pow(index, power, ORDER)) % MODULUS
        return lhs == rhs
    except (ValueError, TypeError):
        return False


def pedersen_verify_opening(pair: tuple[int, int], commitments: list[int]) -> bool:
    """Verify an aggregate constant-term opening, not individual key shares."""
    try:
        if (not isinstance(pair, (tuple, list)) or len(pair) != 2
                or not isinstance(commitments, list) or len(commitments) < 2):
            return False
        value, blind = scalar(pair[0]), scalar(pair[1])
        lhs = _group_power(GENERATOR, value) * _group_power(PEDERSEN_GENERATOR, blind) % MODULUS
        return lhs == group_element(commitments[0])
    except (ValueError, TypeError):
        return False


def _pedersen_reconstruction_indices(shares, commitments):
    if len(shares) < len(commitments):
        raise ProtocolError("insufficient Pedersen shares")
    if any(not pedersen_verify_share(i, pair, commitments) for i, pair in shares.items()):
        raise ProtocolError("invalid Pedersen reconstruction share")
    return tuple(sorted(shares)[:len(commitments)])


def pedersen_reconstruct_pair(shares: dict[int, tuple[int, int]], commitments: list[int]) -> tuple[int, int]:
    """Recover the existing shared secret AND its constant-term blinding.

    No fresh sharing is performed. Exposing this opening is appropriate only
    for an already authorized aggregate, not an individual client's secret.
    """
    selected = _pedersen_reconstruction_indices(shares, commitments)
    weights = _lagrange_at_zero(selected)
    pair = tuple(sum(coefficient * shares[i][component] for i, coefficient in
                     zip(selected, weights, strict=True)) % ORDER for component in (0, 1))
    if not pedersen_verify_opening(pair, commitments):
        raise ProtocolError("Pedersen aggregate opening differs from commitments")
    return pair


def pedersen_reconstruct(shares: dict[int, tuple[int, int]], commitments: list[int]) -> int:
    # Preserve the old key-only path's group-arithmetic cost. Only the new
    # authorized aggregate witness needs the second component/opening check.
    selected = _pedersen_reconstruction_indices(shares, commitments)
    return sum(coefficient * shares[i][0] for i, coefficient in
               zip(selected, _lagrange_at_zero(selected), strict=True)) % ORDER


def sum_pedersen_shares(shares: list[tuple[int, int]]) -> tuple[int, int]:
    if not shares:
        raise ProtocolError("empty Pedersen share set")
    if any(not isinstance(pair, (tuple, list)) or len(pair) != 2
           for pair in shares):
        raise ProtocolError("invalid Pedersen share")
    return (sum(scalar(pair[0]) for pair in shares) % ORDER,
            sum(scalar(pair[1]) for pair in shares) % ORDER)


@dataclass
class Identity:
    name: str
    signing: Ed25519PrivateKey
    encryption: X25519PrivateKey

    @classmethod
    def generate(cls, name: str) -> Identity:
        return cls(name, Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    def public(self) -> dict:
        return {"signing": self.signing.public_key().public_bytes_raw().hex(),
                "encryption": self.encryption.public_key().public_bytes_raw().hex()}

    def private(self) -> dict:
        return {"name": self.name, "signing": self.signing.private_bytes_raw().hex(),
                "encryption": self.encryption.private_bytes_raw().hex()}

    @classmethod
    def from_private(cls, data: dict) -> Identity:
        return cls(data["name"], Ed25519PrivateKey.from_private_bytes(bytes.fromhex(data["signing"])),
                   X25519PrivateKey.from_private_bytes(bytes.fromhex(data["encryption"])))

    def sign(self, body: dict) -> dict:
        payload = {"sender": self.name, "body": body}
        return {**payload, "signature": self.signing.sign(canonical(payload)).hex()}


def verify(envelope: dict, registry: dict, *, sender: str | None = None) -> dict:
    try:
        name = envelope["sender"]
        if sender is not None and name != sender:
            raise ProtocolError("unexpected sender")
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(registry[name]["signing"]))
        public.verify(bytes.fromhex(envelope["signature"]),
                      canonical({"sender": name, "body": envelope["body"]}))
        return envelope["body"]
    except Exception as exc:
        raise ProtocolError("signature verification failed") from exc


def _key(shared: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=b"trustlessfl/aion/share/v1/" + aad).derive(shared)


def _pedersen_share_aad(task: str, sender: str, recipient: str, round_id: int,
                        coordinate: int, commitments: list[int]) -> bytes:
    if (not all(isinstance(name, str) and name for name in (task, sender, recipient))
            or type(round_id) is not int or round_id < 1
            or type(coordinate) is not int or coordinate < 0
            or not isinstance(commitments, list) or len(commitments) < 2):
        raise ProtocolError("invalid Pedersen share context")
    for element in commitments:
        group_element(element)
    return canonical({"protocol": "aion-pedersen-mask-share-v1", "task": task,
                      "sender": sender, "recipient": recipient, "round": round_id,
                      "coordinate": coordinate, "commitments": digest(commitments)})


def _pedersen_share_key(shared: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=b"trustlessfl/aion/pedersen-mask-share/v1/" + aad).derive(shared)


def encrypt_pedersen_share(pair: tuple[int, int], recipient_public: str, *, task: str,
                           sender: str, recipient: str, round_id: int,
                           coordinate: int, commitments: list[int]) -> dict:
    """Send a hiding-VSS share only to its pinned recipient and round."""
    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
        raise ProtocolError("invalid Pedersen share")
    value, blind = scalar(pair[0]), scalar(pair[1])
    associated = _pedersen_share_aad(task, sender, recipient, round_id,
                                     coordinate, commitments)
    ephemeral = X25519PrivateKey.generate()
    try:
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_public)))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid Pedersen share recipient") from exc
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_pedersen_share_key(shared, associated)).encrypt(
        nonce, canonical([value, blind]), associated)
    return {"ephemeral": ephemeral.public_key().public_bytes_raw().hex(),
            "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


def decrypt_pedersen_share(packet: dict, identity: Identity, *, task: str,
                           sender: str, round_id: int, coordinate: int,
                           commitments: list[int]) -> tuple[int, int]:
    """Reject a share replayed under another task, sender, round, or coordinate."""
    associated = _pedersen_share_aad(task, sender, identity.name, round_id,
                                     coordinate, commitments)
    try:
        shared = identity.encryption.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(packet["ephemeral"])))
        raw = AESGCM(_pedersen_share_key(shared, associated)).decrypt(
            bytes.fromhex(packet["nonce"]), bytes.fromhex(packet["ciphertext"]), associated)
        pair = json.loads(raw)
        if not isinstance(pair, list) or len(pair) != 2:
            raise ProtocolError("invalid Pedersen share payload")
        return scalar(pair[0]), scalar(pair[1])
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("Pedersen share decryption failed") from exc


def _pedersen_vector_aad(task: str, sender: str, recipient: str, round_id: int,
                         commitments: list[list[int]]) -> bytes:
    if (not all(isinstance(name, str) and name for name in (task, sender, recipient))
            or type(round_id) is not int or round_id < 1
            or not isinstance(commitments, list) or not commitments
            or any(not isinstance(row, list) or len(row) < 2 for row in commitments)
            or len({len(row) for row in commitments}) != 1):
        raise ProtocolError("invalid Pedersen vector context")
    for row in commitments:
        for element in row:
            if type(element) is not int:
                raise ProtocolError("invalid Pedersen vector commitment")
            group_element(element)
    return canonical({"protocol": "aion-pedersen-mask-vector-v2", "task": task,
                      "sender": sender, "recipient": recipient, "round": round_id,
                      "dimension": len(commitments), "commitments": digest(commitments)})


def _pedersen_vector_key(shared: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None,
                info=b"trustlessfl/aion/pedersen-mask-vector/v2/" + aad).derive(shared)


def encrypt_pedersen_vector_shares(pairs: list, recipient_public: str, *, task: str,
                                   sender: str, recipient: str, round_id: int,
                                   commitments: list[list[int]]) -> dict:
    """Encrypt ordered fixed-width shares with one ECDH exchange per recipient."""
    associated = _pedersen_vector_aad(task, sender, recipient, round_id, commitments)
    if (not isinstance(pairs, list) or len(pairs) != len(commitments)
            or any(not isinstance(pair, (list, tuple)) or len(pair) != 2 for pair in pairs)):
        raise ProtocolError("invalid Pedersen vector shares")
    width = (ORDER.bit_length() + 7) // 8
    raw = b"".join(scalar(value).to_bytes(width, "big") for pair in pairs for value in pair)
    ephemeral = X25519PrivateKey.generate()
    try:
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_public)))
    except (TypeError, ValueError) as exc:
        raise ProtocolError("invalid Pedersen vector recipient") from exc
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_pedersen_vector_key(shared, associated)).encrypt(nonce, raw, associated)
    return {"encoding": "pedersen-vector-v2",
            "ephemeral": ephemeral.public_key().public_bytes_raw().hex(),
            "nonce": nonce.hex(), "ciphertext": base64.b64encode(ciphertext).decode("ascii")}


def decrypt_pedersen_vector_shares(packet: dict, identity: Identity, *, task: str,
                                   sender: str, round_id: int,
                                   commitments: list[list[int]]) -> list[tuple[int, int]]:
    """Bind every coordinate, vector length, recipient and round before decoding."""
    associated = _pedersen_vector_aad(task, sender, identity.name, round_id, commitments)
    width = (ORDER.bit_length() + 7) // 8
    expected_size = 2 * width * len(commitments)
    try:
        if (not isinstance(packet, dict)
                or set(packet) != {"encoding", "ephemeral", "nonce", "ciphertext"}
                or packet["encoding"] != "pedersen-vector-v2"
                or not isinstance(packet["ciphertext"], str)
                or len(packet["ciphertext"]) != 4 * ((expected_size + 16 + 2) // 3)):
            raise ProtocolError("invalid Pedersen vector packet")
        shared = identity.encryption.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(packet["ephemeral"])))
        ciphertext = base64.b64decode(packet["ciphertext"], validate=True)
        raw = AESGCM(_pedersen_vector_key(shared, associated)).decrypt(
            bytes.fromhex(packet["nonce"]), ciphertext, associated)
        if len(raw) != expected_size:
            raise ProtocolError("invalid Pedersen vector payload")
        return [(scalar(int.from_bytes(raw[offset:offset + width], "big")),
                 scalar(int.from_bytes(raw[offset + width:offset + 2 * width], "big")))
                for offset in range(0, len(raw), 2 * width)]
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise ProtocolError("Pedersen vector decryption failed") from exc


def encrypt_share(value: int, recipient_public: str, aad: dict) -> dict:
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_public)))
    associated = canonical(aad)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_key(shared, associated)).encrypt(nonce, canonical(value), associated)
    return {"ephemeral": ephemeral.public_key().public_bytes_raw().hex(),
            "nonce": nonce.hex(), "ciphertext": ciphertext.hex()}


def decrypt_share(packet: dict, identity: Identity, aad: dict) -> int:
    try:
        shared = identity.encryption.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(packet["ephemeral"])))
        associated = canonical(aad)
        raw = AESGCM(_key(shared, associated)).decrypt(
            bytes.fromhex(packet["nonce"]), bytes.fromhex(packet["ciphertext"]), associated)
        return scalar(json.loads(raw))
    except Exception as exc:
        raise ProtocolError("share decryption failed") from exc
