"""Feldman VSS and authenticated, recipient-bound protocol envelopes.

Scalar arithmetic uses the prime-order subgroup of RFC 3526 group 14.
This Python implementation is variable-time and intended for research.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from functools import lru_cache
from math import prod

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


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def scalar(value: object) -> int:
    if type(value) is not int or not 0 <= value < ORDER:
        raise ProtocolError("invalid scalar")
    return value


@lru_cache(maxsize=8192)
def group_element(value: int) -> int:
    if type(value) is not int or not 1 <= value < MODULUS:
        raise ProtocolError("invalid group element")
    if pow(value, ORDER, MODULUS) != 1:
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
    return shares, [pow(GENERATOR, coefficient, MODULUS) for coefficient in coefficients]


def verify_share(index: int, value: int, commitments: list[int]) -> bool:
    try:
        scalar(value)
        if type(index) is not int or not 0 < index < ORDER or len(commitments) < 2:
            return False
        rhs = 1
        for power, commitment in enumerate(commitments):
            rhs = rhs * pow(group_element(commitment), pow(index, power, ORDER), MODULUS) % MODULUS
        return pow(GENERATOR, value, MODULUS) == rhs
    except (ValueError, TypeError):
        return False


def aggregate_commitments(commitments: list[list[int]]) -> list[int]:
    if not commitments or len({len(c) for c in commitments}) != 1:
        raise ProtocolError("inconsistent commitment degrees")
    return [prod(group_element(c[k]) for c in commitments) % MODULUS
            for k in range(len(commitments[0]))]


def reconstruct(shares: dict[int, int], commitments: list[int]) -> int:
    if len(shares) < len(commitments):
        raise ProtocolError("insufficient shares")
    if any(not verify_share(i, value, commitments) for i, value in shares.items()):
        raise ProtocolError("invalid reconstruction share")
    selected = sorted(shares)[:len(commitments)]
    result = 0
    for i in selected:
        coefficient = 1
        for j in selected:
            if j != i:
                coefficient = coefficient * j * pow(j - i, -1, ORDER) % ORDER
        result = (result + coefficient * shares[i]) % ORDER
    return result


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
