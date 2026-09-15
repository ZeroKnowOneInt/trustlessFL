"""Experimental artifact-style rounded linear masking, plus AION DMC/DMR.

The public artifact's scalar, matrix-column-sum construction is reproduced
algebraically. It is NOT a vetted LWE PRF. It must not protect private data.
All modular arithmetic is exact Python integer arithmetic, never NumPy int64.
"""

import hashlib
import math
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_EVEN
from functools import lru_cache

import numpy as np

from .crypto import ORDER, ProtocolError

OUTPUT_MODULUS = 2**128


@lru_cache(maxsize=8192)
def _column(task: str, index: int) -> int:
    # Fixed public matrix represented by its column sums, as in the artifact.
    value = hashlib.shake_256(f"aion/research/matrix/{task}/{index}".encode()).digest(256)
    return int.from_bytes(value, "big") % ORDER


def artifact_mask(key: int, task: str, round_id: int, dimension: int) -> list[int]:
    """Rounded linear key-homomorphic research surrogate (not a secure PRF)."""
    if not 0 <= key < ORDER or round_id < 1 or dimension < 1:
        raise ProtocolError("invalid mask parameters")
    seed = int.from_bytes(hashlib.sha256(f"aion/round/{task}/{round_id}".encode()).digest(), "big")
    return [(((key * seed * _column(task, i)) % ORDER) * OUTPUT_MODULUS + ORDER // 2)
            // ORDER % OUTPUT_MODULUS for i in range(dimension)]


@dataclass(frozen=True)
class FixedPoint:
    decimals: int = 4
    max_abs: float = 100.0
    max_clients: int = 4

    def __post_init__(self):
        if type(self.decimals) is not int or not 0 <= self.decimals <= 9:
            raise ProtocolError("decimals must be an integer in [0, 9]")
        if not math.isfinite(self.max_abs) or self.max_abs <= 0 or self.max_clients < 2:
            raise ProtocolError("invalid numeric bounds")
        if self.max_integer * self.max_clients * self.padding >= OUTPUT_MODULUS // 4:
            raise ProtocolError("encoding exceeds modulus capacity")

    @property
    def scale(self) -> int:
        return 10**self.decimals

    @property
    def padding(self) -> int:
        return 10**len(str(2 * self.max_clients - 1))

    @property
    def max_integer(self) -> int:
        return int(Decimal(str(self.max_abs)) * self.scale)

    def encode(self, values) -> list[int]:
        array = np.asarray(values)
        if array.ndim != 1 or array.dtype.kind not in "fiu" or not np.isfinite(array).all():
            raise ProtocolError("expected a finite, one-dimensional numeric vector")
        if (np.abs(array.astype(float)) > self.max_abs).any():
            raise ProtocolError("local value exceeds encoding bound")
        return [int((Decimal(str(float(x))) * self.scale).to_integral_value(rounding=ROUND_HALF_EVEN))
                for x in array]

    def mask(self, values, key: int, task: str, round_id: int) -> list[int]:
        encoded = self.encode(values)
        masks = artifact_mask(key, task, round_id, len(encoded))
        return [(x * self.padding + h) % OUTPUT_MODULUS for x, h in zip(encoded, masks, strict=True)]

    def unmask(self, total: list[int], key: int, task: str, round_id: int, count: int) -> list[int]:
        if not 2 <= count <= self.max_clients:
            raise ProtocolError("invalid aggregate size")
        masks = artifact_mask(key, task, round_id, len(total))
        result = []
        for y, h in zip(total, masks, strict=True):
            value = (y - h) % OUTPUT_MODULUS
            if value > OUTPUT_MODULUS // 2:
                value -= OUTPUT_MODULUS
            # Nearest integer without decimal-context loss or floating point.
            magnitude = (abs(value) + self.padding // 2) // self.padding
            decoded = magnitude if value >= 0 else -magnitude
            if abs(decoded) > self.max_integer * count:
                raise ProtocolError("aggregate outside declared bound")
            result.append(decoded)
        return result


@dataclass
class MaskedGradientFilter:
    """Standalone Algorithm 6 experiment, not applied to modular wire values.

Bounding a modular field representation is not the paper's real-valued norm
test. Integrating this with the wire backend would change its privacy model.
"""
    bound: float
    beta: float = 0.2

    def __post_init__(self):
        if not math.isfinite(self.bound) or self.bound <= 0 or not 0 < self.beta < 1:
            raise ProtocolError("invalid MGF parameters")

    def alpha(self, previous: np.ndarray, h_max: float) -> float:
        if not np.isfinite(previous).all() or not math.isfinite(h_max) or h_max <= 0:
            raise ProtocolError("invalid MGF scale")
        return self.beta * float(np.linalg.norm(previous, ord=np.inf)) / h_max

    def accepts(self, masked: np.ndarray) -> bool:
        return bool(np.isfinite(masked).all() and np.linalg.norm(masked) <= self.bound)

    def evolve(self, previous: np.ndarray, older: np.ndarray,
               previous_mask: np.ndarray, older_mask: np.ndarray,
               previous_alpha: float, older_alpha: float) -> float:
        numerator = np.linalg.norm(previous) + previous_alpha * np.linalg.norm(previous_mask, ord=np.inf)
        denominator = np.linalg.norm(older) + older_alpha * np.linalg.norm(older_mask, ord=np.inf)
        if not np.isfinite([numerator, denominator]).all() or denominator <= 0 or numerator <= 0:
            raise ProtocolError("undefined MGF bound evolution")
        self.bound *= float(numerator / denominator)
        return self.bound
