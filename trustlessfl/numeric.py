"""Experimental artifact-style rounded linear masking, plus AION DMC/DMR.

The public artifact's scalar, matrix-column-sum construction is reproduced
algebraically. It is NOT a vetted LWE PRF. It must not protect private data.
All modular arithmetic is exact Python integer arithmetic, never NumPy int64.
"""

import hashlib
import math
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_EVEN
from functools import cached_property, lru_cache
from fractions import Fraction

import numpy as np

from .crypto import ORDER, ProtocolError, canonical

OUTPUT_MODULUS = 2**128
# NIST P-192 prime. Kept separate from the 2047-bit Feldman VSS field so
# future LWE parameter sets need not inherit the VSS modulus.
HPRF_MODULUS_192 = 2**192 - 2**64 - 1


# The FMNIST/LeNet5 reference has 61,706 coordinates. A smaller LRU cache
# evicts every public column before the next client evaluates the same mask.
@lru_cache(maxsize=65536)
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


def _rank_mod_q(matrix: tuple[tuple[int, ...], ...], modulus: int) -> int:
    """Rank over the VSS scalar field, used only during public setup."""
    rows = [list(row) for row in matrix]
    width = len(rows)
    rank = 0
    for column in range(width):
        pivot = next((i for i in range(rank, width) if rows[i][column] % modulus), None)
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        inverse = pow(rows[rank][column], -1, modulus)
        rows[rank] = [(v * inverse) % modulus for v in rows[rank]]
        for i in range(rank + 1, width):
            factor = rows[i][column]
            rows[i] = [(a - factor * b) % modulus for a, b in zip(rows[i], rows[rank], strict=True)]
        rank += 1
    return rank


@lru_cache(maxsize=128)
def _binary_matrices(task: str, width: int, modulus: int) -> tuple[tuple[tuple[int, ...], ...], ...]:
    """Deterministic public full-rank binary matrices A0 and A1.

    This is an algebraic reference, not a distribution/parameter validation of
    the Boneh--Lewi--Montgomery--Raghunathan LWE security theorem.
    """
    matrices = []
    for branch in (0, 1):
        for attempt in range(256):
            descriptor = {"domain": "aion/lwe-reference/matrix/v1", "task": task,
                          "width": width, "branch": branch, "attempt": attempt}
            if modulus != ORDER:
                descriptor.update(domain="aion/lwe-reference/matrix/v2", modulus=modulus)
            seed = canonical(descriptor)
            data = hashlib.shake_256(seed).digest((width * width + 7) // 8)
            bits = [(data[i // 8] >> (i % 8)) & 1 for i in range(width * width)]
            matrix = tuple(tuple(bits[i * width:(i + 1) * width]) for i in range(width))
            if _rank_mod_q(matrix, modulus) == width:
                matrices.append(matrix)
                break
        else:
            raise ProtocolError("could not derive full-rank public matrix")
    return tuple(matrices)


def _lwe_input_bits(task: str, round_id: int, block: int, modulus: int,
                    input_bits: int) -> tuple[int, ...]:
    """Map one model block and round into the public PRF input domain."""
    if input_bits == 128:
        if not 1 <= round_id < 1 << 64 or not 0 <= block < 1 << 64:
            raise ProtocolError("LWE-reference round or block exceeds injective input domain")
        point = (round_id << 64) | block
        return tuple((point >> i) & 1 for i in range(128))
    if input_bits != 32:
        raise ProtocolError("invalid LWE-reference input length")
    # Legacy research transcript. SHA-256 truncated to 32 bits can collide
    # across distinct rounds or model blocks.
    descriptor = {"domain": "aion/lwe-reference/input/v1", "task": task,
                  "round": round_id, "block": block}
    if modulus != ORDER:
        descriptor.update(domain="aion/lwe-reference/input/v2", modulus=modulus)
    seed = hashlib.sha256(canonical(descriptor)).digest()
    return tuple((seed[i // 8] >> (i % 8)) & 1 for i in range(32))


def lwe_reference_mask(key: list[int], task: str, round_id: int, dimension: int,
                       modulus: int = ORDER, *, input_bits: int = 128) -> list[int]:
    """Evaluate the paper's rounded binary-matrix product over a vector key.

    The small configurable width is for functional experiments only. No
    concrete LWE hardness or side-channel resistance is claimed.
    """
    if (not isinstance(key, list) or not 2 <= len(key) <= 32
            or modulus not in (ORDER, HPRF_MODULUS_192)
            or any(type(v) is not int or not 0 <= v < modulus for v in key)
            or not isinstance(task, str) or not task or type(round_id) is not int
            or round_id < 1 or type(dimension) is not int or dimension < 1
            or type(input_bits) is not int or input_bits not in (32, 128)):
        raise ProtocolError("invalid LWE-reference mask parameters")
    width = len(key)
    matrices = _binary_matrices(task, width, modulus)
    output = []
    blocks = (dimension + width - 1) // width
    if input_bits == 128 and (round_id >= 1 << 64 or blocks > 1 << 64):
        raise ProtocolError("LWE-reference round or block exceeds injective input domain")
    for block in range(blocks):
        bits = _lwe_input_bits(task, round_id, block, modulus, input_bits)
        values = key[:]
        for bit in reversed(bits):
            values = [sum(a * b for a, b in zip(row, values, strict=True)) % modulus
                      for row in matrices[bit]]
        output.extend((((v * OUTPUT_MODULUS + modulus // 2) // modulus) % OUTPUT_MODULUS)
                      for v in values)
    return output[:dimension]


@dataclass(frozen=True)
class FixedPoint:
    decimals: int = 4
    max_abs: float = 100.0
    max_clients: int = 4
    mask_backend: str = "artifact"
    hprf_width: int = 8
    hprf_input_bits: int | None = None
    original_hprf_setup: tuple[int, ...] = ()

    def __post_init__(self):
        if type(self.decimals) is not int or not 0 <= self.decimals <= 9:
            raise ProtocolError("decimals must be an integer in [0, 9]")
        if not math.isfinite(self.max_abs) or self.max_abs <= 0 or self.max_clients < 2:
            raise ProtocolError("invalid numeric bounds")
        if self.max_integer * self.max_clients * self.padding >= self.output_modulus // 4:
            raise ProtocolError("encoding exceeds modulus capacity")
        if self.mask_backend not in ("artifact", "lwe-reference", "lwe-192-reference", "aion-original") or not 2 <= self.hprf_width <= 32:
            raise ProtocolError("invalid research mask backend")
        if self.mask_backend == "aion-original":
            from .aion_original_hprf import OriginalAionHPRF
            OriginalAionHPRF.from_public_setup(self.original_hprf_setup)
            if self.hprf_input_bits is not None:
                raise ProtocolError("original HPRF uses the author's integer input, not input bits")
        elif self.original_hprf_setup:
            raise ProtocolError("original setup is only valid for aion-original")
        if (self.hprf_input_bits is not None
                and (type(self.hprf_input_bits) is not int
                     or self.hprf_input_bits not in (32, 128))
                or (self.mask_backend == "artifact" and self.hprf_input_bits == 128)):
            raise ProtocolError("invalid research HPRF input length")

    @property
    def effective_hprf_input_bits(self) -> int:
        if self.hprf_input_bits is not None:
            return self.hprf_input_bits
        return 32 if self.mask_backend == "artifact" else 128

    def _mask(self, key, task: str, round_id: int, dimension: int) -> list[int]:
        if self.mask_backend == "aion-original":
            from .aion_original_hprf import OriginalAionHPRF
            # Canonical residue only at the wire boundary, not in raw hprf().
            hprf = OriginalAionHPRF.from_public_setup(self.original_hprf_setup)
            return [h % hprf.p for h in hprf.hprf(key, round_id, dimension)]
        if self.mask_backend == "artifact":
            return artifact_mask(key, task, round_id, dimension)
        if not isinstance(key, list) or len(key) != self.hprf_width:
            raise ProtocolError("wrong vector HPRF key width")
        modulus = HPRF_MODULUS_192 if self.mask_backend == "lwe-192-reference" else ORDER
        return lwe_reference_mask(key, task, round_id, dimension, modulus,
                                  input_bits=self.effective_hprf_input_bits)

    @cached_property
    def output_modulus(self) -> int:
        if self.mask_backend == "aion-original":
            from .aion_original_hprf import OriginalAionHPRF
            return OriginalAionHPRF.from_public_setup(self.original_hprf_setup).p
        return OUTPUT_MODULUS

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
        masks = self._mask(key, task, round_id, len(encoded))
        modulus = self.output_modulus
        return [(x * self.padding + h) % modulus for x, h in zip(encoded, masks, strict=True)]

    def unmask(self, total: list[int], key: int, task: str, round_id: int, count: int) -> list[int]:
        if not 2 <= count <= self.max_clients:
            raise ProtocolError("invalid aggregate size")
        masks = self._mask(key, task, round_id, len(total))
        modulus = self.output_modulus
        result = []
        for y, h in zip(total, masks, strict=True):
            value = (y - h) % modulus
            if value > modulus // 2:
                value -= modulus
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


@dataclass(frozen=True)
class MGFIntegerCodec:
    """Exact bounded-mask arithmetic in the selected HPRF output ring.

    Clients must separately secret-share each quantized mask coordinate.
    This arithmetic alone neither validates that a client used its HPRF key
    nor prevents a malicious client from choosing an inconsistent mask.
    """

    decimals: int = 4
    max_abs: float = 100.0
    max_clients: int = 4
    max_alpha: str = "1"
    hprf_modulus: int = OUTPUT_MODULUS

    def __post_init__(self):
        FixedPoint(self.decimals, self.max_abs, self.max_clients)
        if type(self.hprf_modulus) is not int or self.hprf_modulus < 2:
            raise ProtocolError("invalid MGF HPRF modulus")
        if not 0 < self._fraction(self.max_alpha) <= self.max_abs:
            raise ProtocolError("invalid maximum MGF mask scale")

    @staticmethod
    def _fraction(value: str) -> Fraction:
        if not isinstance(value, str):
            raise ProtocolError("MGF decimal value must be a string")
        try:
            number = Decimal(value)
            if not number.is_finite():
                raise ProtocolError("MGF decimal value must be finite")
            return Fraction(number)
        except (ValueError, ArithmeticError) as exc:
            raise ProtocolError("invalid MGF decimal value") from exc

    @property
    def scale(self) -> int:
        return 10**self.decimals

    @staticmethod
    def _round_ratio(numerator: int, denominator: int) -> int:
        quotient, remainder = divmod(abs(numerator), denominator)
        if 2 * remainder > denominator or (2 * remainder == denominator and quotient % 2):
            quotient += 1
        return quotient if numerator >= 0 else -quotient

    def mask(self, values, hprf_output: list[int], alpha: str) -> tuple[list[int], list[int]]:
        encoded = FixedPoint(self.decimals, self.max_abs, self.max_clients).encode(values)
        fraction = self._fraction(alpha)
        if not 0 < fraction <= self._fraction(self.max_alpha):
            raise ProtocolError("MGF mask scale outside committed range")
        if (not isinstance(hprf_output, list) or len(hprf_output) != len(encoded)
                or any(type(h) is not int or not 0 <= h < self.hprf_modulus for h in hprf_output)):
            raise ProtocolError("invalid MGF HPRF output")
        masks = [self._round_ratio(fraction.numerator * self.scale * h,
                                   fraction.denominator * self.hprf_modulus)
                 for h in hprf_output]
        if not any(masks):
            raise ProtocolError("MGF quantization eliminated the whole mask")
        return [x + m for x, m in zip(encoded, masks, strict=True)], masks

    def accepts(self, masked: list[int], bound: str) -> bool:
        threshold = self._fraction(bound)
        if threshold <= 0:
            raise ProtocolError("MGF bound must be positive")
        if (not isinstance(masked, list) or not masked
                or any(type(value) is not int for value in masked)):
            raise ProtocolError("invalid MGF masked vector")
        max_mask = self._round_ratio(self._fraction(self.max_alpha).numerator * self.scale,
                                     self._fraction(self.max_alpha).denominator)
        limit = FixedPoint(self.decimals, self.max_abs, self.max_clients).max_integer + max_mask
        if any(value < -limit or value > limit for value in masked):
            return False
        return (sum(value * value for value in masked) * threshold.denominator**2
                <= (threshold.numerator * self.scale)**2)

    def recover(self, masked_total: list[int], mask_total: list[int], count: int,
                *, alpha: str | None = None) -> list[int]:
        if (type(count) is not int or not 2 <= count <= self.max_clients
                or not isinstance(masked_total, list) or not isinstance(mask_total, list)
                or not masked_total or len(masked_total) != len(mask_total)):
            raise ProtocolError("invalid MGF aggregate")
        scale = self._fraction(self.max_alpha if alpha is None else alpha)
        if not 0 < scale <= self._fraction(self.max_alpha):
            raise ProtocolError("MGF aggregate mask scale outside declared range")
        max_mask = self._round_ratio(scale.numerator * self.scale, scale.denominator)
        max_value = FixedPoint(self.decimals, self.max_abs, self.max_clients).max_integer
        result = []
        for y, mask in zip(masked_total, mask_total, strict=True):
            if (type(y) is not int or type(mask) is not int
                    or not 0 <= mask <= max_mask * count
                    or abs(y - mask) > max_value * count):
                raise ProtocolError("MGF aggregate outside declared bounds")
            result.append(y - mask)
        return result
