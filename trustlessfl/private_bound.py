"""No-wrap integer policy and explicit plaintext specification of private filtering.

This is NOT an MPC backend. The default aggregation mode fails closed. Only
``mode="plaintext-reference"`` evaluates private values in Python. Never send
individual offsets/masks/keys to the Flower coordinator to use this model.
Application widths are separate from cryptographic backend field/ring sizes.
"""
from dataclasses import dataclass
from fractions import Fraction

from .crypto import ProtocolError
from .paper_dmc import round_even


class PrivateBackendUnavailable(ProtocolError):
    """A private input/MPC implementation is required before live execution."""


def _integer(value, minimum=0):
    if type(value) is not int or value < minimum:
        raise ProtocolError("invalid public integer parameter")
    return value


def scale_canonical_mask(h, p, M):
    _integer(p, 2)
    _integer(M, 1)
    if type(h) is not int or not 0 <= h < p:
        raise ProtocolError("invalid canonical HPRF representative")
    return (2 * M * h + p) // (2 * p)


@dataclass(frozen=True)
class NoWrapPolicy:
    dimension: int
    max_clients: int
    coordinate_cap: int
    scale: int
    spacing: int
    mask_max: int
    squared_bound: int
    minimum_accepted: int = 2
    output: str = "sum-and-count"

    def __post_init__(self):
        for value in (self.dimension, self.max_clients, self.coordinate_cap,
                      self.scale, self.spacing, self.mask_max, self.minimum_accepted):
            _integer(value, 1)
        _integer(self.squared_bound)
        if (self.squared_bound > self.norm_cap or
                self.minimum_accepted > self.max_clients or
                self.output not in ("sum-and-count", "mean-only")):
            raise ProtocolError("invalid no-wrap policy")

    @property
    def norm_cap(self):
        return self.dimension * self.coordinate_cap**2

    @property
    def offset_max(self):
        return self.mask_max + 2 * self.spacing * self.coordinate_cap

    def widths(self):
        return {
            "offset_unsigned": self.offset_max.bit_length(),
            "residual_signed": 1 + (self.mask_max + self.spacing*self.coordinate_cap).bit_length(),
            "update_signed": 1 + self.coordinate_cap.bit_length(),
            "norm_unsigned": self.norm_cap.bit_length(),
            "sum_signed": 1 + (self.max_clients*self.coordinate_cap).bit_length(),
            "count_unsigned": self.max_clients.bit_length(),
        }

    def mask_scale_numerator_bits(self, p):
        _integer(p, 2)
        return (2*self.mask_max*(p-1) + p).bit_length()

    def _vector(self, values):
        if (not isinstance(values, (tuple, list)) or len(values) != self.dimension
                or any(type(value) is not int for value in values)):
            raise ProtocolError("invalid integer vector shape or type")

    def encode(self, update, masks):
        """Client-side integer encoding; not a proof of an honest update."""
        self._vector(update)
        self._vector(masks)
        if any(abs(u) > self.coordinate_cap for u in update):
            raise ProtocolError("client update exceeds coordinate cap")
        if any(not 0 <= m <= self.mask_max for m in masks):
            raise ProtocolError("invalid scaled mask representative")
        # No clipping, float conversion, modular reduction, or silent truncation.
        return tuple(self.spacing*u + m + self.spacing*self.coordinate_cap
                     for u, m in zip(update, masks, strict=True))


@dataclass(frozen=True)
class ReferenceSubmission:
    offsets: tuple[int, ...]
    masks: tuple[int, ...]


def _decode_reference(policy, offsets, masks):
    policy._vector(offsets)
    policy._vector(masks)
    if any(not 0 <= m <= policy.mask_max for m in masks):
        raise ProtocolError("reference requires exact registered-key masks")
    bit_max = 1 << policy.widths()["offset_unsigned"]
    if any(not 0 <= v < bit_max for v in offsets):
        raise ProtocolError("invalid canonical bitstring framing")
    update = []
    valid = True
    for v, m in zip(offsets, masks, strict=True):
        wire_ok = v <= policy.offset_max
        safe_v = v if wire_ok else policy.spacing*policy.coordinate_cap
        residual = safe_v - policy.spacing*policy.coordinate_cap - m
        quotient, remainder = divmod(abs(residual), policy.spacing)
        coordinate_ok = wire_ok and remainder == 0 and quotient <= policy.coordinate_cap
        # Check the FULL quotient before narrowing or squaring; sanitize invalids.
        u = (-quotient if residual < 0 else quotient) if coordinate_ok else 0
        update.append(u)
        valid = valid and coordinate_ok
    squared_norm = sum(u*u for u in update)
    assert squared_norm <= policy.norm_cap
    return update, valid and squared_norm <= policy.squared_bound


def aggregate(policy, submissions, *, mode="mpc"):
    """Specify permitted output. Live private execution is intentionally unavailable.

    Reference masks are supplied in clear solely for mathematical tests. They
    are NOT a share/key binding proof. An actual backend must privately import
    the registered keys and authenticate client inputs before computing them.
    """
    if mode == "mpc":
        raise PrivateBackendUnavailable(
            "this aggregation API has no authenticated MPC backend configured; "
            "no plaintext fallback is permitted")
    if mode != "plaintext-reference":
        raise ProtocolError("unsupported execution mode")
    if (not isinstance(policy, NoWrapPolicy) or
            not isinstance(submissions, (tuple, list)) or len(submissions) > policy.max_clients):
        raise ProtocolError("invalid reference cohort")
    total = [0]*policy.dimension
    count = 0
    for submission in submissions:
        if not isinstance(submission, ReferenceSubmission):
            raise ProtocolError("invalid reference submission")
        update, accepted = _decode_reference(policy, submission.offsets, submission.masks)
        count += int(accepted)
        total = [value + int(accepted)*u for value, u in zip(total, update, strict=True)]
    assert all(abs(value) <= policy.max_clients*policy.coordinate_cap for value in total)
    if count < policy.minimum_accepted:
        return {"status": "abort"}
    if policy.output == "mean-only":
        return {"status": "ok", "mean": tuple(round_even(Fraction(value, count)) for value in total)}
    return {"status": "ok", "sum": tuple(total), "count": count}


@dataclass(frozen=True)
class PublicRound:
    round_id: int
    integer_mean: tuple[int, ...]
    squared_bound: int


@dataclass(frozen=True)
class DynamicBound:
    boot: int
    minimum: int
    maximum: int
    epsilon_squared: int = 1
    ratio_minimum: Fraction = Fraction(1, 4)
    ratio_maximum: Fraction = Fraction(4)

    def __post_init__(self):
        for value in (self.boot, self.minimum, self.maximum, self.epsilon_squared):
            _integer(value, 1)
        if not self.minimum <= self.boot <= self.maximum:
            raise ProtocolError("invalid dynamic boundary range")
        for value in (self.ratio_minimum, self.ratio_maximum):
            if type(value) not in (int, Fraction):
                raise ProtocolError("dynamic ratios must be exact rationals")
        if not 0 < self.ratio_minimum <= 1 <= self.ratio_maximum:
            raise ProtocolError("invalid dynamic boundary ratio")

    def next_threshold(self, policy, successful_history):
        """Public arbitrary-precision arithmetic; history needs external certificates.

        Only successful aggregate outputs enter history. Abort keeps prior
        state; average-only output uses its published rounded mean directly.
        Do not run this repeatedly on the same frozen inputs with new bounds.
        """
        if (not isinstance(successful_history, (tuple, list)) or len(successful_history) > 2
                or self.maximum > policy.norm_cap):
            raise ProtocolError("invalid dynamic boundary safety envelope")
        previous_id = 0
        for item in successful_history:
            if not isinstance(item, PublicRound):
                raise ProtocolError("invalid public history record")
            _integer(item.round_id, 1)
            _integer(item.squared_bound, 1)
            policy._vector(item.integer_mean)
            if (item.round_id <= previous_id or
                    not self.minimum <= item.squared_bound <= self.maximum or
                    any(abs(u) > policy.coordinate_cap for u in item.integer_mean)):
                raise ProtocolError("invalid public history bounds or order")
            previous_id = item.round_id
        if len(successful_history) < 2:
            return self.boot
        old, new = successful_history
        old_norm = sum(u*u for u in old.integer_mean)
        new_norm = sum(u*u for u in new.integer_mean)
        ratio = Fraction(new_norm+self.epsilon_squared, old_norm+self.epsilon_squared)
        ratio = min(self.ratio_maximum, max(self.ratio_minimum, ratio))
        return min(self.maximum, max(self.minimum, round_even(new.squared_bound*ratio)))
