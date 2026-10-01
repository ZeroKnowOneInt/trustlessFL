"""Exact numerical reference for paper Algorithms 6, 7 and 8.

No keys or masks are shared here. Fractions isolate representation errors
from modular carry. This is an audit reference, NOT a production backend.
The paper does not specify a combined MGF/DMC wire encoding; we explicitly
test both raw and DMC-normalized meanings of h_max instead of conflating them.
"""

from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction

from .crypto import ProtocolError


class QuantizedLiftError(ProtocolError):
    """Public-safe numerical failure category, never coordinates or values."""

    CODES = frozenset({"precision", "no-candidate", "ambiguous"})

    def __init__(self, code, message):
        if code not in self.CODES:
            raise ValueError("unknown quantized lift failure category")
        self.code = code
        super().__init__(message)


def rational(value):
    # Decimal spelling, not a binary-float mantissa, is the reference input.
    try:
        return Fraction(str(value)) if not isinstance(value, Fraction) else value
    except (ValueError, ZeroDivisionError) as exc:
        raise ProtocolError("invalid finite rational") from exc


def round_even(value):
    value = rational(value)
    lower, remainder = divmod(value.numerator, value.denominator)
    twice = remainder * 2
    return lower + (twice > value.denominator or
                    (twice == value.denominator and lower % 2 == 1))


@dataclass(frozen=True)
class PaperDMC:
    clients: int
    decimals: int
    modulus: int
    coefficient: Fraction = Fraction(1)

    def __post_init__(self):
        if (type(self.clients) is not int or self.clients < 1 or
                type(self.decimals) is not int or not 0 <= self.decimals <= 12 or
                type(self.modulus) is not int or self.modulus < 3):
            raise ProtocolError("invalid DMC parameters")
        object.__setattr__(self, "coefficient", rational(self.coefficient))
        if self.coefficient <= 0:
            raise ProtocolError("DMC coefficient must be positive")

    @property
    def extra_digits(self):
        # ceil(log10(2q)), without a floating-point logarithm boundary.
        digits, power = 0, 1
        while power < 2 * self.clients:
            digits, power = digits + 1, power * 10
        return digits

    @property
    def denominator(self):
        return 10 ** (self.decimals + self.extra_digits)

    @property
    def period(self):
        return self.coefficient * self.modulus / self.denominator

    def quantize(self, value):
        scale = 10 ** self.decimals
        return Fraction(round_even(rational(value) * scale), scale)

    def unbounded_grid_collision(self, selected_count):
        """Grid collision if physical mask-sum bounds are NOT imposed.

        If period/model_quantum = a/b in lowest terms, shifting carry by b
        changes the decoded sum by exactly a model quanta. Our candidate carry
        interval [-1,n] has n+2 integers. When n+2 >= 2b, EVERY carry has a
        partner +/-b in that interval, with identical distance to the grid.
        Actual masks must ALSO lie in [0,n*max_mask]. This criterion alone
        cannot justify rejecting a round: the paired candidate may violate
        those bounds. It is retained as a diagnostic for the old decoder.
        """
        if type(selected_count) is not int or not 1 <= selected_count <= self.clients:
            raise ProtocolError("invalid selected count for grid collision check")
        step = (self.period * 10 ** self.decimals).denominator
        return selected_count + 2 >= 2 * step

    def mask(self, model, hprf):
        if len(model) != len(hprf):
            raise ProtocolError("DMC dimension mismatch")
        if any(type(h) is not int or not 0 <= h <= self.modulus for h in hprf):
            raise ProtocolError("invalid original HPRF representative")
        return [self.quantize(x) + self.coefficient * h / self.denominator
                for x, h in zip(model, hprf, strict=True)]

    def remove(self, masked_sum, aggregate_hprf):
        """Literal Algorithm 8 subtraction and rounding, no carry oracle."""
        return [self.quantize(x) for x in self.residual(masked_sum, aggregate_hprf)]

    def residual(self, masked_sum, aggregate_hprf):
        if len(masked_sum) != len(aggregate_hprf):
            raise ProtocolError("DMR dimension mismatch")
        if any(type(h) is not int or not 0 <= h <= self.modulus for h in aggregate_hprf):
            raise ProtocolError("invalid aggregate HPRF representative")
        return [rational(y) - self.coefficient * h / self.denominator
                for y, h in zip(masked_sum, aggregate_hprf, strict=True)]

    def remove_centered(self, masked_sum, aggregate_hprf, *, sum_bound):
        """Explicit modular adaptation; not literal Algorithm 8.

        A caller must supply an independent bound on each true SUM coordinate.
        Reject ambiguous configurations BEFORE reading the masked sum.
        """
        bound = rational(sum_bound)
        error_bound = self.coefficient * (self.clients - 1) / self.denominator
        if bound < 0 or bound + error_bound >= self.period / 2:
            raise ProtocolError("scaled ring lacks unique bounded sum lift")
        if error_bound >= Fraction(1, 2 * 10 ** self.decimals):
            raise ProtocolError("scaled rounding error exceeds DMC precision")
        return [self.quantize((v + self.period / 2) % self.period - self.period / 2)
                for v in self.residual(masked_sum, aggregate_hprf)]

    def mask_decimal_wire(self, model, hprf):
        """Single masked view at DMC decimal precision; no auxiliary shares."""
        return [Fraction(round_even(v * self.denominator), self.denominator)
                for v in self.mask(model, hprf)]

    def remove_quantized_lift(self, masked_sum, aggregate_hprf, *, selected_count,
                              decimal_wire=False):
        """Experimental numeric adaptation, NOT literal paper Algorithm 8.

        Enumerate bounded carries and keep only residuals consistent with the
        known model quantization AND implied nonnegative bounded mask sum.
        Never infer an individual key/update and never
        choose between ambiguous sums. Decimal wire rounding adds its own error
        bound. Correctness assumes compliant HPRF masks and model quantization;
        there is no malicious-input proof or production privacy claim.
        """
        if type(selected_count) is not int or not 1 <= selected_count <= self.clients:
            raise ProtocolError("invalid selected count for quantized lift")
        error = self.coefficient * (selected_count - 1) / self.denominator
        if decimal_wire:
            error += Fraction(selected_count, 2 * self.denominator)
        if error >= Fraction(1, 2 * 10 ** self.decimals):
            raise QuantizedLiftError("precision", "quantized lift error exceeds model precision")
        result = []
        # A candidate update sum implies mask_total = transmitted_sum-sum.
        # Each compliant HPRF mask is nonnegative and bounded by coefficient*p.
        # Decimal-wire rounding is monotone; use its exact rounded endpoint.
        mask_limit = (Fraction(selected_count * round_even(self.coefficient * self.modulus),
                               self.denominator) if decimal_wire
                      else selected_count * self.period)
        residuals = self.residual(masked_sum, aggregate_hprf)
        for transmitted, residual in zip(masked_sum, residuals, strict=True):
            candidates = set()
            for carry in range(-1, selected_count + 1):
                value = residual - carry * self.period
                rounded = self.quantize(value)
                implied_mask = rational(transmitted) - rounded
                if abs(value - rounded) <= error and 0 <= implied_mask <= mask_limit:
                    candidates.add(rounded)
            if not candidates:
                raise QuantizedLiftError("no-candidate", "no quantized sum lift fits the numerical error bound")
            if len(candidates) != 1:
                raise QuantizedLiftError("ambiguous", "ambiguous quantized sum lift")
            result.append(candidates.pop())
        return result

    def with_mgf(self, previous_linf, *, beta="0.2", hmax_domain):
        """Make h_max's units explicit when combining Algorithms 6 and 7.

        normalized: hmax=p/D, so alpha/D=beta*linf/p.
        raw: hmax=p, so alpha/D=beta*linf/(p*D).
        Both are candidate interpretations, NOT claimed author wire formats.
        """
        magnitude, beta = rational(previous_linf), rational(beta)
        if magnitude <= 0 or beta <= 0:
            raise ProtocolError("MGF scaling needs positive public magnitude and beta")
        if hmax_domain not in ("raw", "normalized"):
            raise ProtocolError("unknown h_max domain")
        hmax = Fraction(self.modulus, self.denominator if hmax_domain == "normalized" else 1)
        return PaperDMC(self.clients, self.decimals, self.modulus, beta * magnitude / hmax)


def select_masked(vectors, bound):
    """Algorithm 6's inclusive L2 test, with no plaintext input/percentile override."""
    bound = rational(bound)
    if bound < 0:
        raise ProtocolError("invalid MGF bound")
    return [i for i, vector in enumerate(vectors)
            if sum((rational(x) ** 2 for x in vector), Fraction(0)) <= bound ** 2]


def public_mgf_term(public_sum, aggregate_hprf, codec):
    """Algorithm 6 history term from PUBLIC aggregate, never private updates.

    General Euclidean norms are irrational; sqrt uses 60 decimal digits.
    All mask scaling and bound-ratio operations otherwise retain fractions.
    This term is for a SUM, not the mean a training optimizer may consume.
    """
    if len(public_sum) != len(aggregate_hprf) or not public_sum:
        raise ProtocolError("MGF public history dimension mismatch")
    # Reuse validation of the original output representatives.
    codec.residual([0] * len(aggregate_hprf), aggregate_hprf)
    squared = sum((rational(x) ** 2 for x in public_sum), Fraction(0))
    with localcontext() as context:
        context.prec = 60
        norm = rational((Decimal(squared.numerator) / Decimal(squared.denominator)).sqrt())
    mask_linf = codec.coefficient * max(aggregate_hprf) / codec.denominator
    return norm + mask_linf


def evolve_bound(previous_bound, *, older_term, newer_term):
    """Algorithm 6: b_r=b_(r-1)*term_(r-1)/term_(r-2).

    Caller supplies two committed historical terms, not the current candidate
    norm or a single previous mask norm reused in both slots. No implicit
    bootstrap percentile, clipping, min-selection or mean conversion.
    """
    bound, older, newer = map(rational, (previous_bound, older_term, newer_term))
    if bound < 0 or older <= 0 or newer < 0:
        raise ProtocolError("invalid MGF historical terms")
    return bound * newer / older
