"""Check algebraic prerequisites of the cited BLMR LWE-HPRF theorem.

Passing these checks does not establish LWE hardness, a concrete security
level, correct public-matrix sampling, or side-channel resistance.
"""

from dataclasses import dataclass

from .crypto import ProtocolError


def ceil_log2(value: int) -> int:
    if type(value) is not int or value < 2:
        raise ProtocolError("modulus must be an integer greater than one")
    return (value - 1).bit_length()


@dataclass(frozen=True)
class LweTheoremParameters:
    """Syntactic and exact-integer error-bound checks, not a security audit.

    The BLMR construction uses m = n*ceil(log2 q) and requires
    alpha*m**input_bits*p to be negligible. `target_bits` makes one concrete
    upper-bound check, but choosing that bound does not prove the underlying
    LWE instance has that many bits of security.
    """

    dimension: int
    width: int
    modulus: int
    output_modulus: int
    input_bits: int
    alpha_numerator: int
    alpha_denominator: int
    target_bits: int

    def _validate_shape(self) -> None:
        integers = (self.dimension, self.width, self.modulus, self.output_modulus,
                    self.input_bits, self.alpha_numerator, self.alpha_denominator,
                    self.target_bits)
        if any(type(value) is not int for value in integers):
            raise ProtocolError("LWE theorem parameters must be integers")
        if (self.dimension < 1 or self.input_bits < 1 or self.target_bits < 1
                or self.alpha_numerator < 1 or self.alpha_denominator < 1
                or not 1 < self.output_modulus < self.modulus):
            raise ProtocolError("invalid LWE theorem parameter domain")
        required = self.dimension * ceil_log2(self.modulus)
        if self.width != required:
            raise ProtocolError(f"LWE key width {self.width} differs from n*ceil(log2 q)={required}")

    def validate(self) -> None:
        self._validate_shape()
        left = (self.alpha_numerator * self.width**self.input_bits
                * self.output_modulus * 2**self.target_bits)
        if left > self.alpha_denominator:
            raise ProtocolError("LWE theorem rounding/noise upper bound is not met")

    def regev_window_possible(self) -> bool:
        """Can any alpha satisfy both checks for this q and target bound?

        This combines the BLMR sufficient alpha upper bound with the Regev
        q > 2*sqrt(n)/alpha condition quoted in the same paper. It is not a
        concrete LWE attack-cost estimate or proof of security.
        """
        self._validate_shape()
        scale = self.width**self.input_bits * self.output_modulus * 2**self.target_bits
        return self.modulus**2 > 4 * self.dimension * scale**2

    def validate_regev_noise_scale(self) -> None:
        """Check a chosen alpha against the paper's quoted Regev reduction."""
        self.validate()
        if (self.alpha_numerator * self.modulus)**2 <= 4 * self.dimension * self.alpha_denominator**2:
            raise ProtocolError("LWE alpha*q is below the Regev reduction condition")


def minimum_regev_window_modulus_bits(dimension: int, output_modulus: int,
                                      input_bits: int, target_bits: int,
                                      *, max_bits: int = 8192) -> int:
    """Lower bound on q bit length before both sufficient inequalities can fit.

    Assumes the largest integer q for each bit length, not a selected prime.
    The resulting width is dimension*bits, and this does not estimate hardness
    or implementation feasibility.
    """
    if (any(type(v) is not int for v in (dimension, output_modulus, input_bits, target_bits, max_bits))
            or dimension < 1 or output_modulus < 2 or input_bits < 1 or target_bits < 1
            or max_bits < 2):
        raise ProtocolError("invalid LWE modulus search parameters")
    for bits in range(max(2, ceil_log2(output_modulus + 1)), max_bits + 1):
        q_max = 2**bits - 1
        scale = (dimension * bits)**input_bits * output_modulus * 2**target_bits
        if q_max**2 > 4 * dimension * scale**2:
            return bits
    raise ProtocolError("no Regev-compatible modulus window within max_bits")


# Values in Aion/agent/Aion/HPRF/init.py. These are an audit fixture only.
AION_ARTIFACT_HPRF = {
    "dimension": 128,
    "width": 512,
    "output_modulus": 95325756275086363396928995575400109969095977033837034603059483527243639993519,
    "modulus": 476628781375431816984644977877000549845479885169185173015297417636218199967595,
}
