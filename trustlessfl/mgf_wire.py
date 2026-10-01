"""Deterministic, authenticated round state for bounded-mask MGF.

MGF operates on signed integer vectors, not modular residues. Each update
also carries recipient-encrypted Pedersen shares of its *actual* bounded
mask; aggregate reconstruction subtracts only masks of the certified roster.
This arithmetic does not prove that a malicious client used its HPRF key,
nor does a small bounded mask provide semantic input privacy by itself.
"""

from __future__ import annotations

from fractions import Fraction
from math import isqrt

from .crypto import ProtocolError
from .numeric import MGFIntegerCodec, OUTPUT_MODULUS

_DECIMAL_UNIT = 10**12


def _positive_decimal(value: str, label: str) -> Fraction:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ProtocolError(f"invalid MGF {label}")
    number = MGFIntegerCodec._fraction(value)
    if number <= 0:
        raise ProtocolError(f"invalid MGF {label}")
    return number


def _decimal(value: Fraction) -> str:
    """Round a positive rational to twelve decimal places, ties to even."""
    if value <= 0:
        raise ProtocolError("MGF privacy scale or bound became zero")
    numerator = value.numerator * _DECIMAL_UNIT
    quotient, remainder = divmod(numerator, value.denominator)
    if 2 * remainder > value.denominator or (2 * remainder == value.denominator and quotient % 2):
        quotient += 1
    if quotient == 0:
        raise ProtocolError("MGF privacy scale or bound is below wire precision")
    return f"{quotient // _DECIMAL_UNIT}.{quotient % _DECIMAL_UNIT:012d}".rstrip("0").rstrip(".")


def _nonnegative_decimal(value: str, label: str) -> Fraction:
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise ProtocolError(f"invalid MGF {label}")
    number = MGFIntegerCodec._fraction(value)
    if number < 0:
        raise ProtocolError(f"negative MGF {label}")
    return number


def _norm_decimal(decoded, scale):
    value = Fraction(isqrt(sum(x * x for x in decoded) * _DECIMAL_UNIT**2),
                     _DECIMAL_UNIT * scale)
    return _decimal(value) if value else "0"


def initial_mgf_state(p) -> dict:
    beta = _positive_decimal(p.mgf_beta, "beta")
    if beta >= 1:
        raise ProtocolError("MGF beta must be below one")
    state = {"alpha": p.mgf_initial_alpha, "bound": p.mgf_initial_bound,
             "term": p.mgf_initial_term}
    if p.mgf_artifact_bound:
        state.update(norms=[], mask_linf="1")
    validate_mgf_state(p, state)
    return state


def validate_mgf_state(p, state: dict) -> dict:
    fields = {"alpha", "bound", "term"} | ({"norms", "mask_linf"} if p.mgf_artifact_bound else set())
    if not isinstance(state, dict) or set(state) != fields:
        raise ProtocolError("invalid committed MGF round state")
    alpha = _positive_decimal(state["alpha"], "alpha")
    bound = (_nonnegative_decimal(state["bound"], "bound") if p.mgf_artifact_bound
             else _positive_decimal(state["bound"], "bound"))
    term = _positive_decimal(state["term"], "term")
    if alpha > Fraction(str(p.max_abs)):
        raise ProtocolError("MGF alpha exceeds declared numeric range")
    # The bound and previous-round term are public, consensus-bound values.
    # An arbitrarily large bound weakens filtering, so the setup cap is
    # inherited by every certified successor state.
    max_norm = Fraction(str(p.max_abs)) * (p.mgf_dimension + 1)
    if (not p.mgf_artifact_bound and bound > max_norm) or term > max_norm:
        raise ProtocolError("MGF bound or reference term exceeds declared numeric range")
    if p.mgf_artifact_bound:
        if not isinstance(state["norms"], list) or len(state["norms"]) > 2:
            raise ProtocolError("invalid MGF norm history")
        for value in state["norms"]:
            _nonnegative_decimal(value, "historical norm")
        _nonnegative_decimal(state["mask_linf"], "historical mask norm")
    return state


def evolve_mgf_state(p, state: dict, decoded: list[int], count: int,
                     aggregate_hprf: list[int], *, aggregate_mask: list[int] | None = None) -> dict:
    """Alpha/bound evolution with explicitly selected mask-norm semantics.

    `decoded` is the certified sum of quantized global gradients. The first
    round uses an explicit committed bootstrap term because Algorithm 6 does
    not prescribe one for a zero-valued genesis model.
    With aggregate_mask, use the verified integer sum of bounded wire masks,
    retaining carries and per-client rounding. The protocol supplies this
    already-reconstructed value; no new shares are requested. Omitting it
    retains the literal aggregate-HPRF reference calculation, NOT the actual
    bounded-mask-sum norm used by the author's central learning experiment.
    """
    validate_mgf_state(p, state)
    modulus = p.codec.output_modulus
    if (type(count) is not int or not 2 <= count <= len(p.clients)
            or not isinstance(decoded, list) or len(decoded) != p.mgf_dimension
            or any(type(x) is not int for x in decoded)
            or not isinstance(aggregate_hprf, list) or len(aggregate_hprf) != p.mgf_dimension
            or any(type(h) is not int or not 0 <= h < modulus
                   for h in aggregate_hprf)):
        raise ProtocolError("invalid MGF bound evolution input")
    scale = p.mgf_codec.scale * count
    gradient_norm = Fraction(isqrt(sum(x * x for x in decoded) * _DECIMAL_UNIT**2),
                             _DECIMAL_UNIT * scale)
    if aggregate_mask is None:
        mask_norm = (_positive_decimal(state["alpha"], "alpha")
                     * max(aggregate_hprf) / modulus)
    else:
        check_mgf_aggregate_mask(aggregate_mask, aggregate_hprf, state["alpha"],
                                 count, p.mgf_codec.scale, modulus=modulus)
        mask_norm = Fraction(max(aggregate_mask), p.mgf_codec.scale)
    current_term = gradient_norm + mask_norm
    next_alpha = _positive_decimal(p.mgf_beta, "beta") * max(abs(x) for x in decoded) / scale
    next_bound = (_positive_decimal(state["bound"], "bound") * current_term
                  / _positive_decimal(state["term"], "term"))
    successor = {"alpha": _decimal(next_alpha), "bound": _decimal(next_bound),
                 "term": _decimal(current_term)}
    return validate_mgf_state(p, successor)


def evolve_artifact_state(p, state, decoded, count, selection):
    """Artifact's two-history-norm state, with fixed-point model arithmetic."""
    validate_mgf_state(p, state)
    if (not p.mgf_artifact_bound or type(count) is not int or not 2 <= count <= len(p.clients)
            or not isinstance(decoded, list) or len(decoded) != p.mgf_dimension
            or any(type(value) is not int for value in decoded)):
        raise ProtocolError("invalid artifact MGF aggregate")
    recorded = selection["bound"]
    if "squared_integer" in recorded:
        value = Fraction(isqrt(recorded["squared_integer"] * _DECIMAL_UNIT**2),
                         _DECIMAL_UNIT * p.mgf_codec.scale)
        bound = _decimal(value) if value else "0"
    else:
        bound = recorded["decimal"]
    scale = count * p.mgf_codec.scale
    norm = _norm_decimal(decoded, scale)
    alpha = _positive_decimal(p.mgf_beta, "beta") * max(abs(x) for x in decoded) / scale
    successor = {"alpha": _decimal(alpha), "bound": bound, "term": state["term"],
                 "norms": (state["norms"] + [norm])[-2:],
                 "mask_linf": selection["cohort_mask_linf"]}
    return validate_mgf_state(p, successor)


def check_mgf_aggregate_mask(mask_total: list[int], aggregate_hprf: list[int],
                             alpha: str, count: int, scale: int, *,
                             modulus: int = OUTPUT_MODULUS) -> None:
    """Reject aggregate masks inconsistent with the reconstructed HPRF key.

    Almost key homomorphism holds modulo the configured output ring, while MGF
    sums rounded *bounded* masks as integers. An unknown integer carry of the
    output modulus is therefore allowed. At most `count` HPRF rounding units
    and half a bounded-mask rounding unit per client are tolerated.

    This is an aggregate consistency check, not a proof that every individual
    client used its own HPRF output or trained honestly.
    """
    if (type(modulus) is not int or modulus < 2
            or type(count) is not int or count < 2 or type(scale) is not int or scale < 1
            or not isinstance(mask_total, list) or not isinstance(aggregate_hprf, list)
            or not mask_total or len(mask_total) != len(aggregate_hprf)
            or any(type(value) is not int or value < 0 for value in mask_total)
            or any(type(value) is not int or not 0 <= value < modulus
                   for value in aggregate_hprf)):
        raise ProtocolError("invalid MGF aggregate consistency input")
    amplitude = _positive_decimal(alpha, "alpha") * scale
    tolerance = Fraction(count, 2) + amplitude * count / modulus
    for observed, hprf in zip(mask_total, aggregate_hprf, strict=True):
        base = amplitude * hprf / modulus
        lower = (observed - base) // amplitude
        if not any(-1 <= carry <= count
                   and abs(observed - base - amplitude * carry) <= tolerance
                   for carry in (lower, lower + 1)):
            raise ProtocolError("MGF aggregate mask is inconsistent with HPRF key")
