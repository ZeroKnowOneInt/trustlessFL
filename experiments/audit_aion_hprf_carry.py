"""Reproducible arithmetic audit, not a new protocol or security backend.

Run from the repository root with its dependencies on PYTHONPATH. The author
tree and the existing runtime codec remain read-only. All keys here are public
test fixtures; no live client secrets are inspected.
"""

import argparse
import importlib.util
import json
import random
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.numeric import FixedPoint
from trustlessfl.paper_dmc import PaperDMC


SOURCE = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"


def center(value, modulus):
    """Match FixedPoint: even moduli retain the positive midpoint.

    Odd p: [-floor(p/2), floor(p/2)]. Even p: (-p/2, p/2].
    Strict capacity bounds below exclude the ambiguous even midpoint.
    """
    if type(value) is not int or type(modulus) is not int or modulus < 2:
        raise ValueError("integer value and modulus >= 2 required")
    residue = value % modulus
    return residue - modulus if residue > modulus // 2 else residue


def encode(value, scale):
    """Exact decimal-spelling input convention, ties-to-even quantization."""
    if type(scale) is not int or scale <= 0:
        raise ValueError("positive integer scale required")
    rational = value if isinstance(value, Fraction) else Fraction(str(value))
    return round(rational * scale)


def decode(value, scale):
    if type(value) is not int or type(scale) is not int or scale <= 0:
        raise ValueError("integer value and positive integer scale required")
    return Fraction(value, scale)


def feasibility(modulus, max_clients, integer_bound, error_bound):
    """Strict inequalities, using integers only (no approximate p/2)."""
    if any(type(x) is not int for x in
           (modulus, max_clients, integer_bound, error_bound)):
        raise ValueError("integer parameters required")
    if modulus < 2 or max_clients < 1 or integer_bound < 1 or error_bound < 0:
        raise ValueError("invalid capacity parameters")
    minimum = 2 * error_bound + 1
    maximum = (modulus - 1 - 2 * error_bound) // (2 * max_clients * integer_bound)
    return {"minimum_delta": minimum, "maximum_delta": maximum,
            "feasible": minimum <= maximum}


def check_capacity(modulus, delta, max_clients, integer_bound, error_bound):
    limits = feasibility(modulus, max_clients, integer_bound, error_bound)
    if type(delta) is not int or not limits["minimum_delta"] <= delta <= limits["maximum_delta"]:
        raise ValueError("infeasible delta: rounding or centered capacity bound")
    return limits


def modular_reference(encoded, masks, aggregate_mask, *, modulus, delta,
                      max_clients, integer_bound, error_bound):
    """Independent bounded reference for unweighted integer SUM, not MGF.

    Client-side bounds are necessary: a wrapped residue alone cannot reveal
    whether an out-of-range plaintext was encoded. This is not a malicious-
    client range proof or a replacement for protocol authentication.
    """
    check_capacity(modulus, delta, max_clients, integer_bound, error_bound)
    count = len(encoded)
    if not 1 <= count <= max_clients or len(masks) != count:
        raise ValueError("invalid participation count")
    dimension = len(aggregate_mask)
    if (any(len(v) != dimension for v in [*encoded, *masks])
            or any(type(z) is not int or abs(z) > integer_bound for v in encoded for z in v)
            or any(type(h) is not int for v in [*masks, aggregate_mask] for h in v)):
        raise ValueError("invalid shape, integer type or update bound")
    wire = [[(delta * z + h) % modulus for z, h in zip(zs, hs, strict=True)]
            for zs, hs in zip(encoded, masks, strict=True)]
    total = [sum(v) % modulus for v in zip(*wire, strict=True)]
    return [round(Fraction(center(c - h, modulus), delta))
            for c, h in zip(total, aggregate_mask, strict=True)]


def decomposition(hprf, keys, round_id, masks, aggregate, coordinate):
    """Derive e independently from internal q-domain wrap and rounding.

    This does NOT merely define e as D mod p and assume it is small.
    q-domain linearity gives sum(t_i)=t_A+u*q; each rounding residual is
    bounded by 1/2. Canonicalization changes only the p-multiple carry.
    """
    block, column = divmod(coordinate, hprf.m)
    coefficient = hprf.column_sums[column]
    t = [(k * (round_id + block) % hprf.q) * coefficient % hprf.q for k in keys]
    ta = (sum(keys) * (round_id + block) % hprf.q) * coefficient % hprf.q
    assert (sum(t) - ta) % hprf.q == 0
    u = (sum(t) - ta) // hprf.q
    raw = [v[coordinate] for v in masks]
    ha = aggregate[coordinate]
    raw_difference = sum(raw) - ha
    error = raw_difference - u * hprf.p
    assert 2 * abs(error) <= len(keys) + 1
    difference = sum(h % hprf.p for h in raw) - ha % hprf.p
    carry = u - sum(h // hprf.p for h in raw) + ha // hprf.p
    assert difference == carry * hprf.p + error
    assert center(difference, hprf.p) == error
    return difference, carry, error, raw_difference


def audit(source=SOURCE, trials=8, seed=20261008):
    port = OriginalAionHPRF.from_directory(source)
    spec = importlib.util.spec_from_file_location("carry_audit_author", source / "hprf.py")
    author_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(author_module)
    author = author_module.HPRF(port.n, port.m, port.p, port.q, str(source / "matrix"))
    rng = random.Random(seed)
    codec = FixedPoint(decimals=6, max_abs=10.0, max_clients=100,
                       mask_backend="aion-original", original_hprf_setup=port.public_setup())
    # ceil((N+1)/2), independently derived from N+1 nearest-round residuals.
    error_bound = (codec.max_clients + 2) // 2
    limits = check_capacity(port.p, codec.padding, codec.max_clients,
                            codec.max_integer, error_bound)
    report = dict(seed=seed, trials_per_count=trials, p=port.p, q=port.q,
                  scale=codec.scale, delta=codec.padding, error_bound=error_bound,
                  max_clients=codec.max_clients, integer_bound=codec.max_integer,
                  capacity=limits, checked_coordinates=0, carry_coordinates=0,
                  observed_max_error=0, integer_mismatches=0, author_mismatches=0,
                  maximum_quantization_error="0", maximum_float_mean_error=0.0,
                  carry_example=None, nonzero_error_example=None)
    max_quantization = Fraction(0)
    for count in (2, 3, 4, 20, 100):
        for trial in range(trials):
            keys = [rng.randint(1, 100000) for _ in range(count)]
            round_id = rng.randint(1, 1000)
            # Cross a block boundary; include one full FMNIST-sized vector.
            dimension = 61706 if count == 4 and trial == 0 else 1025
            masks = [port.hprf(k, round_id, dimension) for k in keys]
            aggregate = port.hprf(sum(keys), round_id, dimension)
            for key, expected in zip([*keys, sum(keys)], [*masks, aggregate], strict=True):
                assert expected == author.hprf(key, round_id, dimension)
            updates = [[Fraction(rng.randint(-10000000, 10000000), 1000000)
                        + Fraction(rng.randint(-49, 49), 100000000)
                        for _ in range(dimension)] for _ in keys]
            # Keep generated inputs inside the declared client bound.
            updates = [[max(Fraction(-10), min(Fraction(10), x)) for x in v] for v in updates]
            encoded = [[encode(x, codec.scale) for x in v] for v in updates]
            plain = [sum(v) for v in zip(*encoded, strict=True)]
            recovered = modular_reference(encoded, masks, aggregate, modulus=port.p,
                delta=codec.padding, max_clients=100, integer_bound=codec.max_integer,
                error_bound=error_bound)
            # Exercise the existing runtime, not just a fresh reference formula.
            wire = [[(codec.padding * z + h) % port.p for z, h in zip(zs, hs, strict=True)]
                    for zs, hs in zip(encoded, masks, strict=True)]
            total = [sum(v) % port.p for v in zip(*wire, strict=True)]
            runtime = codec.unmask(total, sum(keys), "carry-audit", round_id, count)
            assert plain == recovered == runtime
            for j in range(dimension):
                d, carry, error, raw_d = decomposition(port, keys, round_id, masks, aggregate, j)
                report["checked_coordinates"] += 1
                report["carry_coordinates"] += carry != 0
                report["observed_max_error"] = max(report["observed_max_error"], abs(error))
                if (carry and report["carry_example"] is None
                        or error and report["nonzero_error_example"] is None):
                    example = dict(keys=keys, round=round_id, coordinate=j,
                                   masks=[v[j] for v in masks], aggregate_mask=aggregate[j],
                                   difference=d, raw_difference=raw_d, carry=carry, error=error,
                                   plaintext_sum=plain[j], recovered_sum=runtime[j])
                    if carry and report["carry_example"] is None:
                        report["carry_example"] = example
                    if error and report["nonzero_error_example"] is None:
                        report["nonzero_error_example"] = example
                for v, zs in zip(updates, encoded, strict=True):
                    max_quantization = max(max_quantization, abs(decode(zs[j], codec.scale) - v[j]))
                # Ordinary float FedAvg reference; conversion only after the
                # integer modular path has completed.
                float_mean = sum(float(v[j]) for v in updates) / count
                reconstructed_mean = decode(runtime[j], codec.scale * count)
                report["maximum_float_mean_error"] = max(report["maximum_float_mean_error"],
                    abs(float_mean - float(reconstructed_mean)))
    report["maximum_quantization_error"] = str(max_quantization)
    # Literal DMC/DMR fails on the reproduced carry, without floating-point noise.
    ex = report["carry_example"]
    dmc = PaperDMC(len(ex["keys"]), 6, port.p)
    masked = [dmc.mask([0], [h])[0] for h in ex["masks"]]
    report["literal_dmr_zero_sum_result"] = str(dmc.remove([sum(masked)], [ex["aggregate_mask"]])[0])
    report["safe_capacity_lhs"] = codec.padding * codec.max_clients * codec.max_integer + error_bound
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--trials", type=int, default=8)
    parser.add_argument("--seed", type=int, default=20261008)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error("trials must be positive")
    print(json.dumps(audit(args.source, args.trials, args.seed), indent=2))


if __name__ == "__main__":
    main()
