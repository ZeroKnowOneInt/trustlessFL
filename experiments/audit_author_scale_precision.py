"""Compare author float32 norm and post-scaling wire precision on public fixtures.

No private state, training shards, additional shares or alpha perturbations.
These are numeric candidates, not an exact E2 or paper end-to-end reproduction.
"""

import argparse
import json
import random
from fractions import Fraction
from pathlib import Path
from math import gcd
from dataclasses import dataclass

import numpy as np

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC


@dataclass(frozen=True)
class FinitePrecisionDMC(PaperDMC):
    transport_extra_digits: int = 0

    @property
    def denominator(self):
        return super().denominator * 10**self.transport_extra_digits


def finite_precision_audit(source, *, rounds=10, dimension=32, extra_digits=8):
    """Offline finite post-scale rounding candidate; NOT a privacy proof."""
    if not 0 <= extra_digits <= 12 or rounds < 1 or dimension < 1:
        raise ValueError("invalid finite wire audit settings")
    hprf = OriginalAionHPRF.from_directory(source)
    results = {}
    for fp32 in (False, True):
        magnitude = Fraction(253, 40000)
        if fp32:
            magnitude = Fraction(float(np.float32(float(magnitude))))
        for count in (2, 4, 10):
            base = PaperDMC(20, 6, hprf.p).with_mgf(magnitude, hmax_domain="normalized")
            codec = FinitePrecisionDMC(20, 6, hprf.p, base.coefficient * 10**extra_digits,
                                      transport_extra_digits=extra_digits)
            assert codec.period == base.period
            rng = random.Random(20261001)
            keys = [rng.randint(1, 100000) for _ in range(count)]
            row = dict(verified_rounds=0, rejected_rounds=0, wrong_accepted_rounds=0,
                       wire_denominator=codec.denominator, public_norm=str(magnitude))
            for r in range(1, rounds + 1):
                models = [[Fraction(rng.randint(-10000, 10000), 10**6)
                           for _ in range(dimension)] for _ in keys]
                wire = [codec.mask_decimal_wire(x, hprf.hprf(k, r, dimension))
                        for k, x in zip(keys, models)]
                total = [sum(v[j] for v in wire) for j in range(dimension)]
                expected = [sum(v[j] for v in models) for j in range(dimension)]
                try:
                    actual = codec.remove_quantized_lift(total, hprf.hprf(sum(keys), r, dimension),
                        selected_count=count, decimal_wire=True)
                except ProtocolError:
                    row["rejected_rounds"] += 1
                else:
                    row["verified_rounds" if actual == expected else "wrong_accepted_rounds"] += 1
            results[f"fp32={fp32}/n={count}"] = row
    return dict(scope="finite wire precision fixture; not Flower learning or privacy proof",
                transport_extra_digits=extra_digits, rounds=rounds, dimension=dimension,
                additional_mask_shares=0, results=results)


def recover_public_exact_wire(wire, codec):
    """Recover individual encoded updates using ONLY public numeric parameters.

    Exact wire Y = E*x + C*h; gcd cancellation reveals h modulo E/gcd(E,C).
    Return None where multiple h representatives fit [0,p], never choose one.
    This audit attack is not a decoder to use in a private aggregation path.
    """
    denominator = codec.denominator * codec.coefficient.denominator
    model_step = denominator // 10**codec.decimals
    coefficient = codec.coefficient.numerator
    common = gcd(model_step, coefficient)
    residue_modulus = model_step // common
    inverse = pow(coefficient // common, -1, residue_modulus)
    result = []
    for value in wire:
        transmitted = value * denominator
        if transmitted.denominator != 1 or transmitted.numerator % common:
            raise ProtocolError("wire is not an exact-scale integer representative")
        transmitted = transmitted.numerator
        mask = (transmitted // common * inverse) % residue_modulus
        if mask > codec.modulus:
            raise ProtocolError("public residue exceeds mask range")
        if mask + residue_modulus <= codec.modulus:
            result.append(None)
        else:
            result.append((transmitted - coefficient * mask) // model_step)
    return result


def audit(source, *, rounds=10, dimension=32):
    if rounds < 1 or dimension < 1:
        raise ValueError("positive fixture dimensions required")
    hprf = OriginalAionHPRF.from_directory(source)
    results = {}
    for name, magnitude in (("committed_failure", Fraction(253, 40000)),
                            ("previous_false_rejection", Fraction(59, 80000))):
        for fp32 in (False, True):
            public_norm = Fraction(float(np.float32(float(magnitude)))) if fp32 else magnitude
            for rounded_wire in (False, True):
                for count in (2, 4, 10):
                    codec = PaperDMC(20, 6, hprf.p).with_mgf(public_norm, hmax_domain="normalized")
                    rng = random.Random(20261001)
                    keys = [rng.randint(1, 100000) for _ in range(count)]
                    row = dict(public_norm=str(public_norm), verified_rounds=0,
                               rejected_rounds=0, wrong_accepted_rounds=0,
                               keyless_individual_coordinates_recovered=0,
                               keyless_attack_coordinates_tested=0)
                    for r in range(1, rounds + 1):
                        models = [[Fraction(rng.randint(-10000, 10000), 10**6)
                                   for _ in range(dimension)] for _ in keys]
                        method = codec.mask_decimal_wire if rounded_wire else codec.mask
                        wire = [method(x, hprf.hprf(k, r, dimension)) for k, x in zip(keys, models)]
                        if not rounded_wire:
                            for vector, model in zip(wire, models):
                                plain = recover_public_exact_wire(vector, codec)
                                row["keyless_attack_coordinates_tested"] += dimension
                                for got, expected_value in zip(plain, model):
                                    if got is not None:
                                        if Fraction(got, 10**codec.decimals) != expected_value:
                                            raise AssertionError("public cancellation recovered a wrong update")
                                        row["keyless_individual_coordinates_recovered"] += 1
                        total = [sum(v[j] for v in wire) for j in range(dimension)]
                        expected = [sum(v[j] for v in models) for j in range(dimension)]
                        try:
                            actual = codec.remove_quantized_lift(total,
                                hprf.hprf(sum(keys), r, dimension), selected_count=count,
                                decimal_wire=rounded_wire)
                        except ProtocolError:
                            row["rejected_rounds"] += 1
                        else:
                            row["verified_rounds" if actual == expected else "wrong_accepted_rounds"] += 1
                    results[f"{name}/fp32={fp32}/rounded-wire={rounded_wire}/n={count}"] = row
    return dict(scope="public numeric precision audit, not Flower learning or privacy proof",
                rounds=rounds, dimension=dimension, additional_mask_shares=0, results=results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--dimension", type=int, default=32)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--finite-extra-digits", type=int,
                        help="Offline finite rounded wire candidate, not exact-rational wire")
    args = parser.parse_args()
    result = (audit(args.source, rounds=args.rounds, dimension=args.dimension)
              if args.finite_extra_digits is None else finite_precision_audit(args.source,
                  rounds=args.rounds, dimension=args.dimension, extra_digits=args.finite_extra_digits))
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
