"""Independent, public-fixture Algorithm 7/8 and MGF unit/order audit.

Deliberately does not call PaperDMC or the Flower numeric decoder. This is
not a runtime backend, privacy proof, or proof that all paper mappings fail.
"""

import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF


def denominator(clients, decimals):
    if (type(clients) is not int or clients < 1 or type(decimals) is not int
            or not 0 <= decimals <= 12):
        raise ValueError("invalid paper decimal parameters")
    extra, power = 0, 1
    while power < 2 * clients:
        extra, power = extra + 1, power * 10
    return 10 ** (decimals + extra)


def rounded(value, decimals):
    # The paper does not specify ties; explicitly use exact half-even here.
    quantum = 10 ** decimals
    return Fraction(round(value * quantum), quantum)


def audit(source, *, clients=20, rounds=4, dimension=8, decimals=6):
    if (any(type(v) is not int for v in (clients, rounds, dimension))
            or not 2 <= clients <= 200 or not 1 <= rounds <= 60
            or not 1 <= dimension <= 840):
        raise ValueError("invalid bounded public audit dimensions")
    source = Path(source)
    hprf = OriginalAionHPRF.from_directory(source)
    d = denominator(clients, decimals)
    # Public, non-random keys; no production key search or Context reads.
    keys = list(range(1, clients + 1))
    magnitude, beta = Fraction(1, 10), Fraction(1, 5)
    native_alpha = beta * magnitude / hprf.p
    normalized_alpha = beta * magnitude / Fraction(hprf.p, d)
    modes = {
        "literal_dmc": (Fraction(1, d), hprf.p, Fraction(1)),
        "native_mgf_then_dmc": (native_alpha / d, hprf.p, native_alpha),
        "dmc_then_normalized_mgf": (normalized_alpha / d, Fraction(hprf.p, d), normalized_alpha),
    }
    rows = {name: dict(hmax=str(hmax), alpha=str(alpha), effective_scale=str(scale),
                      period=str(scale * hprf.p), literal_mismatches=0,
                      decimal_mismatches=0, decimal_plaintext_rounding_matches=0,
                      wire_coordinates=0, centered_verified_coordinates=0,
                      centered_precondition_rejections=0)
            for name, (scale, hmax, alpha) in modes.items()}
    nonzero_carries, first = 0, None
    for r in range(1, rounds + 1):
        masks = [hprf.hprf(k, r, dimension) for k in keys]
        aggregate = hprf.hprf(sum(keys), r, dimension)
        # Grid-aligned signed public models; bound fixed BEFORE decoding.
        models = [[Fraction((i + j + r) % 11 - 5, 1000)
                   for j in range(dimension)] for i in range(clients)]
        bound = Fraction(clients, 200)  # Per-client absolute bound 0.005.
        true_sum = [sum(x[j] for x in models) for j in range(dimension)]
        for j in range(dimension):
            difference = sum(h[j] for h in masks) - aggregate[j]
            carry = round(Fraction(difference, hprf.p))
            error = difference - carry * hprf.p
            if abs(error) > clients - 1:
                raise AssertionError("original centered HPRF error exceeds paper bound")
            nonzero_carries += carry != 0
            if carry and first is None:
                first = dict(round=r, coordinate=j, carry=carry, small_error=error)
        for name, (scale, _, _) in modes.items():
            row, period = rows[name], scale * hprf.p
            exact = [[x + scale * h for x, h in zip(model, mask)]
                     for model, mask in zip(models, masks)]
            wire = [[Fraction(round(y * d), d) for y in vector] for vector in exact]
            total = [sum(vector[j] for vector in exact) for j in range(dimension)]
            total_wire = [sum(vector[j] for vector in wire) for j in range(dimension)]
            residual = [y - scale * h for y, h in zip(total, aggregate)]
            decimal_residual = [y - scale * h for y, h in zip(total_wire, aggregate)]
            row["literal_mismatches"] += sum(rounded(v, decimals) != x
                                             for v, x in zip(residual, true_sum))
            row["decimal_mismatches"] += sum(rounded(v, decimals) != x
                                             for v, x in zip(decimal_residual, true_sum))
            row["wire_coordinates"] += clients * dimension
            row["decimal_plaintext_rounding_matches"] += sum(
                rounded(y, decimals) == x for vector, model in zip(wire, models)
                for y, x in zip(vector, model))
            # Separate modular adaptation; NEVER called literal Algorithm 8.
            error_bound = scale * (clients - 1) + Fraction(clients, 2 * d)
            if bound + error_bound >= period / 2 or error_bound >= Fraction(1, 2 * 10**decimals):
                row["centered_precondition_rejections"] += 1
            else:
                centered = [rounded((v + period / 2) % period - period / 2, decimals)
                            for v in decimal_residual]
                if centered != true_sum:
                    raise AssertionError("bounded independent modular adaptation failed")
                row["centered_verified_coordinates"] += dimension
    return dict(scope="independent exact-rational public mapping audit, not Flower or privacy completion",
                clients=clients, rounds=rounds, dimension=dimension, decimals=decimals,
                denominator=d, public_fixture_keys=keys,
                public_previous_magnitude=str(magnitude), beta=str(beta),
                source_sha256={name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                               for name in ("matrix", "initialization_values")},
                nonzero_carry_coordinates=nonzero_carries, first_carry=first, modes=rows,
                normalized_scale_independent_of_extra_digits=(normalized_alpha / d == native_alpha),
                additional_mask_shares=0, individual_experiment_keys_read=False,
                limitations=["Centering assumes an independent enforced SUM bound.",
                             "Wire rounding recovery is a countercheck, not a security proof.",
                             "These candidate compositions are not an author-confirmed combined wire."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument("--dimension", type=int, default=8)
    parser.add_argument("--decimals", type=int, default=6)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.source, clients=args.clients, rounds=args.rounds,
                   dimension=args.dimension, decimals=args.decimals)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
