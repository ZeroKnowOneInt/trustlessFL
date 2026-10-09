"""Public, deterministic arithmetic audit; NOT an AMR or ZKP implementation.

No actor state, private experiment inputs, Flower traffic, or live shares are
read. The original author matrix is read-only. Synthetic polynomial values
model the arithmetic of aggregate shares, not encrypted/Pedersen VSS execution.
The matched-q variant is a diagnostic ring, not the deployed sharing field or
a claim that Shamir sharing over this composite modulus is secure.
"""

import argparse
import hashlib
import json
from fractions import Fraction
from math import gcd
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ORDER


def center(value, modulus):
    value %= modulus
    return value - modulus if 2 * value > modulus else value


def round_integer(value, divisor):
    """Nearest integer, ties to even; valid recovery never reaches a tie."""
    quotient, remainder = divmod(value, divisor)
    return quotient + (2 * remainder > divisor or
                       (2 * remainder == divisor and quotient % 2))


def capacity(modulus, delta, count, coordinate_bound, error):
    if (any(type(v) is not int for v in
            (modulus, delta, count, coordinate_bound)) or
            modulus < 3 or delta < 1 or count < 1 or coordinate_bound < 0):
        raise ValueError("invalid capacity parameters")
    error = Fraction(error)
    if error < 0:
        raise ValueError("negative error bound")
    return dict(
        rounding_safe=delta > 2 * error,
        signed_capacity_safe=modulus > 2 * (delta * count * coordinate_bound + error),
    )


def lagrange(indices, modulus):
    """Centered integer lifts of modular coefficients, no rational division."""
    if (not indices or len(set(indices)) != len(indices) or
            any(type(i) is not int or not 0 < i < modulus for i in indices)):
        raise ValueError("invalid interpolation indices")
    weights = []
    for i in indices:
        weight = 1
        for j in indices:
            if i != j:
                weight = weight * j * pow(j - i, -1, modulus) % modulus
        weights.append(center(weight, modulus))
    return weights


def public_slope(count, modulus):
    # Fixed across rounds: these are one-time-sharing arithmetic fixtures.
    label = f"trustlessfl/public-split-wire-amr/v1/{count}".encode()
    length = (modulus.bit_length() + 7) // 8
    return int.from_bytes(hashlib.shake_256(label).digest(length), "big") % modulus


def inverse_scalar_outputs(hprf, round_id, outputs):
    """Recover candidates modulo q from PUBLIC scalar-artifact outputs only.

    This attacks the author's scalar adapter, NOT vector-key BLMR. It uses an
    invertible public coefficient, enumerates its small rounding interval, and
    checks further coordinates. No secret or small-key prior is an argument.
    Zero ring outputs also allow raw h=p, as in the original implementation.
    """
    candidates = None
    used = []
    for j, output in enumerate(outputs):
        if type(output) is not int or not 0 <= output < hprf.p:
            raise ValueError("expected canonical public ring output")
        coefficient = ((round_id + j // hprf.m) *
                       hprf.column_sums[j % hprf.m]) % hprf.q
        if candidates is None:
            if gcd(coefficient, hprf.q) != 1:
                continue
            inv = pow(coefficient, -1, hprf.q)
            candidates = set()
            for raw in ([0, hprf.p] if output == 0 else [output]):
                low = max(0, -(-(raw * hprf.q - hprf.q // 2) // hprf.p))
                high = min(hprf.q - 1,
                           ((raw + 1) * hprf.q - hprf.q // 2 - 1) // hprf.p)
                if high - low + 1 > 4096:
                    raise ValueError("rounding interval outside this small public audit")
                candidates.update(t * inv % hprf.q for t in range(low, high + 1))
        else:
            candidates = {key for key in candidates if
                          (((key * coefficient % hprf.q) * hprf.p +
                            hprf.q // 2) // hprf.q) % hprf.p == output}
        used.append(j)
        if len(candidates) <= 1:
            break
    return dict(candidates=None if candidates is None else sorted(candidates),
                coordinate_indices=used)


def binding_counterexample():
    p, delta, scale = 101, 8, 10
    z, h = [2, 3], [80, 70]
    mask_sum = sum(h) % p
    honest = [(delta * a + b) % p for a, b in zip(z, h)]
    forged = [(honest[0] + delta) % p, honest[1]]
    decode = lambda wire: Fraction(round_integer(center(sum(wire) - mask_sum, p), delta), scale)
    return dict(honest_wire=honest, forged_wire=forged,
                honest_sum=str(decode(honest)), forged_sum=str(decode(forged)),
                proven_z_unchanged=True, aggregate_key_unchanged=True,
                capacity=capacity(p, delta, 2, 3, 1),
                note="arithmetic witness only; no ZKP generated")


def subset_difference_counterexample():
    keys = [31337, 64221, 7849, 83937]  # Public fixtures only.
    before, after = sum(keys) % ORDER, sum(keys[:3]) % ORDER
    return dict(before_roster=[1, 2, 3, 4], after_roster=[1, 2, 3],
                recovered_removed_key=(before - after) % ORDER,
                expected_removed_key=keys[3], rejoining_required=False)


def relaxed_l2_counterexample(hprf):
    # Valid nonzero author-profile keys. Twenty malicious clients each shift
    # ONE h coordinate by 10, keeping z, t, w and the committed key unchanged.
    count, malicious, dimension, delta = 100, 20, 100000, 202
    per_client_shift, round_id = 10, 4
    keys = [1 + (7919 * i + 31336) % 100000 for i in range(count)]
    residual_bound_squared = Fraction(dimension * hprf.q * hprf.q, 12)
    ratios, exact_rounding_failures = [], 0
    for key in keys[:malicious]:
        masks = hprf.hprf(key, round_id, dimension)
        assert masks[0] + per_client_shift < hprf.p
        energy = 0
        for j, value in enumerate(masks):
            t = (key * (round_id + j // hprf.m) *
                 hprf.column_sums[j % hprf.m]) % hprf.q
            changed = value + (per_client_shift if j == 0 else 0)
            residual = hprf.q * changed - hprf.p * t
            energy += residual * residual
            exact_rounding_failures += int(j == 0 and abs(residual) > hprf.q // 2)
        ratios.append(energy / residual_bound_squared)
    honest_residual = center(sum(hprf.hprf(key, round_id, 1)[0] for key in keys) -
                             hprf.hprf(sum(keys), round_id, 1)[0], hprf.p)
    forged_sum = round_integer(center(honest_residual + malicious * per_client_shift,
                                     hprf.p), delta)
    return dict(clients=count, malicious_clients=malicious, dimension=dimension, delta=delta,
                per_client_mask_shift=per_client_shift,
                relaxed_residual_norm_passes=all(ratio <= 1 for ratio in ratios),
                maximum_squared_norm_ratio=str(max(ratios)),
                actual_per_coordinate_rounding_bound_passes=exact_rounding_failures == 0,
                exact_rounding_rejects_clients=exact_rounding_failures,
                honest_decoded_z_sum=round_integer(honest_residual, delta),
                decoded_z_sum=forged_sum, proven_z_sum=0,
                note="public original-HPRF fixture; relaxed predicate only, not a ZKP or Flower attack")


def arithmetic_audit(hprf):
    dimension, bound = 32, 1000000
    variants = [("asr_control", None, ())]
    variants += [(f"{name}_{a}_{b}", modulus, (a, b))
                 for name, modulus in (("current_order", ORDER), ("matched_q_ring", hprf.q))
                 for a, b in ((1, 2), (1, 3), (2, 3))]
    rows = {name: dict(coordinates=0, exact_coordinates=0, max_abs_error=0,
                       fixed_delta_certified_cases=0, cases=[])
            for name, _, _ in variants}
    wrapped = 0
    for count in (2, 20, 100):
        keys = [1 + (7919 * i + 31336) % 100000 for i in range(count)]
        key_sum = sum(keys)
        delta = 2 * count + 2  # Fixed BEFORE errors are observed.
        for round_id in (1, 4, 60):
            z = [[((i + 1) * 123457 + (j + 1) * 65537 + round_id * 17) %
                  (2 * bound + 1) - bound for j in range(dimension)]
                 for i in range(count)]
            masks = [hprf.hprf(key, round_id, dimension) for key in keys]
            expected = [sum(row[j] for row in z) for j in range(dimension)]
            mask_sums = [sum(row[j] for row in masks) for j in range(dimension)]
            wrapped += sum(value >= hprf.p for value in mask_sums)
            wires = [sum((delta * z[i][j] + masks[i][j]) % hprf.p
                         for i in range(count)) % hprf.p for j in range(dimension)]
            for name, modulus, indices in variants:
                weights = []
                if modulus is None:
                    reconstructed = hprf.hprf(key_sum, round_id, dimension)
                    error_bound = Fraction(count + 1, 2)
                else:
                    weights = lagrange(indices, modulus)
                    slope = public_slope(count, modulus)
                    shares = [(key_sum + slope * index) % modulus for index in indices]
                    assert sum(w * s for w, s in zip(weights, shares)) % modulus == key_sum
                    share_masks = [hprf.hprf(s, round_id, dimension) for s in shares]
                    reconstructed = [sum(w * row[j] for w, row in zip(weights, share_masks)) %
                                     hprf.p for j in range(dimension)]
                    # This bound requires interpolation in the HPRF key ring.
                    error_bound = (Fraction(count + sum(map(abs, weights)), 2)
                                   if modulus == hprf.q else None)
                errors = [center(mask_sums[j] - reconstructed[j], hprf.p)
                          for j in range(dimension)]
                if error_bound is not None:
                    assert max(map(abs, errors)) <= error_bound
                decoded = [round_integer(center(wires[j] - reconstructed[j], hprf.p), delta)
                           for j in range(dimension)]
                exact = sum(a == b for a, b in zip(expected, decoded))
                checks = (None if error_bound is None else
                          capacity(hprf.p, delta, count, bound, error_bound))
                required_delta = (None if error_bound is None else int(2 * error_bound) + 1)
                feasible = (None if error_bound is None else all(capacity(
                    hprf.p, required_delta, count, bound, error_bound).values()))
                row = rows[name]
                row["coordinates"] += dimension
                row["exact_coordinates"] += exact
                row["max_abs_error"] = max(row["max_abs_error"], max(map(abs, errors)))
                row["fixed_delta_certified_cases"] += int(checks is not None and all(checks.values()))
                row["cases"].append(dict(clients=count, round=round_id, delta=delta,
                    weights=weights, exact_coordinates=exact, max_abs_error=max(map(abs, errors)),
                    error_bound=None if error_bound is None else str(error_bound),
                    fixed_delta_checks=checks, minimum_delta_for_stated_bound=required_delta,
                    minimum_delta_fits_capacity=feasible))
    try:
        lagrange((1, 6), hprf.q)
        nonunit_rejected = False
    except ValueError:
        nonunit_rejected = True
    return dict(dimension_per_case=dimension, coordinate_bound=bound,
                real_mask_sum_wrap_coordinates=wrapped, variants=rows,
                matched_q_indices_1_6_nonunit_rejected=nonunit_rejected)


def output_inversion_audit(hprf):
    fixtures = [31337, hprf.q // 2 + 12345, hprf.q - 1234567]
    records = []
    for key in fixtures:
        outputs = [v % hprf.p for v in hprf.hprf(key, 4, 32)]
        result = inverse_scalar_outputs(hprf, 4, outputs)
        records.append(dict(expected_key_mod_q=key % hprf.q, **result,
                            exact=result["candidates"] == [key % hprf.q]))
    # Even when AMR broadcasts ONLY H(sum_share, r), this scalar artifact's
    # invertibility defeats the matched-q diagnostic variant's key privacy.
    keys = [31337, 64221, 7849, 83937]
    slopes = [public_slope(i + 1, hprf.q) for i in range(len(keys))]
    recovered = []
    for selected, round_id in ((range(4), 4), (range(3), 7)):
        share_candidates = []
        for index in (1, 2):
            share = sum(keys[i] + slopes[i] * index for i in selected) % hprf.q
            outputs = [v % hprf.p for v in hprf.hprf(share, round_id, 32)]
            result = inverse_scalar_outputs(hprf, round_id, outputs)
            share_candidates.append(result["candidates"])
        if any(candidates is None or len(candidates) != 1 for candidates in share_candidates):
            recovered.append(None)
        else:
            recovered.append(sum(w * values[0] for w, values in
                                 zip(lagrange((1, 2), hprf.q), share_candidates)) % hprf.q)
    return dict(public_output_fixtures=records, key_range_prior_used=False,
                matched_q_amr_recovered_sum_keys=recovered,
                matched_q_amr_removed_key=(None if None in recovered else
                                          (recovered[0] - recovered[1]) % hprf.q),
                expected_removed_key=keys[3],
                applies_to="original scalar artifact; NOT general vector-key LWE/BLMR")


def audit(source):
    source = Path(source)
    hprf = OriginalAionHPRF.from_directory(source)
    return dict(scope="public numerical audit only; no ZKP, Flower, VSS traffic or Byzantine AMR",
                parameters=dict(p=hprf.p, q=hprf.q, sharing_order_bits=ORDER.bit_length()),
                source_sha256={name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                               for name in ("matrix", "initialization_values")},
                binding_attack=binding_counterexample(),
                permanent_exclusion=subset_difference_counterexample(),
                relaxed_l2=relaxed_l2_counterexample(hprf),
                arithmetic=arithmetic_audit(hprf),
                scalar_output_inversion=output_inversion_audit(hprf),
                runtime_changed=False, production_security_claim=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    args = parser.parse_args()
    print(json.dumps(audit(args.source), indent=2))


if __name__ == "__main__":
    main()
