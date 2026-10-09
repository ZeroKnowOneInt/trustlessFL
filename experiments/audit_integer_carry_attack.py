"""Public malicious-wire counterexample to the proposed integer carry codec.

This is an isolated numeric audit, not a Flower attack run. All fixture keys
are public constants. No experiment private state or training input is read.
The codec proposal is not connected to the runtime.
"""

import argparse
import json
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF


def round_nearest(value):
    quotient, remainder = divmod(value.numerator, value.denominator)
    return quotient + (2 * remainder > value.denominator or
                       (2 * remainder == value.denominator and quotient % 2))


def audit(source):
    hprf = OriginalAionHPRF.from_directory(source)
    count, dimension = 20, 8
    radix, guard, multiplier = count + 2, 4 * (count + 1), 20000
    stride = radix * guard
    mask_period = stride * multiplier + guard
    period = Fraction(1, 50)
    unit = period / mask_period
    quantum = stride * unit
    bound = Fraction(1, 10)
    shifts = 5
    wire_shift = shifts * guard
    error = Fraction(mask_period * (count - 1), hprf.p) + Fraction(count + 1, 2)
    assert error < Fraction(guard, 2)

    # All honest model updates are zero; the only change is to one sender's
    # already-masked integer vector. The initial keys and shares do not change.
    masks = [hprf.hprf(key, 4, dimension) for key in range(1, count + 1)]
    aggregate = hprf.hprf(sum(range(1, count + 1)), 4, dimension)
    vectors = [[round_nearest(Fraction(mask_period * value, hprf.p))
                for value in row] for row in masks]
    for row in vectors:
        assert sum((unit * value) ** 2 for value in row) <= bound ** 2
    changed = [value + wire_shift for value in vectors[0]]
    assert sum((unit * value) ** 2 for value in changed) <= bound ** 2

    decoded = []
    for coordinate in range(dimension):
        original_total = sum(row[coordinate] for row in vectors)
        for modification, expected in ((0, 0), (wire_shift, -shifts * multiplier)):
            total = original_total + modification
            residual = total - round_nearest(Fraction(
                mask_period * aggregate[coordinate], hprf.p))
            carry = round_nearest(Fraction(residual, guard)) % radix
            if carry == radix - 1:
                carry = -1
            value = round_nearest(Fraction(residual - carry * mask_period, stride))
            assert -1 <= carry <= count
            assert abs(residual - carry * mask_period - stride * value) <= error
            assert 0 <= total - stride * value <= count * mask_period
            assert value == expected
        decoded.append(value * quantum)
    assert sum(value ** 2 for value in decoded) > bound ** 2
    return dict(
        scope="public numeric counterexample; no certified history or Flower attack run",
        selected_clients=count, dimension=dimension, round=4,
        changed_sender_count=1, wire_change_per_coordinate=str(wire_shift * unit),
        decoded_change_per_coordinate=str(decoded[0]),
        amplification=str(abs(decoded[0] / (wire_shift * unit))),
        same_masked_norm_acceptance=True, decoded_change_norm_exceeds_bound=True,
        carry_residual_and_implied_mask_bounds_pass=True,
        aggregate_key_unchanged=True, additional_client_shares=0,
        proposal_suitable_for_malicious_clients_without_more_checks=False,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("../Aion/agent/Aion/HPRF"))
    args = parser.parse_args()
    print(json.dumps(audit(args.source), indent=2))


if __name__ == "__main__":
    main()
