"""Capacity/MGF tradeoff for one scaled masked vector, using public fixtures.

This is an offline diagnostic. It does not change a Flower manifest, rescale
live updates, or infer private values. The sufficient capacity bounds below
are specifically for centered decoding, not impossibility bounds for every
decoder. HPRF and transport rounding are accounted for separately.
"""

import argparse
import json
import random
from fractions import Fraction
from pathlib import Path

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.paper_dmc import PaperDMC, rational, select_masked


SOURCE = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"


def capacity_envelope(codec, selected_count, update_bound):
    """Coordinate update bound is independent of the observed masked vector.

    Wire error <= n/(2D), HPRF error <= E, P=coefficient*p/D.
    n*B + P*E/p + n/(2D) < P/2.
    The strict lower P limit is solved exactly, including P-dependent error.
    """
    if (type(selected_count) is not int or not 2 <= selected_count <= codec.clients
            or rational(update_bound) < 0):
        raise ValueError("invalid selected count or update bound")
    count, bound = selected_count, rational(update_bound)
    error = (count + 2) // 2  # ceil((n+1)/2), conservative nearest-round bound
    slope = Fraction(1, 2) - Fraction(error, codec.modulus)
    if slope <= 0:
        raise ValueError("HPRF error exhausts centered modulus capacity")
    wire_error = Fraction(count, 2 * codec.denominator)
    total_error = codec.period * error / codec.modulus + wire_error
    strict_minimum = (count * bound + wire_error) / slope
    max_client_bound = (codec.period * slope - wire_error) / count
    return dict(
        selected_count=count, update_bound=str(bound), period=str(codec.period),
        hprf_error_bound=error, wire_rounding_error=str(wire_error),
        total_error_bound=str(total_error),
        minimum_period_exclusive=str(strict_minimum),
        maximum_client_bound_exclusive=str(max_client_bound),
        capacity_safe=codec.period > strict_minimum,
        quantization_safe=total_error < Fraction(1, 2 * 10**codec.decimals),
    )


def from_period(base, period):
    """Explicit comparison candidate, NOT the original beta scaling rule."""
    return PaperDMC(base.clients, base.decimals, base.modulus,
                    rational(period) * base.denominator / base.modulus)


def grid_alias_profile(codec, selected_count):
    """Public scale diagnostic; it does not decide the unknown mask carry.

    P*S=a/b in lowest terms: changing carry by b changes the decoded model
    sum by exactly a model quanta. Physical mask limits may still rule out
    that candidate, so grid aliasing alone is NOT a runtime failure verdict.
    """
    if type(selected_count) is not int or not 2 <= selected_count <= codec.clients:
        raise ValueError("invalid selected count")
    ratio = codec.period * 10**codec.decimals
    width = selected_count + 1  # difference between -1 and selected_count
    return dict(period_in_model_quanta=str(ratio),
                indistinguishable_carry_spacing=ratio.denominator,
                corresponding_sum_shift=str(ratio.denominator * codec.period),
                grid_alias_possible_in_carry_interval=ratio.denominator <= width,
                every_unbounded_carry_has_grid_partner=codec.unbounded_grid_collision(selected_count),
                verdict="grid arithmetic only; physical mask bounds and actual residual still required")


def audit(source=SOURCE, *, clients=20, dimension=8, seed=20261008):
    if (type(clients) is not int or clients < 2 or type(dimension) is not int
            or not 1 <= dimension <= 4096):
        raise ValueError("invalid fixture size")
    hprf = OriginalAionHPRF.from_directory(source)
    base = PaperDMC(clients, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    update_bound, mgf_bound = Fraction(1, 100), Fraction(1, 10)
    rng = random.Random(seed)
    keys = [rng.randint(1, 100000) for _ in range(clients)]
    masks = [hprf.hprf(k, 4, dimension) for k in keys]
    aggregate = hprf.hprf(sum(keys), 4, dimension)
    # Deliberately aligned positive updates exercise the worst-case SUM.
    updates = [[update_bound] * dimension for _ in keys]
    original_envelope = capacity_envelope(base, clients, update_bound)
    # Factor-two capacity margin; beta changes and must be reported explicitly.
    proposed_period = max(base.period, 2 * Fraction(original_envelope["minimum_period_exclusive"]))
    raised = from_period(base, proposed_period)
    rows = []
    for label, codec in (("original-scale", base), ("capacity-raised-scale", raised)):
        wire = [codec.mask_decimal_wire(x, h) for x, h in zip(updates, masks, strict=True)]
        total = [sum(v[j] for v in wire) for j in range(dimension)]
        expected = [clients * update_bound] * dimension
        center_only = [codec.quantize((r + codec.period / 2) % codec.period - codec.period / 2)
                       for r in codec.residual_modulo(total, aggregate)]
        envelope = capacity_envelope(codec, clients, update_bound)
        if envelope["capacity_safe"] and envelope["quantization_safe"]:
            assert codec.remove_centered(total, aggregate, sum_bound=clients * update_bound,
                       selected_count=clients, decimal_wire=True) == expected
        squares = [sum(x*x for x in row) for row in wire]
        rows.append(dict(profile=label, **envelope,
            effective_beta=str(codec.period / Fraction(1, 10)),
            same_scale_for_filter_and_sum=True,
            mgf_bound=str(mgf_bound), accepted_clients=len(select_masked(wire, mgf_bound)),
            min_masked_norm_squared=str(min(squares)),
            max_masked_norm_squared=str(max(squares)),
            sum_coordinate=str(expected[0]), center_decoded_coordinate=str(center_only[0]),
            centered_mismatches=sum(a != b for a, b in zip(expected, center_only, strict=True))))

    # The original scale CAN be used by restricting honest updates. Quantify
    # the required clipping instead of silently applying it to training.
    restricted = max(Fraction(0), Fraction(original_envelope["maximum_client_bound_exclusive"]) / 2)
    restricted = base.quantize(restricted)
    clipped = [[min(x, restricted) for x in row] for row in updates]
    clipped_wire = [base.mask_decimal_wire(x, h) for x, h in zip(clipped, masks, strict=True)]
    clipped_total = [sum(v[j] for v in clipped_wire) for j in range(dimension)]
    recovered = base.remove_centered(clipped_total, aggregate, sum_bound=clients * restricted,
                                    selected_count=clients, decimal_wire=True)
    assert recovered == [clients * restricted] * dimension
    return dict(scope="public fixture feasibility only; no Flower or learning-quality claim",
                p=hprf.p, q=hprf.q, clients=clients, dimension=dimension, seed=seed,
                initial_scale_magnitude="0.1", fixture_update_bound=str(update_bound),
                profiles=rows,
                restricted_update_candidate=dict(per_client_bound=str(restricted),
                    original_sum_coordinate=str(clients * update_bound),
                    clipped_sum_coordinate=str(recovered[0]),
                    retained_update_fraction=str(restricted / update_bound),
                    exact_recovery=True, changes_training_updates=True),
                conclusion="Neither candidate preserves both the original scale policy and unrestricted updates.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--clients", type=int, default=20)
    parser.add_argument("--dimension", type=int, default=8)
    args = parser.parse_args()
    print(json.dumps(audit(args.source, clients=args.clients, dimension=args.dimension), indent=2))


if __name__ == "__main__":
    main()
