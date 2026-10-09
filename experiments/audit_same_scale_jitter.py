"""Evaluate a tiny downward scale adjustment without changing model precision.

Public original-HPRF fixtures only. This candidate stays outside the runtime.
Besides honest recovery, test a single malicious wire under unchanged keys:
successful honest decoding is insufficient to establish MGF bound semantics.
"""

import argparse
import json
from fractions import Fraction
from math import gcd, isqrt
from pathlib import Path

from experiments.audit_author_scale_precision import FinitePrecisionDMC
from experiments.audit_same_scale_feasibility import SOURCE, grid_alias_profile
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.paper_dmc import PaperDMC, QuantizedLiftError, round_even, select_masked


def candidate(base):
    """P'=a/(S*K), gcd(a,K)=1, K=N+2, 0<P'<=P.

    The allowable carry interval has width N+1<K. Each carry has a distinct
    phase on the model quantization grid. Total numerical error must be less
    than half its minimum phase separation 1/(S*K).
    """
    scale, radix = 10**base.decimals, base.clients + 2
    numerator = (base.period * scale * radix).__floor__()
    while numerator > 0 and gcd(numerator, radix) != 1:
        numerator -= 1
    if numerator <= 0:
        raise ValueError("period too small for positive separated grid")
    period = Fraction(numerator, scale * radix)
    for extra_digits in range(13):
        denominator = base.denominator * 10**extra_digits
        codec = FinitePrecisionDMC(base.clients, base.decimals, base.modulus,
            period * denominator / base.modulus, transport_extra_digits=extra_digits)
        # Match the decoder's documented conservative bound, including wire rounding.
        error = period * (base.clients - 1) / base.modulus + Fraction(base.clients, 2 * denominator)
        if error < Fraction(1, 2 * scale * radix):
            return codec, dict(radix=radix, scale_drop=str(base.period-period),
                relative_scale_drop=str((base.period-period)/base.period),
                phase_separation=str(Fraction(1, scale*radix)),
                aggregate_error_bound=str(error), extra_wire_digits=extra_digits)
    raise ValueError("wire precision budget cannot separate carries")


def audit(source=SOURCE, *, clients=20, dimension=8):
    if type(clients) is not int or clients < 10 or type(dimension) is not int or not 1 <= dimension <= 16:
        raise ValueError("public bound attack fixture requires >=10 clients and dimension 1..16")
    hprf = OriginalAionHPRF.from_directory(source)
    base = PaperDMC(clients, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    codec, parameters = candidate(base)
    keys, round_id, bound = list(range(1, clients+1)), 4, Fraction(1, 10)
    masks = [hprf.hprf(k, round_id, dimension) for k in keys]
    aggregate = hprf.hprf(sum(keys), round_id, dimension)
    honest = dict(coordinates=0, mismatches=0)
    filter_differences = 0
    max_mgf_coordinate_change = Fraction(0)
    # Same six-decimal updates, including both signs and nontrivial mask carries.
    for phase in range(3):
        updates = [[Fraction(((i+1)*(j+3)*(phase+1)) % 20001-10000, 10**6)
                    for j in range(dimension)] for i in range(clients)]
        original_wire = [base.mask_decimal_wire(x,h) for x,h in zip(updates,masks,strict=True)]
        new_wire = [codec.mask_decimal_wire(x,h) for x,h in zip(updates,masks,strict=True)]
        filter_differences += len(set(select_masked(original_wire,bound))
                                  ^set(select_masked(new_wire,bound)))
        max_mgf_coordinate_change = max(max_mgf_coordinate_change,
            max(abs(a-b) for v,w in zip(original_wire,new_wire,strict=True)
                for a,b in zip(v,w,strict=True)))
        total = [sum(v[j] for v in new_wire) for j in range(dimension)]
        expected = [sum(x[j] for x in updates) for j in range(dimension)]
        recovered = codec.remove_quantized_lift(total, aggregate,
            selected_count=clients, decimal_wire=True)
        honest["coordinates"] += dimension
        honest["mismatches"] += sum(a!=b for a,b in zip(expected,recovered,strict=True))

    # Original keys/shares stay fixed. A sender can sign an arbitrarily altered
    # wire, so an attack test cannot assume its mask was honestly generated.
    zero_wire = [codec.mask_decimal_wire([0]*dimension,h) for h in masks]
    zero_total = [sum(v[j] for v in zero_wire) for j in range(dimension)]
    assert codec.remove_quantized_lift(zero_total, aggregate,
        selected_count=clients, decimal_wire=True) == [0]*dimension
    attack = None
    for shift_count in range(1, clients+1):
        # P is model-grid aligned here; shifting by P'-P moves to the next
        # carry phase while only changing the visible vector by a tiny amount.
        wire_delta = Fraction(round_even(shift_count*(codec.period-base.period)*codec.denominator),
                              codec.denominator)
        changed = [[v+wire_delta for v in zero_wire[0]], *zero_wire[1:]]
        original_accepted = select_masked(zero_wire,bound)
        changed_accepted = select_masked(changed,bound)
        if original_accepted != changed_accepted or len(changed_accepted)!=clients:
            continue
        total = [sum(v[j] for v in changed) for j in range(dimension)]
        try:
            decoded = codec.remove_quantized_lift(total,aggregate,
                selected_count=clients,decimal_wire=True)
        except QuantizedLiftError:
            continue
        change = max(map(abs,decoded))
        if not change:
            continue
        # For one deviating sender and zero honest updates, correct binding
        # implies ||x_attacker|| <= b + sqrt(d)*P + wire-rounding slack.
        # Use the integer ceiling of sqrt(d) to avoid floating-point sqrt.
        root_ceiling = isqrt(dimension) + (isqrt(dimension)**2 < dimension)
        independent_bound = bound+root_ceiling*codec.period+Fraction(root_ceiling,2*codec.denominator)
        outside = sum(v*v for v in decoded) > independent_bound**2
        row = dict(changed_sender_count=1, shifts=shift_count,
            wire_delta_per_coordinate=str(wire_delta), decoded_change_per_coordinate=str(decoded[0]),
            public_fixture_true_mask_subtraction=str(total[0]-zero_total[0]),
            public_fixture_true_mask_subtraction_after_quantization=str(codec.quantize(total[0]-zero_total[0])),
            amplification=str(change/abs(wire_delta)),
            original_accepted=len(original_accepted), changed_accepted=len(changed_accepted),
            decoded_sum_l2_squared=str(sum(v*v for v in decoded)),
            conservative_one_sender_bound=str(independent_bound),
            decoded_change_exceeds_one_sender_bound=outside,
            same_keys=True, additional_mask_shares=0)
        if attack is None or outside:
            attack=row
        if outside:
            break
    if attack is None:
        raise ValueError("no amplification fixture found; do not assert an attack")
    return dict(scope="offline public fixture; neither Flower integration nor universal MGF equivalence",
        clients=clients,dimension=dimension,original_period=str(base.period),
        candidate_period=str(codec.period),parameters=parameters,
        same_scale_for_mgf_and_aggregation=True,update_quantization_changed=False,
        original_mgf_bound=str(bound),honest_recovery=honest,
        observed_filter_differences=filter_differences,
        max_observed_mgf_coordinate_change=str(max_mgf_coordinate_change),
        grid=grid_alias_profile(codec,clients),malicious_wire=attack,
        acceptable_as_mgf_preserving_fix=(False if attack["decoded_change_exceeds_one_sender_bound"] else None))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,default=SOURCE)
    parser.add_argument("--clients",type=int,default=20)
    parser.add_argument("--dimension",type=int,default=8)
    args=parser.parse_args()
    print(json.dumps(audit(args.source,clients=args.clients,dimension=args.dimension),indent=2))


if __name__ == "__main__":
    main()
