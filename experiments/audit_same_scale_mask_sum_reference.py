"""Numerical target for a possible private correction, NOT its implementation.

All keys here are public fixtures. Never import this oracle into a Flower
actor or use it to read experiment private inputs. It establishes what
additional computation would correct the existing single decimal wire;
it does not establish that revealing the result is safe.
"""

import argparse
import json
from fractions import Fraction

from experiments.audit_same_scale_feasibility import SOURCE
from experiments.audit_scaled_sum_collision import audit as collision_audit
from experiments.audit_same_scale_jitter import audit as jitter_audit, candidate
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ORDER
from trustlessfl.paper_dmc import PaperDMC, round_even
from trustlessfl.source_paper_numeric import mask_integer_wire


def recover_with_public_fixture_mask_sum(codec, wire_sum, mask_sum):
    """Strict integer-grid target; the caller supplies the true rounded sum.

    This input is unavailable from an aggregate key alone. There is no
    reconstruction, secure computation, or authentication in this function.
    Reject off-grid aggregates instead of guessing a carry or silently rounding.
    """
    scale = 10**codec.decimals
    extra, remainder = divmod(codec.denominator, scale)
    if remainder or extra < 1 or len(wire_sum) != len(mask_sum):
        raise ValueError("incompatible wire/model scales or dimensions")
    if any(type(v) is not int for v in [*wire_sum, *mask_sum]):
        raise ValueError("reference subtraction requires integer wire values")
    result = []
    for wire, mask in zip(wire_sum, mask_sum, strict=True):
        if mask < 0:
            raise ValueError("negative public fixture mask sum")
        value, remainder = divmod(wire-mask, extra)
        if remainder:
            raise ValueError("aggregate is off the integer update grid")
        result.append(value)
    return result


def public_fixture_mask_sum(codec, hprf, keys, round_id, dimension):
    if not keys or len(keys) > codec.clients or any(
            type(k) is not int or not 1 <= k <= 100000 for k in keys):
        raise ValueError("invalid public original-key fixture")
    if type(dimension) is not int or dimension < 1:
        raise ValueError("positive fixture dimension required")
    total = [0]*dimension
    for key in keys:
        rounded = mask_integer_wire(codec, [0]*dimension,
                                    hprf.hprf(key, round_id, dimension))
        total = [a+b for a, b in zip(total, rounded, strict=True)]
    return total


def honest_fixture(hprf, *, clients, selected_count, dimension, round_id):
    codec = PaperDMC(clients, 6, hprf.p).with_mgf("0.001", hmax_domain="normalized")
    scale = 10**codec.decimals
    keys = [1+((i*7919+round_id*101) % 100000) for i in range(selected_count)]
    expected, total = [0]*dimension, [0]*dimension
    mask_sum, raw_mask_sum = [0]*dimension, [0]*dimension
    true_sum = [Fraction(0)]*dimension
    accepted, max_quantization = 0, Fraction(0)
    # Public fixture; a varying signed input, not FMNIST training evidence.
    for i, key in enumerate(keys):
        ticks = [((i+1)*(j+7)*37+round_id*11) % 20001-10000
                 for j in range(dimension)]
        encoded = [round_even(Fraction(t, 10)) for t in ticks]
        masks = hprf.hprf(key, round_id, dimension)
        wire = mask_integer_wire(codec, encoded, masks)
        rounded_masks = mask_integer_wire(codec, [0]*dimension, masks)
        # Same original MGF predicate, on the very same transmitted vector.
        accepted += sum(v*v for v in wire) <= codec.denominator**2
        for j, (tick, z, y, mask) in enumerate(zip(ticks, encoded, wire, rounded_masks, strict=True)):
            expected[j] += z
            total[j] += y
            mask_sum[j] += mask
            raw_mask_sum[j] += masks[j]
            true_sum[j] += Fraction(tick, 10*scale)
            max_quantization = max(max_quantization, abs(Fraction(z, scale)-Fraction(tick, 10*scale)))
    decoded = recover_with_public_fixture_mask_sum(codec, total, mask_sum)
    if decoded != expected:
        raise AssertionError("true decimal mask subtraction failed integer recovery")
    max_mean_error = max(abs(Fraction(z, scale)-x)/selected_count
                         for z, x in zip(decoded, true_sum, strict=True))
    if max_mean_error > Fraction(1, 2*scale):
        raise AssertionError("mean quantization error exceeds fixed-point bound")
    # A party seeing both public Y_sum and the decoded sum infers mask_sum.
    inferred = [y-(codec.denominator//scale)*z for y, z in zip(total, decoded, strict=True)]
    aggregate_hprf = hprf.hprf(sum(keys), round_id, dimension)
    true_carries = [round_even(Fraction(raw-h, hprf.p))
                    for raw, h in zip(raw_mask_sum, aggregate_hprf, strict=True)]
    inferred_carries = [round_even(Fraction(mask, codec.denominator)/codec.period-Fraction(h, hprf.p))
                       for mask, h in zip(inferred, aggregate_hprf, strict=True)]
    # Public decimal precision must be sufficient for this inference claim.
    carry_error_bound = Fraction(selected_count+1, 2*hprf.p)+Fraction(
        selected_count, 2*codec.denominator)/codec.period
    if carry_error_bound >= Fraction(1, 2):
        raise AssertionError("fixture precision does not justify carry inference")
    if inferred_carries != true_carries:
        raise AssertionError("outputs did not imply fixture carries as predicted")
    return dict(candidates=clients, selected_count=selected_count, dimension=dimension,
        round=round_id, coordinate_mismatches=0, mgf_accepted=accepted,
        sum_coordinates_outside_centered_period=sum(
            abs(Fraction(z, scale)) >= codec.period/2 for z in expected),
        max_individual_quantization_error=str(max_quantization),
        max_mean_quantization_error=str(max_mean_error),
        public_outputs_imply_true_decimal_mask_sum=inferred == mask_sum,
        output_inferred_carry_matches_true=inferred_carries == true_carries,
        nonzero_inferred_carry_coordinates=sum(c != 0 for c in inferred_carries),
        carry_inference_error_bound=str(carry_error_bound))


def collision_reference(source, hprf):
    collision = collision_audit(source)
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    masks, recovered = [], []
    for execution in collision["executions"]:
        mask_sum = public_fixture_mask_sum(codec, hprf,
            execution["public_fixture_keys"], collision["hprf_round"], collision["dimension"])
        z = recover_with_public_fixture_mask_sum(codec, collision["masked_sum"], mask_sum)
        if z != execution["encoded_sum"]:
            raise AssertionError("reference failed the existing aggregate collision")
        masks.append(mask_sum)
        recovered.append(z)
    return dict(same_wire_sum=True, same_key_sum=True,
        aggregate_key_decoder=collision["decoder_rejection"],
        true_decimal_mask_sums_differ=masks[0] != masks[1],
        correct_integer_sums_recovered=True,
        public_integer_sums=recovered)


def amplification_reference(source, hprf):
    old = jitter_audit(source)
    base = PaperDMC(20, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    codec, _ = candidate(base)
    masks = public_fixture_mask_sum(codec, hprf, list(range(1, 21)), 4, 8)
    delta = Fraction(old["malicious_wire"]["wire_delta_per_coordinate"])*codec.denominator
    if delta.denominator != 1:
        raise AssertionError("attack does not have an integer decimal wire")
    changed = [v+int(delta) for v in masks]
    try:
        recover_with_public_fixture_mask_sum(codec, changed, masks)
    except ValueError as exc:
        if "off the integer" not in str(exc):
            raise
    else:
        raise AssertionError("off-grid amplification attack was not rejected")
    extra = codec.denominator//10**codec.decimals
    changed = [v+extra for v in masks]
    assert recover_with_public_fixture_mask_sum(codec, changed, masks) == [1]*8
    return dict(previous_amplification=old["malicious_wire"]["amplification"],
        off_grid_attack_rejected=True, valid_grid_change_has_unit_response=True)


def audit(source=SOURCE, *, full_dimension=61706):
    if type(full_dimension) is not int or not 1 <= full_dimension <= 100000:
        raise ValueError("full_dimension must be within the public audit budget")
    hprf = OriginalAionHPRF.from_directory(source)
    # These are actual artifact facts, not assumptions about every LWE HPRF.
    if hprf.q != 5*hprf.p or hprf.p % 2 != 1:
        raise ValueError("this circuit-cost observation requires the author's q=5p setup")
    # Check the exact floor simplification, including its upper endpoint p.
    for t in [0, 1, 2, 3, 4, hprf.q//2, hprf.q-3, hprf.q-2, hprf.q-1]:
        assert (t*hprf.p+hprf.q//2)//hprf.q == (t+2)//5
    fixtures = [honest_fixture(hprf, clients=n, selected_count=max(2, n//2),
                dimension=288, round_id=r) for n in (2, 20, 100) for r in (1, 4, 9)]
    fixtures.append(honest_fixture(hprf, clients=20, selected_count=20,
                                  dimension=full_dimension, round_id=4))
    return dict(scope="public-key numerical reference, not a private MPC/Flower implementation",
        model_scale=10**6, original_scale_and_mgf_unchanged=True,
        fixtures=fixtures, collision=collision_reference(source, hprf),
        amplification=amplification_reference(source, hprf),
        computation_target=dict(hprf_q=hprf.q, hprf_p=hprf.p, vss_field_bits=ORDER.bit_length(),
            individual_evaluations_20_clients=20*full_dimension,
            individual_evaluations_100_clients=100*full_dimension,
            aggregate_evaluations_current_asr=full_dimension,
            nonlinear_steps="secret residue modulo q; floor((t+2)/5); exact decimal-wire rounding",
            naive_sharewise_mod_q_conversion_valid=ORDER % hprf.q == 0),
        extra_client_shares=0, runtime_modified=False,
        privacy_proved=False, output_implied_carry_leakage_still_requires_review=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full-dimension", type=int, default=61706)
    args = parser.parse_args()
    print(json.dumps(audit(full_dimension=args.full_dimension), indent=2))


if __name__ == "__main__":
    main()
