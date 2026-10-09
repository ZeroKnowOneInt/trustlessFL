"""Read-only/public-fixture audit of mod-p recovery on the CURRENT MGF wire.

Fixture keys/updates are public, never runtime client secrets. Original archived
synthetic round 4 did not retain private mask ground truth: the minimal replay
uses its committed public scale/bound, not its original private keys/updates.
"""

import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path

from experiments.audit_aion_hprf_carry import SOURCE, decomposition
from experiments.audit_scaled_ring import audit_public_history
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.modular_recovery import (center_p, hprf_error_bound,
    maximum_clients, spacing_limits)
from trustlessfl.paper_dmc import PaperDMC, QuantizedLiftError, round_even
from trustlessfl.source_paper_numeric import mask_integer_wire, select_masked


def legacy_candidates(codec, total, ha, count):
    """Diagnostic replica only; NEVER used by modular recovery."""
    transmitted = Fraction(total, codec.denominator)
    residual = transmitted-codec.coefficient*ha/codec.denominator
    error = (codec.coefficient*(count-1)+Fraction(count, 2))/codec.denominator
    limit = Fraction(count*round_even(codec.coefficient*codec.modulus), codec.denominator)
    rows = []
    for carry in range(-1, count+1):
        value = residual-carry*codec.period
        rounded = codec.quantize(value)
        if abs(value-rounded) <= error and 0 <= transmitted-rounded <= limit:
            rows.append(dict(carry=carry, update_quanta=int(rounded*10**codec.decimals)))
    return rows


def ceil_fraction(value):
    return -(-value.numerator//value.denominator)


def synthetic_fixture(source=SOURCE, *, archived_run=None):
    hprf = OriginalAionHPRF.from_directory(source)
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.0016", hmax_domain="normalized")
    # Deliberately known public fixture. Coordinates have different carries
    # and signed update sums; magnitude is below archived MGF bound, but some
    # SUM coordinates exceed the scaled ring's half-period.
    keys, round_id = [4, 16], 4
    updates = [[0, 700, -700, 5, -5, 800, -800, 0], [0]*8]
    masks = [hprf.hprf(k, round_id, 8) for k in keys]
    aggregate = hprf.hprf(sum(keys), round_id, 8)
    wire = [mask_integer_wire(codec, z, h) for z, h in zip(updates, masks, strict=True)]
    total = [sum(row[j] for row in wire) for j in range(8)]
    spacing, period = codec.denominator//10**codec.decimals, codec.coefficient*hprf.p
    assert period.denominator == 1
    period = int(period)
    count, eh = len(keys), hprf_error_bound(len(keys), p=hprf.p, q=hprf.q)
    # Subtracting a rounded aggregate mask adds one more rounding residual.
    ew = ceil_fraction(codec.coefficient*eh+Fraction(count+1, 2))
    rows = []
    for j, ha in enumerate(aggregate):
        _, _, e, difference = decomposition(hprf, keys, round_id, masks, aggregate, j)
        c = (difference-e)//hprf.p
        truth = sum(z[j] for z in updates)
        scaled_ha = round_even(codec.coefficient*ha)
        raw_r = center_p((total[j]-scaled_ha) % hprf.p, hprf.p)
        scaled_r = center_p((total[j]-scaled_ha) % period, period)
        candidates = legacy_candidates(codec, total[j], ha, count)
        rows.append(dict(round=round_id, selected_count=count, coordinate=j,
            integer_mask_sum=sum(h[j] for h in masks), aggregate_hprf=ha,
            difference=difference, carry=c, hprf_error=e,
            plaintext_update_quanta=truth, masked_integer_sum=total[j],
            masked_sum_mod_p=total[j] % hprf.p, subtraction_mod_p=(total[j]-scaled_ha) % hprf.p,
            centered_mod_p=raw_r, naive_mod_p_update=round_even(Fraction(raw_r, spacing)),
            naive_mod_p_exact=round_even(Fraction(raw_r, spacing)) == truth,
            scaled_wire_error=total[j]-scaled_ha-c*period-spacing*truth,
            scaled_ring_center=scaled_r,
            scaled_ring_update=round_even(Fraction(scaled_r, spacing)),
            scaled_ring_exact=round_even(Fraction(scaled_r, spacing)) == truth,
            true_sum_spacing_abs=abs(spacing*truth), scaled_half_period=str(Fraction(period, 2)),
            true_scaled_sum_fits=2*(abs(spacing*truth)+ew) < period,
            legacy_carry_candidate_count=len(candidates),
            legacy_update_candidate_count=len({r['update_quanta'] for r in candidates}),
            legacy_candidates=candidates, ambiguous=len({r['update_quanta'] for r in candidates}) > 1,
            scale_shift=round_even(codec.coefficient*(masks[0][j]+hprf.p))-
                        round_even(codec.coefficient*masks[0][j])))
    try:
        codec.remove_quantized_lift([Fraction(y, codec.denominator) for y in total],
                                   aggregate, selected_count=count, decimal_wire=True)
        legacy_status = "success"
    except QuantizedLiftError as exc:
        legacy_status = exc.code
    try:
        codec.remove_modular_integer_wire(total, aggregate, selected_count=count,
                                         client_integer_bound=10**8, original_q=hprf.q)
        modular_status = "success"
    except ProtocolError as exc:
        modular_status = str(exc)
    result = dict(scope="public minimal r4 reproduction, NOT the archived private-key execution",
        public_fixture_keys=keys, public_fixture_update_quanta=updates, p=hprf.p, q=hprf.q,
        coefficient=str(codec.coefficient), model_scale=10**codec.decimals,
        wire_denominator=codec.denominator, update_spacing=spacing,
        scaled_wire_modulus=period, hprf_error_bound=eh, rounded_wire_error_bound=ew,
        legacy_status=legacy_status, modular_status=modular_status, coordinates=rows,
        mod_p_compatible=all(r['scale_shift'] % hprf.p == 0 for r in rows),
        integer_scale_reference_limits=spacing_limits(hprf.p, 20, 10**8,
            hprf_error_bound(20, p=hprf.p, q=hprf.q)),
        integer_scale_reference_maximum_clients=maximum_clients(modulus=hprf.p, spacing=spacing,
            client_bound=10**8, mask_multiplier=1, p=hprf.p, q=hprf.q),
        scaled_ring_client_bound_max_for_selected_two=(period-1-2*ew)//(2*spacing*count),
        denominator_clearing=dict(denominator=codec.coefficient.denominator,
            cleared_spacing=codec.coefficient.denominator*spacing,
            update_term_zero_mod_p=(codec.coefficient.denominator*spacing) % hprf.p == 0),
        extra_mask_shares=0, mpc=False, runtime_changed=False)
    if archived_run is not None:
        run = Path(archived_run)
        evidence = (run/'failure.json').read_bytes()
        failure, manifest = json.loads(evidence), json.loads((run/'manifest.json').read_bytes())
        history = failure['completed_rounds']
        assert failure['category'] == 'ambiguous' and len(history) == 3
        assert Fraction(history[-1]['paper_numeric']['next_linf']) == Fraction(1, 625)
        state = dict(paper_bound=history[-1]['paper_numeric']['bound'],
            paper_terms=[e['paper_numeric']['history_term'] for e in history[-2:]])
        # Eighteen additional honest, in-encoding-range but MGF-rejected clients.
        # No second masked vector: selection and both candidate audits use Y.
        vectors = [dict(sender=i, masked_vector=v) for i, v in enumerate(wire)]
        for i in range(2, 20):
            vectors.append(dict(sender=i, masked_vector=mask_integer_wire(codec,
                [10**6]*8, hprf.hprf(100+i, round_id, 8))))
        selection = select_masked(manifest, state, codec, vectors, round_id)
        assert set(selection['selected']) == {0, 1} and selection['total'] == total
        result['archived_public_bound_replay'] = dict(
            failure_sha256=hashlib.sha256(evidence).hexdigest(),
            original_failure_request=failure['request'], public_bound=selection['bound_decimal'],
            selected=selection['selected'], same_mgf_and_aggregate_vector=True,
            original_private_keys_available=False)
    return result


def audit(source=SOURCE, *, synthetic_run=None, fmnist_run=None):
    result = dict(conclusion="C", synthetic=synthetic_fixture(source, archived_run=synthetic_run))
    if fmnist_run is not None:
        history = audit_public_history(fmnist_run)
        original = json.loads((Path(fmnist_run)/'results.json').read_text())
        for row, event in zip(history['rounds'], original['history'], strict=True):
            coefficient = Fraction(event['paper_numeric']['scale']['coefficient'])
            row['coefficient'] = str(coefficient)
            row['integer_coefficient'] = coefficient.denominator == 1
            row['mod_p_preflight_rejected'] = coefficient.denominator != 1
        result['fmnist_public_history'] = history
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--synthetic-run', type=Path)
    parser.add_argument('--fmnist-run', type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.source, synthetic_run=args.synthetic_run,
                          fmnist_run=args.fmnist_run), indent=2))


if __name__ == '__main__':
    main()
