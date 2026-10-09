from fractions import Fraction
from pathlib import Path

import pytest

from experiments.audit_aion_hprf_carry import SOURCE, decode, encode
from experiments.audit_modular_mgf_recovery import audit, synthetic_fixture
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.modular_recovery import hprf_error_bound
from trustlessfl.paper_dmc import PaperDMC


@pytest.fixture(scope="module")
def synthetic():
    if not (SOURCE/'matrix').is_file():
        pytest.skip("author setup required")
    return synthetic_fixture()


def test_current_same_vector_synthetic_ambiguity_and_scaled_incompatibility(synthetic):
    assert synthetic['legacy_status'] == 'ambiguous'
    assert not synthetic['mod_p_compatible']
    assert 'fractional decimal mask scale' in synthetic['modular_status']
    row = synthetic['coordinates'][0]
    assert (row['carry'], row['hprf_error'], row['plaintext_update_quanta']) == (1, 0, 0)
    assert row['difference'] == synthetic['p']
    assert row['integer_mask_sum'] == 26877942862611229325
    assert row['aggregate_hprf'] == 12117516561733458556
    assert row['legacy_update_candidate_count'] == 2
    assert row['naive_mod_p_update'] == 320 != row['plaintext_update_quanta']
    assert row['scale_shift'] == 32000 and row['scale_shift'] % synthetic['p'] != 0


def test_scaled_ring_cancels_mask_carry_but_not_update_sum_alias(synthetic):
    rows = synthetic['coordinates']
    assert all(row['scaled_ring_exact'] for row in rows if row['true_scaled_sum_fits'])
    outside = [row for row in rows if not row['true_scaled_sum_fits']]
    assert outside and all(not row['scaled_ring_exact'] for row in outside)
    assert rows[1]['true_sum_spacing_abs'] == 70000 > 16000
    assert rows[1]['scaled_ring_update'] == 60 != 700
    assert synthetic['scaled_ring_client_bound_max_for_selected_two'] == 79
    assert synthetic['denominator_clearing']['update_term_zero_mod_p']


def test_current_synthetic_public_bound_keeps_mgf_and_sum_same_vector():
    run = Path('.cache/same-scale-synthetic-official-20261008')
    if not (run/'failure.json').is_file():
        pytest.skip("archived public history unavailable")
    row = synthetic_fixture(archived_run=run)
    replay = row['archived_public_bound_replay']
    assert set(replay['selected']) == {0, 1}
    assert replay['same_mgf_and_aggregate_vector']
    assert not replay['original_private_keys_available']
    assert row['legacy_status'] == 'ambiguous'


def test_fmnist_success_is_not_evidence_of_centered_scaled_range():
    run = Path('.cache/same-scale-fmnist-official-20261008')
    if not (run/'results.json').is_file():
        pytest.skip("archived public FMNIST history unavailable")
    result = audit(fmnist_run=run)
    rows = result['fmnist_public_history']['rounds']
    assert len(rows) == 4
    assert all(row['mod_p_preflight_rejected'] for row in rows)
    assert [row['observed_sum_fits_centered_range'] for row in rows] == [True, False, False, False]
    assert [row['public_sum_changed_by_centering'] for row in rows] == [0, 151, 4520, 2955]
    assert not result['fmnist_public_history']['individual_keys_read']


@pytest.mark.parametrize('round_id', [1, 4, 17, 450])
def test_actual_q_domain_decomposition_over_random_keys_and_rounds(round_id):
    if not (SOURCE/'matrix').is_file():
        pytest.skip("author setup required")
    import random
    from experiments.audit_aion_hprf_carry import decomposition
    from trustlessfl.modular_recovery import ModularRecovery, modular_sum
    from trustlessfl.source_paper_numeric import mask_integer_wire
    hprf = OriginalAionHPRF.from_directory(SOURCE)
    rng = random.Random(20261008+round_id)
    count, dimension = 20, 513
    keys = [rng.randint(1, 100000) for _ in range(count)]
    masks = [hprf.hprf(k, round_id, dimension) for k in keys]
    aggregate = hprf.hprf(sum(keys), round_id, dimension)
    errors, carries = [], []
    for j in range(dimension):
        _, _, e, difference = decomposition(hprf, keys, round_id, masks, aggregate, j)
        c = (difference-e)//hprf.p
        assert difference == c*hprf.p+e
        errors.append(e)
        carries.append(c)
    # Actual early-round matrices/keys can produce e=0 in all coordinates;
    # do not manufacture nonzero error to match an assumption. The separate
    # author-HPRF ASR regression explicitly exercises known nonzero e.
    assert any(carries)
    assert max(map(abs, errors)) <= hprf_error_bound(count, p=hprf.p, q=hprf.q)
    updates = [[rng.randint(-100, 100) for _ in range(dimension)] for _ in keys]
    # Compatible A=1 control, NOT the current scaled MGF wire.
    codec = PaperDMC(count, 6, hprf.p)
    wire = [mask_integer_wire(codec, z, h) for z, h in zip(updates, masks, strict=True)]
    plan = ModularRecovery(hprf.p, 100, count, 100,
                           hprf_error_bound(count, p=hprf.p, q=hprf.q))
    assert plan.recover(modular_sum(wire, hprf.p), aggregate, selected_count=count) == [
        sum(row[j] for row in updates) for j in range(dimension)]


def test_float_mean_quantization_error_reported_separately():
    values = ["0.12345649", "-0.01234549", "0.00000049"]
    scale = 10**6
    quanta = [encode(v, scale) for v in values]
    exact_decimal_mean = sum(map(Fraction, values))/len(values)
    quantized_mean = decode(sum(quanta), scale)/len(values)
    assert abs(quantized_mean-exact_decimal_mean) == Fraction(49, 300000000)
    assert abs(quantized_mean-exact_decimal_mean) <= Fraction(1, 2*scale)
    float_mean = sum(map(float, values))/len(values)
    assert abs(float(quantized_mean)-float_mean) < 5.000001e-7
