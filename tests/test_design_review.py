"""Independent review witnesses; no production behavior is modified."""

from fractions import Fraction
import json
from pathlib import Path

import pytest

from experiments.audit_design_review import (SOURCE, scaling_boundaries, adaptive_period_review,
    history_and_weight_counterexamples, projection_and_postcheck_counterexamples, input_overlap)
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from experiments.transmission_numeric import scale_mask, transmission_error_bound


@pytest.fixture(scope='module')
def hprf():
    if not (SOURCE/'matrix').exists():pytest.skip('author setup required')
    return OriginalAionHPRF.from_directory(SOURCE)


def test_reference_scaling_endpoint_midpoints_and_large_ratio(hprf):
    result=scaling_boundaries(hprf)
    assert result['real_raw_p_endpoint']['h']==hprf.p
    assert result['large_ratio']['E']==12>10
    assert result['large_ratio']['bound']==14
    assert result['identity_scale']['general_scaled_bound']>result['identity_scale']['raw_bound']


def test_adaptive_paper_scale_does_not_ensure_decoding_capacity(hprf):
    result=adaptive_period_review(hprf)
    assert result['period']=='32000'
    assert [v['true_U'] for v in result['sum_alias_witnesses']]==[700,-700]
    assert all(abs(v['decoded'])==60 for v in result['sum_alias_witnesses'])
    assert result['fmnist_initial_integer_wire_period']=='773033828125/65536'


def test_correct_mask_sum_history_is_not_literal_algorithm6():
    row=history_and_weight_counterexamples()['history']
    assert row['recovered_U']==1
    assert row['actual_mask_sum']==32
    assert Fraction(row['prompt_history_term'])==Fraction(35,3)
    assert Fraction(row['paper_literal_history_term'])==Fraction(444,101)
    assert row['prompt_history_term']!=row['paper_literal_history_term']


def test_weighted_fedavg_algebra_does_not_preserve_unweighted_mgf_predicate():
    row=history_and_weight_counterexamples()['weighted']
    assert row['unweighted_pass'] and not row['weighted_pass']
    assert row['divided_second_pass'] and not row['unweighted_second_pass']


def test_projection_and_decoder_postchecks_do_not_enforce_input_bounds():
    row=projection_and_postcheck_counterexamples()
    assert row['projection']['selected']==20
    assert row['postcheck']['true_out_of_premise_sum']!=row['postcheck']['recovered_sum']


def test_non_grid_aligned_runtime_bound_floors_while_encoder_rounds():
    row=projection_and_postcheck_counterexamples()['quantized_bound']
    assert row['encoded']==[2,-2]
    assert row['runtime_max_integer']==1<row['round_even_bound']


def test_original_input_overlap_survives_full_domain_sampling(hprf):
    assert input_overlap(hprf)['equal_coordinates']==512


def test_fractional_runtime_period_cannot_use_integer_translation_identity():
    p=101;m=Fraction(3,2)
    assert round(m*Fraction(p,p))!=round(m*Fraction(0,p))+m
    with pytest.raises(ValueError):scale_mask(p,p=p,period=m)


@pytest.mark.parametrize('m',[1,2,7,10,11,33,100])
def test_large_period_formula_uses_general_bound_and_independent_reference(m):
    p=11;q=55;n=20
    for t in range(q):
        c,ta=divmod(n*t,q)
        hi=round(Fraction(p*t,q));ha=round(Fraction(p*ta,q))
        error=n*round(Fraction(m*hi,p))-round(Fraction(m*ha,p))-c*m
        assert abs(error)<=transmission_error_bound(n,p=p,q=q,period=m)


def test_new_ledger_contains_fresh_checks_not_old_success_counts():
    path=Path('.cache/design-independent-review-20261009-v3/report.json')
    if not path.exists():pytest.skip('run audit_design_review for local ledger')
    row=json.loads(path.read_text())
    assert row['runtime_unchanged']
    assert sum(v['exact_coordinates'] for v in row['fresh_recovery']['results'])==752772
    assert row['fresh_small_key_search']['unique_fraction']==1
    assert all(v['exact'] for v in row['fresh_raw_output_inversion']['rows'])
    assert sum(v['cases'] for v in row['arithmetic_enumeration'])>1000000
    assert len(row['fresh_mgf_replay']['results'])==3
