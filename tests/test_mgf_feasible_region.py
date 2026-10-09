"""Feasibility audit helpers: exact boundaries, no fallback/count cap."""
from fractions import Fraction

import pytest

from experiments.audit_mgf_feasible_region import minimum_period, make_vectors, evaluate_selection
from trustlessfl.source_profiles import TransmissionCodec, transmission_error
from trustlessfl.crypto import ProtocolError

P=14760426300877770769
Q=5*P


@pytest.mark.parametrize("n",[2,5,10,20])
@pytest.mark.parametrize("C",[Fraction(100),Fraction(".04268455505371094"),Fraction(".00015")])
def test_minimal_period_is_exact_and_previous_integer_infeasible(n,C):
    a=minimum_period(n,C,21,10000,P,Q)
    assert a["feasible"]
    M=a["M_min"];E=a["E_bar"];Bu=a["B_u"]
    assert 2*(21*n*Bu+E)<M
    assert 2*(21*n*Bu+transmission_error(n,P,Q,M-1))>=M-1
    c=TransmissionCodec(P,Q,10000,21,M,n,C,20)
    assert c.max_integer==Bu and c.error==E


def test_existing_baseline_minimum_matches_committed_profile():
    a=minimum_period(20,Fraction(100),21,10000,P,Q)
    assert a["M_min"]==840000021 and a["E_bar"]==10
    assert a["envelope_margin"]=="1/2"


def test_spacing_failure_has_no_larger_period_fallback():
    a=minimum_period(20,Fraction(100),20,10000,P,Q)
    assert not a["feasible"] and a["reason"]=="spacing-infeasible"


def test_generalized_error_is_recomputed_not_constant_ten():
    a=minimum_period(20,Fraction(1),21,1,11,55)
    assert not a["feasible"] and a["E_bar"]>10


def test_single_raw_Y_preserved_without_client_side_modulo():
    assert make_vectors([[3,-2]],[[99,100]],21)==[
        {"sender":0,"masked_vector":[162,58]}]


def test_capacity_cannot_silently_cap_twenty_candidates():
    c=TransmissionCodec(P,Q,1,21,10000,2,Fraction(1),20)
    m={"dimension":1,"source_profile":{"mgf_scope":"full-vector"},
       "paper_numerics":{"projection":[0,1],"filter_rule":"inclusive-historical-bound-v1"}}
    state={"paper_bound":"100","paper_terms":["1","1"],"paper_mgf_scope":"full-vector"}
    vectors=[{"sender":i,"masked_vector":[i]} for i in range(20)]
    _,ids,pending,error=evaluate_selection(m,state,c,vectors,4)
    assert ids==list(range(20)) and pending is None
    assert error=="selected-count-exceeds-nmax"


def test_reduced_candidate_count_is_not_supported_bootstrap():
    c=TransmissionCodec(P,Q,1,21,10000,2,Fraction(1),2)
    m={"dimension":1,"paper_numerics":{"projection":[0,1]}}
    with pytest.raises(ProtocolError,match="at least two selected"):
        evaluate_selection(m,{},c,[{"sender":i,"masked_vector":[i]} for i in range(2)],1)
