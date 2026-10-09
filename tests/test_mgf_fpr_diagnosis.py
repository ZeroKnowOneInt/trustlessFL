"""Offline norm diagnostics may not alter the protocol or fabricate separation."""

from fractions import Fraction

import numpy as np
import pytest

from experiments.diagnose_mgf_fpr import decomposition, coordinates, oracle, regions, margin, ranks
from trustlessfl.crypto import digest


def test_exact_norm_decomposition_including_negative_alignment():
    result=decomposition([2,-3],[5,7],d=3,S=10)
    assert Fraction(result["update_square"])+Fraction(result["mask_square"])+Fraction(
        result["interaction"])==Fraction(result["total_square"])
    assert Fraction(result["interaction"])==Fraction(2*(2*5-3*7),3*100)
    assert result["cross_equals_twice_inner_product"]


def test_large_signed_integer_squares_are_exact_not_numpy_int64():
    result=decomposition(np.array([2**62,-2**62],dtype=np.int64),[2**62,2**62],d=1,S=1)
    assert Fraction(result["update_square"])==2**125
    assert Fraction(result["mask_square"])==2**125
    assert Fraction(result["interaction"])==0
    assert Fraction(result["total_square"])==2**126


def test_zero_update_uses_diagnostic_epsilon_not_new_mask_or_threshold():
    u=[0,0];m=[3,4];before=digest([u,m])
    result=decomposition(u,m,1,1)
    assert result["N_update"]=="0" and float(result["N_mask"])==5
    assert result["mask_update_ratio"]==5/1e-30
    assert digest([u,m])==before


def test_projection_and_outside_region_partition_full_coordinates():
    r=regions(8,[2,5])
    assert r["projection"]==[2,3,4]
    assert r["outside-J"]==[0,1,5,6,7]
    assert sorted(r["projection"]+r["outside-J"])==r["full-vector"]


def test_coordinate_contributions_are_diagnostics_not_predicate_overrides():
    v=[0]*999+[10];before=digest(v)
    result=coordinates(v)
    assert result["contributions"]["top_0.1_percent"]["count"]==1
    assert result["contributions"]["top_0.1_percent"]["squared_norm_fraction"]==1
    assert result["remaining_95_percent_fraction"]==0
    assert digest(v)==before


def test_coordinate_all_zero_has_no_fake_contribution_fraction():
    result=coordinates([0,0])
    assert result["contributions"]["top_5_percent"]["squared_norm_fraction"] is None


def test_oracle_separates_perfect_fixture_without_mutating_bound():
    scores={0:100,1:121,2:1,3:4};before=digest(scores);bound=Fraction(1)
    result=oracle(scores,{0,1},1,bound)
    assert result["AUC_exact"]=="1"
    assert result["best_TPR_at_FPR_budget"]["0"]["TPR"]==1
    assert result["current"]["FPR"]==.5
    assert bound==1 and digest(scores)==before


def test_oracle_equal_scores_cannot_be_separated_by_tuned_threshold():
    result=oracle({0:4,1:9,2:4,3:9},{0,1},1,Fraction(2))
    assert result["AUC_exact"]=="1/2"
    assert result["best_TPR_at_FPR_budget"]["0"]["TPR"]==0
    for row in result["rows"]:assert row["TPR"]==row["FPR"]


def test_oracle_inclusive_boundary_matches_existing_predicate():
    result=oracle({0:4,1:9,2:4,3:1},{0,1},1,Fraction(2))
    assert result["current"]["TPR"]==.5
    assert result["current"]["FPR"]==0


def test_margin_is_diagnostic_and_fraction_bound_is_unchanged():
    bound=Fraction(4,3);gap,ratio=margin("1",bound)
    assert Fraction(ratio)==Fraction(3,4)
    assert abs(float(gap)-1/3)<1e-16 and bound==Fraction(4,3)


def test_rank_ties_receive_average_ranks():
    assert ranks([5,1,5,2]).tolist()==[2.5,0.,2.5,1.]


@pytest.mark.parametrize("kind",[list,lambda x:np.asarray(x,dtype=object)])
def test_decomposition_does_not_mutate_raw_transmission_inputs(kind):
    u=kind([-1,2,0]);m=kind([3,4,5]);before=(list(u),list(m))
    decomposition(u,m,21,10000)
    assert (list(u),list(m))==before
