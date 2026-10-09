from fractions import Fraction

import pytest

from experiments.audit_same_scale_jitter import SOURCE, audit, candidate
from experiments.audit_same_scale_feasibility import grid_alias_profile
from trustlessfl.paper_dmc import PaperDMC


@pytest.mark.parametrize("count", [2, 20, 100])
def test_downward_scale_separates_carry_phases_at_sufficient_wire_precision(count):
    base = PaperDMC(count, 6, 14760426300877770769).with_mgf(
        "0.1", hmax_domain="normalized")
    codec, parameters = candidate(base)
    assert 0 < codec.period <= base.period
    assert codec.decimals == base.decimals
    assert Fraction(parameters["aggregate_error_bound"]) < Fraction(parameters["phase_separation"])/2
    assert not grid_alias_profile(codec,count)["grid_alias_possible_in_carry_interval"]


def test_too_small_period_is_not_silently_increased():
    with pytest.raises(ValueError,match="period too small"):
        candidate(PaperDMC(20,6,14760426300877770769).with_mgf(
            "0.00000000001",hmax_domain="normalized"))


def test_extra_wire_precision_cannot_hide_hprf_error_infeasibility():
    with pytest.raises(ValueError,match="precision budget"):
        candidate(PaperDMC(20,6,101).with_mgf("0.1",hmax_domain="normalized"))


@pytest.mark.parametrize("clients", [10,20,100])
def test_honest_success_and_unchanged_fixture_filter_do_not_hide_bound_attack(clients):
    if not (SOURCE/"matrix").is_file():
        pytest.skip("original HPRF required")
    report=audit(clients=clients)
    assert report["honest_recovery"] == {"coordinates":24,"mismatches":0}
    assert report["observed_filter_differences"] == 0
    assert report["same_scale_for_mgf_and_aggregation"]
    assert not report["update_quantization_changed"]
    attack=report["malicious_wire"]
    assert attack["changed_sender_count"] == 1 and attack["same_keys"]
    assert attack["original_accepted"] == attack["changed_accepted"] == clients
    assert Fraction(attack["amplification"]) > 100000
    assert Fraction(attack["public_fixture_true_mask_subtraction"]) == Fraction(attack["wire_delta_per_coordinate"])
    assert abs(Fraction(attack["public_fixture_true_mask_subtraction"])) < Fraction(1,2*10**6)
    assert Fraction(attack["public_fixture_true_mask_subtraction_after_quantization"]) == 0
    assert Fraction(attack["decoded_sum_l2_squared"]) > Fraction(attack["conservative_one_sender_bound"])**2
    assert report["acceptable_as_mgf_preserving_fix"] is False


@pytest.mark.parametrize("clients,dimension", [(2,8),(20,0),(20,17)])
def test_fixture_preconditions_are_explicit(clients,dimension):
    with pytest.raises(ValueError,match="public bound attack fixture"):
        audit(clients=clients,dimension=dimension)
