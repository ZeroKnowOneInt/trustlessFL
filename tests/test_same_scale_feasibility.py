from fractions import Fraction

import pytest

from experiments.audit_same_scale_feasibility import (
    SOURCE, audit, capacity_envelope, from_period, grid_alias_profile,
)
from trustlessfl.paper_dmc import PaperDMC, select_masked


def test_capacity_threshold_is_strict_and_includes_wire_rounding():
    base = PaperDMC(20, 6, 1000000007).with_mgf("0.1", hmax_domain="normalized")
    result = capacity_envelope(base, 20, "0.01")
    minimum = Fraction(result["minimum_period_exclusive"])
    assert minimum > Fraction(2, 5)  # > 2*N*B because both errors are present
    assert not capacity_envelope(from_period(base, minimum), 20, "0.01")["capacity_safe"]
    assert capacity_envelope(from_period(base, minimum * 2), 20, "0.01")["capacity_safe"]
    assert Fraction(result["wire_rounding_error"]) == Fraction(1, 10000000)


def test_capacity_alone_does_not_guarantee_rounding_precision():
    base = PaperDMC(20, 6, 1000000007)
    wide = from_period(base, 1000000)
    result = capacity_envelope(wide, 20, "0.01")
    assert result["capacity_safe"]
    assert not result["quantization_safe"]


def test_modulus_growth_cancels_under_original_scaling():
    for p in (101, 1000000007, 14760426300877770769):
        codec = PaperDMC(20, 6, p).with_mgf("0.1", hmax_domain="normalized")
        assert codec.period == Fraction(1, 50)


@pytest.mark.parametrize("count,bound", [(1, 1), (21, 1), (True, 1), (2, -1)])
def test_invalid_range_inputs_rejected(count, bound):
    with pytest.raises(ValueError):
        capacity_envelope(PaperDMC(20, 6, 101), count, bound)


def test_insufficient_modulus_rejected():
    with pytest.raises(ValueError, match="exhausts"):
        capacity_envelope(PaperDMC(20, 6, 3), 20, "0.01")


@pytest.mark.parametrize("clients", [2, 20, 100])
def test_original_hprf_single_view_tradeoff(clients):
    if not (SOURCE / "matrix").is_file():
        pytest.skip("requires original HPRF setup")
    report = audit(clients=clients)
    original, raised = report["profiles"]
    assert original["accepted_clients"] == clients
    assert not original["capacity_safe"]
    assert original["centered_mismatches"] > 0
    assert raised["capacity_safe"] and raised["quantization_safe"]
    assert raised["centered_mismatches"] == 0
    assert raised["accepted_clients"] < clients
    assert report["restricted_update_candidate"]["exact_recovery"]
    assert report["restricted_update_candidate"]["changes_training_updates"]


def test_sum_based_scale_requires_strong_contraction_for_center():
    previous_sum_norm = Fraction(1, 10)
    codec = PaperDMC(20, 6, 14760426300877770769).with_mgf(
        previous_sum_norm, hmax_domain="normalized")
    assert codec.period / 2 == previous_sum_norm / 10
    # A current sum equal to the prior sum cannot use the centered lift.
    assert not capacity_envelope(codec, 20, previous_sum_norm / 20)["capacity_safe"]


@pytest.mark.parametrize("previous_sum_quanta", [1, 2, 4, 5, 1600, 2199, 1000001])
def test_sum_scale_grid_denominator_is_only_one_or_five(previous_sum_quanta):
    codec = PaperDMC(20, 6, 14760426300877770769).with_mgf(
        Fraction(previous_sum_quanta, 10**6), beta="0.2", hmax_domain="normalized")
    result = grid_alias_profile(codec, 10)
    assert result["indistinguishable_carry_spacing"] == (1 if previous_sum_quanta % 5 == 0 else 5)
    assert result["every_unbounded_carry_has_grid_partner"]


def test_grid_alias_flag_does_not_replace_physical_mask_checks():
    codec = PaperDMC(20, 6, 14760426300877770769).with_mgf(
        Fraction(2199, 10**6), hmax_domain="normalized")
    assert not grid_alias_profile(codec, 2)["grid_alias_possible_in_carry_interval"]
    assert grid_alias_profile(codec, 10)["grid_alias_possible_in_carry_interval"]


@pytest.mark.parametrize("factor", [Fraction(1, 100), Fraction(2), Fraction(1000)])
def test_rescaling_vector_and_bound_preserves_mgf_but_not_extra_capacity(factor):
    # A units change is allowed by MGF's bound semantics, but cannot be
    # advertised as new sum capacity: update and mask period scale together.
    vectors = [[Fraction(1, 100), Fraction(-2, 100)],
               [Fraction(1, 10), Fraction(1, 10)],
               [Fraction(3, 100), Fraction(4, 100)]]
    bound = Fraction(1, 20)
    assert select_masked(vectors, bound) == [0, 2]
    scaled = [[factor * x for x in row] for row in vectors]
    assert select_masked(scaled, factor * bound) == [0, 2]
    period, true_sum = Fraction(1, 50), Fraction(1, 5)
    centered = (true_sum + period / 2) % period - period / 2
    scaled_centered = (factor * true_sum + factor * period / 2) % (factor * period) - factor * period / 2
    assert scaled_centered / factor == centered == 0
    assert centered != true_sum
