"""Arithmetic/security-boundary regressions, not protocol/ZKP integration tests."""

import importlib.util
from fractions import Fraction
from pathlib import Path

import pytest

from experiments.audit_split_wire_amr import (
    audit, binding_counterexample, capacity, center, inverse_scalar_outputs,
    lagrange, round_integer,
    subset_difference_counterexample,
)
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ORDER


SOURCE = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"


@pytest.fixture(scope="module")
def original():
    if not (SOURCE / "matrix").is_file():
        pytest.skip("original author HPRF matrix required")
    return OriginalAionHPRF.from_directory(SOURCE)


@pytest.fixture(scope="module")
def report(original):
    return audit(SOURCE)


def test_toy_capacity_and_binding_attack():
    result = binding_counterexample()
    assert result["honest_wire"] == [96, 94]
    assert result["forged_wire"] == [3, 94]
    assert result["honest_sum"] == "1/2"
    assert result["forged_sum"] == "3/5"
    assert all(result["capacity"].values())


def test_strict_capacity_and_rounding_inequalities():
    assert not capacity(101, 8, 2, 3, 4)["rounding_safe"]
    assert not capacity(98, 8, 2, 3, 1)["signed_capacity_safe"]
    assert all(capacity(99, 8, 2, 3, 1).values())
    assert center(80, 101) == -21  # p > sum is insufficient for signed sums.
    assert center(-40, 101) == -40


@pytest.mark.parametrize("value,divisor,expected", [
    (39, 8, 5), (-39, 8, -5), (4, 8, 0), (12, 8, 2), (-12, 8, -2),
])
def test_exact_integer_decoding(value, divisor, expected):
    assert round_integer(value, divisor) == expected


def test_permanent_exclusion_itself_exposes_removed_key():
    result = subset_difference_counterexample()
    assert not result["rejoining_required"]
    assert result["recovered_removed_key"] == result["expected_removed_key"] == 83937


def test_relaxed_l2_residual_is_not_exact_mask_binding(report):
    result = report["relaxed_l2"]
    assert result["relaxed_residual_norm_passes"]
    assert not result["actual_per_coordinate_rounding_bound_passes"]
    assert result["decoded_z_sum"] == 1
    assert result["proven_z_sum"] == 0
    assert result["malicious_clients"] == 20
    assert result["honest_decoded_z_sum"] == 0
    assert result["exact_rounding_rejects_clients"] == 20
    assert Fraction(result["maximum_squared_norm_ratio"]) < 1


def test_sharing_coefficients_preserve_secret_but_not_a_different_ring(original):
    assert lagrange((1, 2), ORDER) == [2, -1]
    secret, slope = 123456, ORDER // 2 + 100
    shares = [(secret + slope * i) % ORDER for i in (1, 2)]
    integer_reconstruction = 2 * shares[0] - shares[1]
    assert integer_reconstruction % ORDER == secret
    assert integer_reconstruction % original.q != secret


def test_matched_ring_weights_and_composite_denominator(original):
    assert lagrange((1, 2), original.q) == [2, -1]
    assert lagrange((2, 3), original.q) == [3, -2]
    weights = lagrange((1, 3), original.q)
    assert sum(weights) % original.q == 1
    assert max(map(abs, weights)) > original.p
    assert original.q == 5 * original.p
    with pytest.raises(ValueError):
        lagrange((1, 6), original.q)


def test_asr_modular_control_preserves_all_288_coordinates(report):
    result = report["arithmetic"]
    control = result["variants"]["asr_control"]
    assert control["exact_coordinates"] == control["coordinates"] == 288
    assert control["fixed_delta_certified_cases"] == 9
    assert control["max_abs_error"] == 1
    assert result["real_mask_sum_wrap_coordinates"] == 241


def test_amr_failure_is_not_hidden_by_cherry_picking_share_subset(report):
    variants = report["arithmetic"]["variants"]
    assert variants["current_order_1_2"]["exact_coordinates"] == 192
    assert variants["current_order_1_3"]["exact_coordinates"] == 0
    assert variants["current_order_2_3"]["exact_coordinates"] == 192
    assert variants["matched_q_ring_1_2"]["exact_coordinates"] == 288
    assert variants["matched_q_ring_1_3"]["exact_coordinates"] == 234
    assert variants["matched_q_ring_2_3"]["exact_coordinates"] == 288
    for case in variants["matched_q_ring_1_3"]["cases"]:
        assert not case["minimum_delta_fits_capacity"]
    # Observed success is NOT a worst-case certificate for delta=2*N+2.
    first = variants["matched_q_ring_2_3"]["cases"][0]
    assert first["exact_coordinates"] == 32
    assert not first["fixed_delta_checks"]["rounding_safe"]
    assert first["minimum_delta_fits_capacity"]


@pytest.mark.parametrize("key", range(505))
def test_scalar_inverse_keeps_true_key_including_raw_p_boundary(key):
    hprf = OriginalAionHPRF(1, 2, 101, 505, [[1, 2]])
    outputs = [v % hprf.p for v in hprf.hprf(key, 1, 4)]
    result = inverse_scalar_outputs(hprf, 1, outputs)
    assert key in result["candidates"]
    assert result["candidates"] == [k for k in range(505)
        if [v % hprf.p for v in hprf.hprf(k, 1, 4)] == outputs]


def test_scalar_inverse_skips_noninvertible_inputs_and_handles_next_block():
    hprf = OriginalAionHPRF(1, 2, 101, 505, [[1, 2]])
    outputs = [v % hprf.p for v in hprf.hprf(313, 5, 4)]
    assert inverse_scalar_outputs(hprf, 5, outputs[:2])["candidates"] is None
    result = inverse_scalar_outputs(hprf, 5, outputs)
    assert 313 in result["candidates"]
    assert result["coordinate_indices"][0] == 2


def test_output_only_attack_does_not_need_small_key_prior(report):
    result = report["scalar_output_inversion"]
    assert not result["key_range_prior_used"]
    for row in result["public_output_fixtures"]:
        assert row["exact"]
        assert row["coordinate_indices"] == [0, 1]
    assert result["matched_q_amr_recovered_sum_keys"] == [187344, 103407]
    assert result["matched_q_amr_removed_key"] == result["expected_removed_key"] == 83937


def test_large_key_attack_also_matches_author_code_not_only_port(original):
    if not (SOURCE / "hprf.py").is_file():
        pytest.skip("author source file required")
    spec = importlib.util.spec_from_file_location("author_hprf_amr_audit", SOURCE / "hprf.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    reference = module.HPRF(original.n, original.m, original.p, original.q, str(SOURCE / "matrix"))
    for key in (31337, original.q // 2 + 12345, original.q - 1234567):
        outputs = reference.hprf(key, 4, 32)
        assert outputs == original.hprf(key, 4, 32)
        result = inverse_scalar_outputs(original, 4, [int(v) % original.p for v in outputs])
        assert result["candidates"] == [key]


def test_report_does_not_claim_runtime_or_security_completion(report):
    assert not report["runtime_changed"]
    assert not report["production_security_claim"]
    assert "no ZKP" in report["scope"]
    assert len(report["source_sha256"]["matrix"]) == 64


def test_capacity_uses_exact_fraction():
    assert capacity(101, 6, 2, 3, Fraction(5, 2))["rounding_safe"]
    assert not capacity(101, 5, 2, 3, Fraction(5, 2))["rounding_safe"]
