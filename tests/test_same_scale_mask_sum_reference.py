from fractions import Fraction

import pytest

from experiments.audit_same_scale_mask_sum_reference import (
    audit, public_fixture_mask_sum, recover_with_public_fixture_mask_sum)
from experiments.audit_same_scale_feasibility import SOURCE
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.paper_dmc import PaperDMC
from trustlessfl.source_paper_numeric import mask_integer_wire


def test_public_reference_corrects_collision_and_rejects_amplification():
    if not (SOURCE/"matrix").is_file():
        pytest.skip("author HPRF artifact required")
    result = audit(full_dimension=1024)
    assert result["runtime_modified"] is False
    assert result["privacy_proved"] is False
    assert result["extra_client_shares"] == 0
    assert result["original_scale_and_mgf_unchanged"]
    assert all(r["coordinate_mismatches"] == 0 for r in result["fixtures"])
    assert all(r["mgf_accepted"] == r["selected_count"] for r in result["fixtures"])
    assert all(r["public_outputs_imply_true_decimal_mask_sum"] for r in result["fixtures"])
    assert all(r["output_inferred_carry_matches_true"] for r in result["fixtures"])
    assert any(r["nonzero_inferred_carry_coordinates"] > 0 for r in result["fixtures"])
    assert any(r["sum_coordinates_outside_centered_period"] > 0 for r in result["fixtures"])
    assert all(Fraction(r["max_mean_quantization_error"]) <= Fraction(1, 2*10**6)
               for r in result["fixtures"])
    assert result["collision"]["aggregate_key_decoder"] == "ambiguous"
    assert result["collision"]["true_decimal_mask_sums_differ"]
    assert result["collision"]["correct_integer_sums_recovered"]
    assert result["amplification"]["off_grid_attack_rejected"]
    assert result["amplification"]["valid_grid_change_has_unit_response"]
    assert result["computation_target"]["naive_sharewise_mod_q_conversion_valid"] is False


def test_signed_exact_integer_sum_and_rounded_mask_endpoint():
    codec = PaperDMC(2, 6, 101).with_mgf("0.1", hmax_domain="normalized")
    encoded = [[-123, 0, 17], [7, -19, 0]]
    masks = [[101, 0, 70], [80, 101, 2]]
    wires = [mask_integer_wire(codec, z, h) for z, h in zip(encoded, masks, strict=True)]
    rounded = [mask_integer_wire(codec, [0]*3, h) for h in masks]
    wire_sum = [sum(r[j] for r in wires) for j in range(3)]
    mask_sum = [sum(r[j] for r in rounded) for j in range(3)]
    assert recover_with_public_fixture_mask_sum(codec, wire_sum, mask_sum) == [-116, -19, 17]


@pytest.mark.parametrize("delta", [-9, -1, 1, 9])
def test_off_grid_wire_is_rejected_instead_of_corrected_to_large_update(delta):
    codec = PaperDMC(2, 6, 101)
    with pytest.raises(ValueError, match="off the integer update grid"):
        recover_with_public_fixture_mask_sum(codec, [20+delta], [20])


@pytest.mark.parametrize("z", [-1000000, -1, 0, 1, 1000000])
def test_response_to_valid_integer_grid_change_is_linear(z):
    codec = PaperDMC(2, 6, 101)
    extra = codec.denominator//10**codec.decimals
    assert recover_with_public_fixture_mask_sum(codec, [20+extra*z], [20]) == [z]


@pytest.mark.parametrize("wire,masks", [([0], []), ([0.0], [0]), ([0], [-1]), ([True], [0])])
def test_reference_rejects_malformed_wire(wire, masks):
    with pytest.raises(ValueError):
        recover_with_public_fixture_mask_sum(PaperDMC(2, 6, 101), wire, masks)


@pytest.mark.parametrize("keys,dimension", [([], 8), ([0], 8), ([100001], 8), ([1], 0)])
def test_public_mask_oracle_has_explicit_fixture_limits(keys, dimension):
    # No source read for malformed inputs; the helper checks them first.
    with pytest.raises(ValueError):
        public_fixture_mask_sum(PaperDMC(2, 6, 101), None, keys, 4, dimension)
