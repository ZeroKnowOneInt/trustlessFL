from fractions import Fraction
from pathlib import Path

import pytest

from experiments.audit_scaled_sum_collision import audit
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.paper_dmc import PaperDMC, QuantizedLiftError
from trustlessfl.source_paper_numeric import FILTER_RULE, mask_integer_wire, recover


def original_source():
    source = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not (source / "matrix").is_file():
        pytest.skip("original author matrix required")
    return source


def test_full_numeric_sum_and_sum_key_can_collide_after_inclusive_mgf():
    source = original_source()
    result = audit(source)
    assert result["dimension"] == 8 and result["hprf_round"] == 4
    assert result["examined_public_pairs"] <= 512
    assert result["same_full_masked_sum"] and result["same_aggregate_key"]
    assert result["same_selected_set"] and result["different_plaintext_sums"]
    assert result["decoder_rejection"] == "ambiguous"
    assert not result["individual_masked_vectors_identical"]
    assert not result["experiment_private_inputs_read"]
    assert result["additional_mask_shares"] == 0
    hprf = OriginalAionHPRF.from_directory(source)
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    for execution in result["executions"]:
        assert sum(execution["public_fixture_keys"]) == result["aggregate_key"]
        assert execution["selected"] == [1, 0]
        assert len(execution["encoded_sum"]) == 8
        actual = [mask_integer_wire(codec, model, hprf.hprf(key, 4, 8)) for key, model
                  in zip(execution["public_fixture_keys"], execution["encoded_updates"], strict=True)]
        assert actual == execution["masked_vectors"]
        assert [sum(row[j] for row in actual) for j in range(8)] == result["masked_sum"]
        assert all(sum(Fraction(x, codec.denominator)**2 for x in row)
                   <= Fraction(result["bound"])**2 for row in actual)


def test_source_recover_rejects_full_sum_collision_instead_of_selecting_an_answer():
    source = original_source()
    result = audit(source)
    hprf = OriginalAionHPRF.from_directory(source)
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    manifest = dict(dimension=8, decimals=6, paper_numerics=dict(
        projection=[0, 8], filter_rule=FILTER_RULE))
    pending = dict(selected=result["executions"][0]["selected"],
                   total=result["masked_sum"], bound_decimal=result["bound"])
    state = {}
    with pytest.raises(QuantizedLiftError) as exc:
        recover(manifest, state, codec, hprf, 4, pending, result["aggregate_key"])
    assert exc.value.code == "ambiguous" and state == {}


def test_aggregate_vss_opening_and_all_aggregate_shares_do_not_determine_the_carry():
    from trustlessfl.crypto import (MODULUS, GENERATOR, PEDERSEN_GENERATOR,
        aggregate_commitments, pedersen_verify_share, pedersen_verify_opening,
        pedersen_reconstruct_pair, sum_pedersen_shares)
    result = audit(original_source())
    aggregates = []
    for execution in result["executions"]:
        commitments, shares = [], []
        # Public fixture polynomials with identical aggregate coefficients;
        # NOT production randomness, nor actual experiment shares.
        for key, blind, slope, blind_slope in zip(execution["public_fixture_keys"],
                (11, 31), (123, 456), (321, 654), strict=True):
            com = [(pow(GENERATOR, key, MODULUS) * pow(PEDERSEN_GENERATOR, blind, MODULUS)) % MODULUS,
                   (pow(GENERATOR, slope, MODULUS) * pow(PEDERSEN_GENERATOR, blind_slope, MODULUS)) % MODULUS]
            packet = {i: (key + slope * i, blind + blind_slope * i) for i in range(1, 5)}
            assert all(pedersen_verify_share(i, pair, com) for i, pair in packet.items())
            commitments.append(com)
            shares.append(packet)
        combined = aggregate_commitments(commitments)
        summed = {i: sum_pedersen_shares([s[i] for s in shares]) for i in range(1, 5)}
        assert pedersen_verify_opening((20001, 42), combined)
        assert pedersen_reconstruct_pair(summed, combined) == (20001, 42)
        aggregates.append((combined, summed))
    assert aggregates[0] == aggregates[1]
    # Individual commitments and masked vectors are not identical; this says
    # only that the aggregate opening/share data adds no disambiguating carry.
    assert result["executions"][0]["encoded_sum"] != result["executions"][1]["encoded_sum"]


@pytest.mark.parametrize("dimension,max_pairs", [(1, 512), (17, 512), (True, 512),
                                                 (8, 1), (8, 4097)])
def test_public_fixture_search_has_explicit_finite_bounds(dimension, max_pairs):
    with pytest.raises(ValueError, match="bounded public fixture"):
        audit(Path("unused-source"), dimension=dimension, max_pairs=max_pairs)


def test_audit_does_not_invent_a_collision_when_search_budget_is_insufficient():
    with pytest.raises(ValueError, match="within audit budget"):
        audit(original_source(), max_pairs=2)
