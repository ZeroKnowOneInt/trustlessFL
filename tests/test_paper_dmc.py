from fractions import Fraction
from pathlib import Path

import pytest

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC, evolve_bound, public_mgf_term, round_even, select_masked


@pytest.mark.parametrize("clients,digits", [(1, 1), (5, 1), (6, 2), (50, 2),
                                             (51, 3), (100, 3), (5000, 4)])
def test_extra_digits_exact_boundaries(clients, digits):
    assert PaperDMC(clients, 6, 101).extra_digits == digits


@pytest.mark.parametrize("value,expected", [("0.5", 0), ("1.5", 2), ("-0.5", 0), ("-1.5", -2)])
def test_signed_tie_rounding(value, expected):
    assert round_even(value) == expected


@pytest.mark.parametrize("clients", [2, 10, 100])
def test_paper_small_error_rounds_away(clients):
    codec = PaperDMC(clients, 3, 1000000007)
    # Both signs and worst allowed e, without modular carries.
    for error in (1 - clients, 0, clients - 1):
        masked = [Fraction(-1234, 1000) + Fraction(100 + error, codec.denominator)]
        assert codec.remove(masked, [100]) == [Fraction(-1234, 1000)]


def author_hprf():
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    return OriginalAionHPRF.from_directory(root)


def test_actual_author_carry_and_no_share_dmc_modular_adaptation():
    hprf = author_hprf()
    codec = PaperDMC(2, 6, hprf.p)
    masks = [hprf.hprf(k, 1, 8) for k in (4, 16)]
    aggregate = hprf.hprf(20, 1, 8)
    models = [[Fraction(-1, 10)] * 8, [Fraction(3, 10)] * 8]
    vectors = [codec.mask(x, h) for x, h in zip(models, masks)]
    total = [a + b for a, b in zip(*vectors)]
    assert codec.remove(total, aggregate) != [Fraction(1, 5)] * 8
    assert codec.remove_centered(total, aggregate, sum_bound="1") == [Fraction(1, 5)] * 8


@pytest.mark.parametrize("domain", ["raw", "normalized"])
def test_small_mgf_mask_rejects_ambiguous_sum_lift(domain):
    hprf = author_hprf()
    codec = PaperDMC(10, 6, hprf.p).with_mgf("0.1", hmax_domain=domain)
    with pytest.raises(ProtocolError, match="unique bounded sum"):
        codec.remove_centered([0], [0], sum_bound="1")
    assert codec.period <= Fraction(1, 50)


def test_normalized_dmc_precision_does_not_change_effective_mgf_scale():
    hprf = author_hprf()
    for count in (2, 10, 100):
        codec = PaperDMC(count, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
        assert codec.coefficient / codec.denominator == Fraction(1, 50 * hprf.p)


def test_exact_normalized_same_total_same_key_different_plaintext_sum():
    """This particular original-HPRF/MGF representation is ambiguous.

    Unlike the earlier rounded-mask fixture, this uses exact fractions and
    DMC precision. It is NOT a counterexample to every possible paper mapping.
    """
    hprf = author_hprf()
    codec = PaperDMC(2, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    def execution(keys, models):
        vectors = [codec.mask([x], hprf.hprf(k, 1, 1))[0] for k, x in zip(keys, models)]
        return sum(vectors), sum(keys), sum(models)
    first = execution((1, 19), (Fraction(1, 50), Fraction(0)))
    second = execution((4, 16), (Fraction(0), Fraction(0)))
    assert first[:2] == second[:2]
    assert first[2] != second[2]


def test_signed_representatives_do_not_remove_normalized_carry_ambiguity():
    hprf = author_hprf()
    codec = PaperDMC(2, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    def centered(k):
        value = hprf.hprf(k, 1, 1)[0]
        return value - hprf.p if value > hprf.p // 2 else value
    first, second = (24, 76), (25, 75)
    # The representative convention changes, but does not determine, the lift.
    first_mask = sum(centered(k) for k in first)
    second_mask = sum(centered(k) for k in second)
    assert sum(first) == sum(second) == 100
    assert first_mask - second_mask == hprf.p
    effective = codec.coefficient / codec.denominator
    assert first_mask * effective == second_mask * effective + Fraction(1, 50)


@pytest.mark.parametrize("decimals", [3, 6, 9, 12])
def test_more_dmc_digits_or_mean_first_does_not_fix_normalized_collision(decimals):
    hprf = author_hprf()
    codec = PaperDMC(2, decimals, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    aggregate = hprf.hprf(20, 1, 1)
    def wire(keys, models):
        return sum(codec.mask([x], hprf.hprf(k, 1, 1))[0] for k, x in zip(keys, models))
    first = wire((1, 19), (Fraction(1, 50), Fraction(0)))
    second = wire((4, 16), (Fraction(0), Fraction(0)))
    assert first == second
    # Dividing both sums by the selected count preserves identical inputs.
    assert first / 2 == second / 2
    first_mean, second_mean = Fraction(1, 100), Fraction(0)
    decoded_mean = codec.quantize(codec.residual([first], aggregate)[0] / 2)
    assert first_mean != second_mean
    assert not (decoded_mean == first_mean and decoded_mean == second_mean)


def test_raw_hmax_double_scaling_leaks_plaintext_by_wire_rounding():
    hprf = author_hprf()
    codec = PaperDMC(10, 6, hprf.p).with_mgf("0.1", hmax_domain="raw")
    model = [Fraction(-12345, 1000000)] * 8
    wire = codec.mask(model, hprf.hprf(101, 1, 8))
    assert wire != model
    # An observer needs neither keys nor shares to remove such tiny masks.
    assert [codec.quantize(y) for y in wire] == model


@pytest.mark.parametrize("decimal_wire", [False, True])
@pytest.mark.parametrize("previous", [Fraction(12347, 1000000), Fraction(12347, 3000000)])
def test_noncommensurate_small_mask_can_have_unique_aggregate_lift(previous, decimal_wire):
    hprf = author_hprf()
    codec = PaperDMC(10, 6, hprf.p).with_mgf(previous, hmax_domain="normalized")
    keys = (101, 202, 303, 404)
    dimension = 32
    models = [[Fraction((i + 1) * (-1) ** j, 1000) for j in range(dimension)] for i in range(4)]
    masking = codec.mask_decimal_wire if decimal_wire else codec.mask
    wire = [masking(x, hprf.hprf(k, 1, dimension)) for k, x in zip(keys, models)]
    total = [sum(v[j] for v in wire) for j in range(dimension)]
    expected = [sum(x[j] for x in models) for j in range(dimension)]
    assert codec.remove_quantized_lift(total, hprf.hprf(sum(keys), 1, dimension),
        selected_count=4, decimal_wire=decimal_wire) == expected


@pytest.mark.parametrize("decimal_wire", [False, True])
def test_quantized_lift_does_not_choose_between_commensurate_ambiguous_sums(decimal_wire):
    hprf = author_hprf()
    codec = PaperDMC(2, 6, hprf.p).with_mgf("0.1", hmax_domain="normalized")
    masking = codec.mask_decimal_wire if decimal_wire else codec.mask
    wire = [masking([0], hprf.hprf(k, 1, 1))[0] for k in (4, 16)]
    with pytest.raises(ProtocolError, match="ambiguous"):
        codec.remove_quantized_lift([sum(wire)], hprf.hprf(20, 1, 1),
            selected_count=2, decimal_wire=decimal_wire)


@pytest.mark.parametrize("decimal_wire", [False, True])
def test_bounded_lift_endpoint_and_signed_update_fixtures_never_accept_wrong_sum(decimal_wire):
    from itertools import product
    p = 1000000007
    accepted = rejected = 0
    for magnitude in (Fraction(59, 80000), Fraction(1, 10), Fraction(12347, 1000000)):
        codec = PaperDMC(20, 6, p).with_mgf(magnitude, hmax_domain="normalized")
        for masks in product((0, 1, p // 2, p - 1, p), repeat=2):
            aggregate = sum(masks) % p
            for models in ((Fraction(-1, 1000), Fraction(1, 500)), (Fraction(0), Fraction(0))):
                method = codec.mask_decimal_wire if decimal_wire else codec.mask
                total = sum(method([x], [h])[0] for x, h in zip(models, masks))
                try:
                    result = codec.remove_quantized_lift([total], [aggregate],
                        selected_count=2, decimal_wire=decimal_wire)
                except ProtocolError:
                    rejected += 1
                else:
                    assert result == [sum(models)]
                    accepted += 1
    assert accepted and rejected


def test_mask_bounds_do_not_hide_genuine_endpoint_ambiguity():
    from trustlessfl.paper_dmc import QuantizedLiftError
    p = 1000000007
    codec = PaperDMC(20, 6, p).with_mgf(Fraction(59, 80000), hmax_domain="normalized")
    # Wire=0, aggregate_H=0 fits both update=0 with mask=0 and
    # update=-2*period with mask=2*period. Both masks are physically bounded.
    with pytest.raises(QuantizedLiftError) as exc:
        codec.remove_quantized_lift([0], [0], selected_count=2, decimal_wire=True)
    assert exc.value.code == "ambiguous"


def test_mgf_masks_only_inclusive_boundary():
    assert select_masked([[3, 4], [0, 6], [-3, -4]], 5) == [0, 2]


def test_paper_bound_uses_distinct_historical_aggregate_masks():
    codec = PaperDMC(2, 3, 1009)
    older = public_mgf_term([3, 4], [100, 200], codec)
    newer = public_mgf_term([0, 2], [300, 400], codec)
    assert older == 5 + Fraction(200, codec.denominator)
    assert newer == 2 + Fraction(400, codec.denominator)
    bound = evolve_bound("0.2", older_term=older, newer_term=newer)
    assert bound == Fraction(1, 5) * newer / older
    # Must not reuse the same old mask norm in both slots (source MMF).
    assert bound != Fraction(1, 5) * (2 + Fraction(200, codec.denominator)) / older


def test_public_sum_is_not_silently_converted_to_selected_mean():
    codec = PaperDMC(2, 3, 1009)
    assert public_mgf_term([6, 8], [0, 0], codec) == 10
    assert public_mgf_term([3, 4], [0, 0], codec) == 5


def test_bound_growth_is_not_silently_clipped_and_zero_denominator_rejected():
    assert evolve_bound(2, older_term=1, newer_term=3) == 6
    with pytest.raises(ProtocolError, match="historical"):
        evolve_bound(2, older_term=0, newer_term=3)


def test_small_public_fixture_audit():
    from experiments.audit_paper_dmc import audit
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    result = audit(root, rounds=2, dimension=8, clients=3)
    assert result["additional_mask_shares"] == 0
    assert result["hprf"]["max_centered_hprf_error"] <= 2
    assert result["modes"]["dmc_only"]["centered_mismatch_coordinates"] == 0
    assert result["modes"]["dmc_only"]["centered_rejections"] == 0
    assert result["modes"]["mgf_normalized_hmax"]["centered_rejections"] > 0


def test_conditional_lift_profile_audit_never_counts_rejection_as_success():
    from experiments.audit_quantized_lift import audit
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    result = audit(root, rounds=2, dimension=4)
    assert result["additional_mask_shares"] == 0
    assert all(row["wrong_accepted_rounds"] == 0 for row in result["results"].values())
    assert result["results"]["bootstrap_0.1/q4"]["ambiguous_rounds"] == 2
    assert result["results"]["author_e2_bootstrap_1/q4"]["ambiguous_rounds"] == 2
    assert result["results"]["public_decimal_0.012347/q4"]["verified_rounds"] == 2


def test_public_history_restores_mean_grid_and_distinguishes_sum(tmp_path):
    import json
    from experiments.audit_quantized_lift import profiles
    path = tmp_path / "public.json"
    path.write_text(json.dumps({"history": [{"round": 1, "selected": [1, 2, 3],
        "result": [0.012347 / 3, -0.001]}]}))
    result = profiles(path)
    assert result["history_r1_mean"] == Fraction(12347, 3000000)
    assert result["history_r1_sum"] == Fraction(12347, 1000000)


def test_invalid_public_quantization_history_is_rejected(tmp_path):
    import json
    from experiments.audit_quantized_lift import profiles
    path = tmp_path / "public.json"
    path.write_text(json.dumps({"history": [{"round": 1, "selected": [1], "result": [0.0123474]}]}))
    with pytest.raises(ValueError, match="quantization"):
        profiles(path)


def test_public_checkpoint_bootstrap_is_hash_pinned_and_not_fixed_artifact_bootstrap(tmp_path):
    import hashlib
    import json
    import numpy as np
    from experiments.audit_quantized_lift import reference_profiles
    reference = tmp_path / "reference.npz"
    weights = np.zeros(61706, dtype=np.float32)
    weights[0], weights[-11] = np.float32(0.79388189315795898), np.float32(0.58977800607681274)
    np.savez(reference, weights=weights)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"training": {"input_root": str(tmp_path),
        "input_sha256": {"reference.npz": hashlib.sha256(reference.read_bytes()).hexdigest()}}}))
    values, metadata = reference_profiles(manifest)
    assert values["reference_full_initial_model"] == Fraction(float(weights[0]))
    assert values["reference_classifier_initial_model"] == Fraction(float(weights[-11]))
    assert metadata["scope"].endswith("NOT author E2 fixed bootstrap")
    np.savez(reference, weights=weights + 1)
    with pytest.raises(ValueError, match="hash"):
        reference_profiles(manifest)


def test_author_e2_bootstrap_is_explicit_fixed_one_not_public_checkpoint_norm():
    import ast
    path = Path(__file__).resolve().parents[2] / "Aion/input_validation/FL_Backdoor_CV/roles/server.py"
    if not path.exists():
        pytest.skip("author source required")
    tree = ast.parse(path.read_text())
    values = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Tuple):
            for target in node.targets:
                if isinstance(target, ast.Tuple):
                    for name, value in zip(target.elts, node.value.elts):
                        if isinstance(name, ast.Attribute) and name.attr == "linf_norm":
                            values.append(ast.literal_eval(value))
    assert values == [1]
