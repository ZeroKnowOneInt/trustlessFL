from fractions import Fraction
from pathlib import Path

import pytest

from experiments.audit_paper_mapping import audit, denominator, rounded


@pytest.mark.parametrize("clients,expected", [(2, 10**7), (20, 10**8), (100, 10**9)])
def test_independent_algorithm_seven_denominator(clients, expected):
    assert denominator(clients, 6) == expected


@pytest.mark.parametrize("clients", [2, 20, 100])
def test_independent_literal_dmr_removes_both_extreme_small_errors(clients):
    d = denominator(clients, 6)
    for e in (1 - clients, 0, clients - 1):
        assert rounded(Fraction(-1234, 10**6) + Fraction(e, d), 6) == Fraction(-1234, 10**6)


@pytest.mark.parametrize("clients,decimals", [(True, 6), (0, 6), (20, -1), (20, True)])
def test_invalid_units_rejected(clients, decimals):
    with pytest.raises(ValueError):
        denominator(clients, decimals)


def test_original_outputs_independently_distinguish_carry_and_small_error():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.source_paper_numeric import paper_codec, SUM_SCALE_SOURCE
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    result = audit(root)
    assert result["nonzero_carry_coordinates"] > 0
    assert abs(result["first_carry"]["small_error"]) <= result["clients"] - 1
    literal, raw, normalized = (result["modes"][name] for name in (
        "literal_dmc", "native_mgf_then_dmc", "dmc_then_normalized_mgf"))
    assert literal["literal_mismatches"] > 0
    assert literal["centered_verified_coordinates"] == 32
    assert raw["decimal_plaintext_rounding_matches"] == raw["wire_coordinates"]
    assert normalized["literal_mismatches"] > 0
    assert normalized["centered_precondition_rejections"] == 4
    assert result["normalized_scale_independent_of_extra_digits"]
    assert result["additional_mask_shares"] == 0
    manifest = dict(clients=list(range(20)), dimension=8, decimals=6,
        paper_numerics=dict(initial_linf="0.1", beta="0.2", projection=[0, 8],
                            scale_source=SUM_SCALE_SOURCE))
    current = paper_codec(manifest, OriginalAionHPRF.from_directory(root), 1)
    assert current.coefficient / current.denominator == Fraction(normalized["effective_scale"])
    assert current.period == Fraction(normalized["period"])
    # Increasing DMC precision does not secretly enlarge the normalized ring.
    finer = audit(root, decimals=7)
    assert finer["modes"]["dmc_then_normalized_mgf"]["period"] == normalized["period"]
    assert Fraction(finer["modes"]["native_mgf_then_dmc"]["period"]) == Fraction(raw["period"]) / 10
