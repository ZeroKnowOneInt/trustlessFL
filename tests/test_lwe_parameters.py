import pytest

from trustlessfl.crypto import ORDER, ProtocolError
from trustlessfl.lwe_parameters import (AION_ARTIFACT_HPRF, LweTheoremParameters,
                                        ceil_log2, minimum_regev_window_modulus_bits)
from trustlessfl.numeric import HPRF_MODULUS_192, OUTPUT_MODULUS


def test_theorem_width_uses_exact_ceil_log2():
    assert ceil_log2(16) == 4
    assert ceil_log2(17) == 5
    assert ceil_log2(HPRF_MODULUS_192) == 192
    assert ceil_log2(ORDER) == 2047


def test_original_aion_artifact_hprf_does_not_meet_cited_width_condition():
    artifact = AION_ARTIFACT_HPRF
    assert ceil_log2(artifact["modulus"]) == 259
    with pytest.raises(ProtocolError, match=r"n\*ceil\(log2 q\)=33152"):
        LweTheoremParameters(**artifact, input_bits=32, alpha_numerator=1,
                             alpha_denominator=2**1024, target_bits=128).validate()


@pytest.mark.parametrize("modulus", [ORDER, HPRF_MODULUS_192])
def test_current_reference_width_is_not_a_security_profile(modulus):
    with pytest.raises(ProtocolError, match="LWE key width"):
        LweTheoremParameters(dimension=128, width=8, modulus=modulus,
                             output_modulus=OUTPUT_MODULUS, input_bits=32,
                             alpha_numerator=1, alpha_denominator=2**4096,
                             target_bits=128).validate()


def test_theorem_noise_bound_is_checked_without_float_overflow():
    small = dict(dimension=1, width=5, modulus=17, output_modulus=2,
                 input_bits=1, alpha_numerator=1, target_bits=5)
    LweTheoremParameters(**small, alpha_denominator=320).validate()
    with pytest.raises(ProtocolError, match="rounding/noise"):
        LweTheoremParameters(**small, alpha_denominator=319).validate()


def test_regev_and_hprf_bounds_have_no_common_window_for_p192_profile():
    profile = LweTheoremParameters(dimension=128, width=128 * 192,
                                   modulus=HPRF_MODULUS_192, output_modulus=OUTPUT_MODULUS,
                                   input_bits=32, alpha_numerator=1,
                                   alpha_denominator=2**1024, target_bits=128)
    assert not profile.regev_window_possible()
    assert minimum_regev_window_modulus_bits(128, OUTPUT_MODULUS, 32, 128) == 793
    assert minimum_regev_window_modulus_bits(128, OUTPUT_MODULUS, 128, 128) == 2610
    assert ceil_log2(ORDER) > 793


def test_chosen_alpha_needs_separate_regev_scale_check():
    toy = dict(dimension=1, width=17, modulus=65537, output_modulus=2,
               input_bits=1, alpha_numerator=1, target_bits=1)
    LweTheoremParameters(**toy, alpha_denominator=1000).validate_regev_noise_scale()
    too_small = LweTheoremParameters(**toy, alpha_denominator=100000)
    too_small.validate()
    with pytest.raises(ProtocolError, match="Regev reduction"):
        too_small.validate_regev_noise_scale()
    assert minimum_regev_window_modulus_bits(1, 2, 1, 1) <= 17
