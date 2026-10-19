"""Test canonical private input binding, not the cryptographic MPC runtime."""
from dataclasses import replace

import pytest

from experiments.run_private_bound_mpc import backend_prime_for
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.mpc_external_client import prepare_bits
from trustlessfl.private_bound import NoWrapPolicy, ReferenceSubmission, aggregate, scale_canonical_mask


def decode_digits(bits):
    return sum(value << position for position, value in enumerate(bits))


@pytest.mark.parametrize("mask_max", (1, 15, 840000021, 2**128))
def test_private_wire_recovers_original_endpoint_and_signed_values(mask_max):
    hprf = OriginalAionHPRF(1, 2, 101, 505, [[1, 2]])
    policy = NoWrapPolicy(2, 2, 2, 1, 5, mask_max, 8)
    rows = []
    for key, update in ((504, (2, -2)), (350, (-2, 2))):
        raw = hprf.hprf(key, 1, 2)
        if key == 504:
            assert raw[0] == hprf.p  # Canonical endpoint must become zero.
        bits = prepare_bits(policy, key, hprf, 1, update)
        assert set(bits) <= {0, 1}
        key_width = (hprf.q-1).bit_length()
        wire_width = policy.widths()["offset_unsigned"]
        assert len(bits) == key_width + 2*wire_width
        assert decode_digits(bits[:key_width]) == key
        offsets = tuple(decode_digits(bits[key_width+j*wire_width:key_width+(j+1)*wire_width]) for j in range(2))
        masks = tuple(scale_canonical_mask(h % hprf.p, hprf.p, mask_max) for h in raw)
        rows.append(ReferenceSubmission(offsets, masks))
    assert aggregate(policy, rows, mode="plaintext-reference") == {"status": "ok", "count": 2, "sum": (0, 0)}


@pytest.mark.parametrize("key", (-1, 505, True, 0.5))
def test_external_key_domain_is_validated(key):
    with pytest.raises(ValueError, match="key domain"):
        prepare_bits(NoWrapPolicy(2, 2, 2, 1, 5, 15, 8), key,
                     OriginalAionHPRF(1, 2, 101, 505, [[1, 2]]), 1, (0, 0))


def test_nonboolean_attack_fixture_is_encoded_for_native_rejection():
    policy = NoWrapPolicy(2, 2, 2, 1, 5, 15, 8)
    bits = prepare_bits(policy, 1, OriginalAionHPRF(1, 2, 101, 505, [[1, 2]]), 1, (0, 0), mutation="nonboolean")
    assert bits[-1] == 2
    assert set(bits[:-1]) <= {0, 1}


def test_backend_field_must_cover_application_and_statistical_margin():
    assert backend_prime_for(85) == 2**127-1
    assert backend_prime_for(86) == 2**255-19
    assert backend_prime_for(213) == 2**255-19
    for width in (214, 0, True):
        with pytest.raises(ProtocolError):
            backend_prime_for(width)
