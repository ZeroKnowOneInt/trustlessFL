import numpy as np
import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl.fmnist_no_wrap_math import audit_updates, quantize


def test_small_and_large_masks_recover_identical_filtered_integer_sum():
    updates = [(2, 0), (-2, 0), (1, 1), (2, 2)]
    result, audit = audit_updates(updates, scale=1, cap=2, threshold=4, seed=42)
    assert result == {"status": "ok", "count": 3, "sum": (1, 1)}
    assert audit["excluded_normal_clients"] == 1
    assert len(audit["profiles"]) == 4
    assert all(p["sum_error"] == p["coordinate_recovery_error"] == 0 for p in audit["profiles"])
    assert audit["profiles"][0]["old_centered_modular_alias_coordinates"] == 2


def test_aggregate_abort_does_not_release_single_survivors_sum():
    result, audit = audit_updates([(1, 0), (2, 2), (2, 2), (2, 2)],
                                 scale=1, cap=2, threshold=4, seed=1)
    assert result == {"status": "abort"}
    assert audit["excluded_normal_clients"] == 3


def test_quantization_bounds_before_integer_conversion_and_never_clips():
    with pytest.raises(ProtocolError, match="no clipping"):
        quantize(np.array([1e100]), 10000, 20000)
    assert quantize(np.array([0.125, 0.375, -0.125, -0.375]), 4, 20000) == (0, 2, 0, -2)


@pytest.mark.parametrize("values", (np.array([np.nan]), np.array([np.inf]), np.array([1], dtype=np.float32)))
def test_invalid_training_delta_is_rejected(values):
    with pytest.raises(ProtocolError):
        quantize(values, 10000, 20000)
