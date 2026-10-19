"""Executable witnesses for output leakage and robustness limits, not proofs of safety."""
import pytest
from experiments import audit_private_bound_security as audit


@pytest.mark.parametrize("case", [
    audit.isolation, audit.threshold_requery, audit.cohort_requery,
    audit.mean_only, audit.minimum_guard, audit.dynamic_capture,
    audit.benign_cancellation, audit.direction_poison,
    audit.history_authentication, audit.public_small_mask, audit.wire_audit,
])
def test_security_counterexample_is_reproducible(case):
    assert "id" in case()
