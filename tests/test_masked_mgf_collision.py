from pathlib import Path

import pytest

from experiments.audit_masked_mgf_collision import audit


def test_identical_decimal_messages_pass_filter_but_have_different_update_sums():
    source = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not (source / "matrix").is_file():
        pytest.skip("author matrix required")
    result = audit(source)
    assert result["same_individual_masked_values"]
    assert result["same_filter_result"]
    assert result["same_aggregate_decoder_inputs"]
    assert result["encoded_sums"] == [20000, 0]
    assert result["decoder_rejection"] == "ambiguous"
    assert result["additional_mask_shares"] == 0
