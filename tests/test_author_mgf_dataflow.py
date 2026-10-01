from pathlib import Path

import pytest

from experiments.audit_author_mgf_dataflow import audit


def test_public_author_tree_separates_asr_mmf_and_training_mgf():
    root = Path(__file__).resolve().parents[2] / "Aion"
    if not root.exists():
        pytest.skip("author source required")
    result = audit(root)
    assert all(result["checks"].values())
    assert result["conclusion"]["not_present_in_training_artifact"].startswith("client-side")
    assert set(result["normalized_function_sha256"]) == {
        "SA_ClientAgent.sendVectors", "SA_AggregatorAgent.report_process",
        "SA_AggregatorAgent.reconstruction_process", "SA_AggregatorAgent.MMF",
        "aggregation_rules.aion",
    }
