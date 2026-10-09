from pathlib import Path

import pytest

from experiments.audit_source_output_information import audit, integer_sum_from_public_mean


@pytest.mark.parametrize("count", [2, 20, 100])
def test_public_mean_reconstructs_signed_quantized_sum_uniquely(count):
    expected = [-1000000000, -3901, -1, 0, 1, 17, 1000000000]
    values = [z/(count*10**6) for z in expected]
    recovered, error = integer_sum_from_public_mean(values, count, 10**6)
    assert recovered == expected and error < 0.00001


@pytest.mark.parametrize("values", [[float("inf")], [float("nan")], [True], ["0.1"], [0.00000025], [1e16]])
def test_nonfinite_offgrid_or_ambiguous_public_mean_is_rejected(values):
    with pytest.raises(ValueError):
        integer_sum_from_public_mean(values, 2, 10**6)


def test_existing_flower_output_infers_mask_sum_without_any_private_input(monkeypatch):
    root = Path(__file__).resolve().parents[1]/".cache/same-scale-fmnist-official-20261008"
    if not (root/"results.json").is_file():
        pytest.skip("completed official Flower artifact not installed")
    opened = []
    original = Path.open

    def guarded(path, *args, **kwargs):
        opened.append(path)
        assert not any(part.startswith("private") for part in path.parts)
        assert path.name not in ("node-configs.json", "reference.npz")
        assert path.suffix != ".npz"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    report = audit(root)
    assert not report["private_keys_or_shares_read"]
    assert not report["aggregate_key_read"]
    assert not report["training_inputs_read"]
    assert not report["carry_vector_exported"]
    assert report["additional_mask_shares"] == 0
    assert len(report["rounds"]) == 4
    assert all(r["inferred_integer_coordinates"] == 61706 for r in report["rounds"])
    verified = [r for r in report["rounds"] if r["received_vector_digest_verified"]]
    assert [r["round"] for r in verified] == [1]
    assert verified[0]["inferred_mask_coordinates"] == 61706
    assert verified[0]["mask_projection_linf_matches_committed_metadata"]
    assert verified[0]["known_aggregate_key_would_suffice_for_carry"]
    for row in report["rounds"][1:]:
        assert row["mask_inference_status"] == "missing-received-vectors"
        assert row["inferred_mask_coordinates"] == 0
        assert row["mask_projection_linf_matches_committed_metadata"] is None
        assert row["known_aggregate_key_would_suffice_for_carry"] is None
    assert all(r["carry_precision_condition_met"] for r in report["rounds"])
    assert opened
