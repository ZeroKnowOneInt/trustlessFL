from fractions import Fraction
from pathlib import Path

import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl.paper_dmc import PaperDMC, select_masked


def test_scaled_ring_residual_preserves_scale_but_is_not_real_sum():
    # Prime modulus, exact illustrative H values; no HPRF rounding error.
    codec = PaperDMC(2, 2, 11, coefficient=100)
    assert codec.period == Fraction(11, 10)
    wire = [codec.mask([0], [h])[0] for h in (8, 7)]
    assert sum(wire) == Fraction(3, 2)
    assert codec.residual([sum(wire)], [4]) == [codec.period]
    assert codec.residual_modulo([sum(wire)], [4]) == [0]
    # This toy ring demonstrates the algebra only; its worst-case original
    # HPRF rounding bound is too large to certify two-decimal model recovery.
    with pytest.raises(ProtocolError, match="rounding error"):
        codec.remove_centered([sum(wire)], [4], sum_bound="0.1")
    # Adding one period to a real sum leaves the same residue.
    assert codec.residual_modulo([sum(wire) + codec.period], [4]) == [0]


def test_decimal_rounding_is_included_in_bounded_lift_precision():
    codec = PaperDMC(20, 3, 1000000007, coefficient=Fraction(9, 4))
    assert codec.remove_centered([0], [0], sum_bound=1) == [0]
    with pytest.raises(ProtocolError, match="rounding error"):
        codec.remove_centered([0], [0], sum_bound=1, decimal_wire=True)
    assert codec.remove_centered([0], [0], sum_bound=1,
                                 selected_count=2, decimal_wire=True) == [0]


@pytest.mark.parametrize("count", [0, -1, 21, True, 1.5])
def test_selected_count_must_be_a_valid_integer(count):
    with pytest.raises(ProtocolError, match="selected count"):
        PaperDMC(20, 6, 101).remove_centered([0], [0], sum_bound=0,
                                            selected_count=count)


def test_decoded_sum_outside_public_bound_rejected():
    codec = PaperDMC(2, 3, 1000000007)
    with pytest.raises(ProtocolError, match="outside independent public bound"):
        codec.remove_centered([Fraction(2)], [0], sum_bound=1)


def test_masked_norm_acceptance_does_not_prove_unique_sum_range():
    codec = PaperDMC(20, 6, 1000000007).with_mgf("0.1", hmax_domain="normalized")
    mgf_bound = 2 * codec.period
    assert select_masked([[mgf_bound]], mgf_bound) == [0]
    with pytest.raises(ProtocolError, match="unique bounded sum"):
        codec.remove_centered([mgf_bound], [0], sum_bound=mgf_bound,
                              selected_count=1, decimal_wire=True)


def test_original_hprf_scaled_ring_audit_keeps_success_and_limits_separate():
    from experiments.audit_scaled_ring import audit
    source = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not (source / "matrix").is_file():
        pytest.skip("original author HPRF matrix required")
    result = audit(source, rounds=2, clients=20, dimension=8)
    assert result["bounded_verified_coordinates"] == {"exact": 48, "decimal": 48}
    assert result["nonzero_carry_coordinates"] > 0
    assert result["max_centered_hprf_error"] <= 19
    assert result["aggregate_mask_norm_example"] is not None
    alias = result["modulo_wire_alias"]
    assert alias["same_individual_keys"] and alias["same_modulo_vectors"]
    assert alias["same_filter_result"] and alias["unwrapped_vectors_differ"]
    assert alias["plaintext_sums"] == ["0", "1/50"]
    assert result["modulo_changes_mgf"]["ordinary_selected"] == [1]
    assert result["modulo_changes_mgf"]["modulo_selected"] == [0, 1]
    assert result["additional_mask_shares"] == 0


def public_history_fixture(tmp_path):
    import hashlib
    import json
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.source_paper_numeric import paper_codec, descriptor
    source_root = Path(__file__).resolve().parents[2] / "Aion"
    source = source_root / "agent/Aion/HPRF"
    if not (source / "matrix").is_file():
        pytest.skip("original author HPRF matrix required")
    hprf = OriginalAionHPRF.from_directory(source)
    manifest = dict(clients=list(range(20)), decimals=6, dimension=1,
                    **{"source-root": str(source_root), "source-sha256": {
                        f"agent/Aion/HPRF/{name}": hashlib.sha256((source / name).read_bytes()).hexdigest()
                        for name in ("initialization_values", "matrix")}},
                    paper_numerics=dict(initial_linf="0.1", beta="0.2", projection=[0, 1]))
    codec = paper_codec(manifest, hprf, 1)
    result = dict(history=[dict(round=1, selected=[0, 1], result=[0.02],
                    paper_numeric=dict(scale=descriptor(codec), next_linf="0.02"))])
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "results.json").write_text(json.dumps(result))
    return manifest, result


def test_public_history_checks_sum_not_mean_and_does_not_touch_inputs(tmp_path):
    from experiments.audit_scaled_ring import audit_public_history
    public_history_fixture(tmp_path)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    result = audit_public_history(tmp_path)
    row = result["rounds"][0]
    assert row["sum_linf"] == "1/25"
    assert row["half_period"] == "1/100"
    assert not row["observed_sum_fits_centered_range"]
    assert row["public_sum_changed_by_centering"] == 1
    assert not result["individual_keys_read"]
    assert not result["plaintext_used_for_runtime_decoding"]
    assert before == {p.name: p.read_bytes() for p in tmp_path.iterdir()}


@pytest.mark.parametrize("kind", ["source_hash", "scale", "round", "dimension", "quantization"])
def test_public_history_inconsistent_evidence_rejected(tmp_path, kind):
    import json
    from experiments.audit_scaled_ring import audit_public_history
    manifest, result = public_history_fixture(tmp_path)
    if kind == "source_hash":
        manifest["source-sha256"]["agent/Aion/HPRF/matrix"] = "0" * 64
    elif kind == "scale":
        result["history"][0]["paper_numeric"]["scale"]["coefficient"] = "0"
    elif kind == "round":
        result["history"][0]["round"] = 2
    elif kind == "dimension":
        result["history"][0]["result"] = []
    else:
        result["history"][0]["result"] = [0.02000025]
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "results.json").write_text(json.dumps(result))
    with pytest.raises(ValueError):
        audit_public_history(tmp_path)
