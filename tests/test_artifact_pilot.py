import gzip
import hashlib
import struct
from copy import deepcopy

import pytest

from experiments.prepare_fashion_mnist import validate_resource
from experiments.export_artifact_pilot import repeat_checks
from experiments.run_aion_artifact import adapt_source, replace_exact, summarize_rounds, unified_patch


def test_fashion_idx_validates_checksum_shape_and_classes():
    header = (2049, 3)
    raw = struct.pack(">II", *header) + bytes([0, 2, 9])
    content = gzip.compress(raw)
    md5 = hashlib.md5(content).hexdigest()
    assert validate_resource(content, md5, header) == raw
    with pytest.raises(ValueError, match="checksum"):
        validate_resource(content, "0" * 32, header)
    with pytest.raises(ValueError, match="header/length"):
        validate_resource(content, md5, (2049, 4))
    invalid = gzip.compress(struct.pack(">II", *header) + bytes([0, 2, 10]))
    with pytest.raises(ValueError, match="class"):
        validate_resource(invalid, hashlib.md5(invalid).hexdigest(), header)


def test_runtime_patch_is_guarded_against_source_drift():
    assert replace_exact("x x", "x", "y", count=2) == "y y"
    with pytest.raises(ValueError, match="anchor"):
        replace_exact("x x", "x", "y")
    with pytest.raises(ValueError, match="anchor"):
        adapt_source("FL_Backdoor_CV/roles/aggregation_rules.py", b"changed source")


def test_runtime_does_not_change_unrelated_source():
    original = b"# attack source\r\nimport random\r\n"
    assert adapt_source("FL_Backdoor_CV/roles/client.py", original) == original


def test_only_server_loader_is_replaced():
    result = adapt_source("FL_Backdoor_CV/roles/server.py", b"self.model = torch.load(path)\n")
    assert b"safe_checkpoint_load(path)" in result
    assert b"torch.load" not in result


def test_mgf_patch_only_adapts_devices_and_adds_observation():
    original = b"x.cuda()\ny.cuda()\n    # computation for next round\n"
    result = adapt_source("FL_Backdoor_CV/roles/aggregation_rules.py", original)
    assert result.count(b".to(args.device)") == 2
    assert b"selected_positions=indices_selected.cpu().tolist()" in result
    assert b"# computation for next round" in result


def test_shprg_input_pickle_is_replaced_but_fresh_matrix_rng_unchanged():
    original = b"self.A = pickle.load(file)\nreturn pickle.load(file)\n"
    result = adapt_source("FL_Backdoor_CV/shprg/shprg.py", original)
    assert b"self.A = pickle.load(file)" in result
    assert b"return (1, 8, 173569775688864, 5000999999999999)" in result


def test_both_artifact_metric_definitions_are_preserved():
    rows = [{"accuracy": 0.8, "poison_accuracy": 0.1},
            {"accuracy": 0.7, "poison_accuracy": 0.8},
            {"accuracy": 0.9, "poison_accuracy": 0.8}]
    result = summarize_rounds(rows)
    assert result["ASR_mean_trainer"] == pytest.approx(1.7 / 3)
    assert result["TER_mean_trainer"] == pytest.approx(0.2)
    assert result["ASR_max_check_results"] == 0.8
    assert result["TER_at_max_ASR_check_results"] == pytest.approx(0.1)
    with pytest.raises(ValueError, match="no completed"):
        summarize_rounds([])


def test_patch_has_markers_for_missing_final_newline():
    result = unified_patch(b"old", b"new", "example.py")
    assert "-old\n\\ No newline at end of file\n+new\n" in result
    assert result.count("\\ No newline at end of file") == 2


def test_repeat_check_ignores_only_timing():
    report = {"initial_model_sha256": "m", "partition_sha256": "p", "metrics": {},
              "matrix_840_sha256": None, "rounds": [{"seconds": 1, "accuracy": 0.8, "model_sha256": "a"}]}
    other = deepcopy(report)
    other["rounds"][0]["seconds"] = 100
    assert all(repeat_checks(report, other).values())
    other["rounds"][0]["model_sha256"] = "different"
    with pytest.raises(ValueError, match="repeat differs"):
        repeat_checks(report, other)
