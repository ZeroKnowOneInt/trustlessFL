"""Runtime measurements retain their scope and reject malformed trace rows."""

import copy
import json

import pytest

from experiments.export_fmnist_official import author_trainer_summary, export, phase_timings


def test_phase_timings_group_batches_without_counting_parallel_requests_as_time():
    trace = [{"action": "prepare", "requests": 4, "replies": 3, "seconds": 2.0},
             {"action": "train", "requests": 20, "replies": 20, "seconds": 5.0},
             {"action": "prepare", "requests": 1, "replies": 1, "seconds": 0.5}]
    original = copy.deepcopy(trace)
    assert phase_timings(trace) == {
        "prepare": {"calls": 2, "requests": 5, "replies": 4, "seconds": 2.5},
        "train": {"calls": 1, "requests": 20, "replies": 20, "seconds": 5.0}}
    assert trace == original
    assert phase_timings([]) == {}


@pytest.mark.parametrize("field,value", [("seconds", -1), ("seconds", float("nan")),
    ("seconds", float("inf")), ("seconds", True), ("requests", True),
    ("requests", -1), ("replies", -1), ("action", ""), ("action", None)])
def test_phase_timings_reject_invalid_measurements(field, value):
    row = {"action": "prepare", "requests": 4, "replies": 4, "seconds": 1.0}
    row[field] = value
    with pytest.raises(ValueError, match="timing trace"):
        phase_timings([row])


def test_phase_timings_reject_overflow_and_invalid_container():
    with pytest.raises(ValueError, match="timing trace"):
        phase_timings({})
    row = {"action": "prepare", "requests": 4, "replies": 4, "seconds": 1e308}
    with pytest.raises(ValueError, match="overflow"):
        phase_timings([row, row])


def test_author_trainer_summary_excludes_checkpoint_not_just_last_round():
    curve = [{"round": 0, "accuracy": 0.0, "attack_success_rate": 1.0},
             {"round": 1, "accuracy": 0.8, "attack_success_rate": 0.1},
             {"round": 2, "accuracy": 0.6, "attack_success_rate": 0.3}]
    summary = author_trainer_summary(curve)
    assert summary["first_round"] == 1 and summary["last_round"] == 2
    assert summary["mean_attack_success_rate"] == pytest.approx(0.2)
    assert summary["mean_test_error_rate"] == pytest.approx(0.3)
    assert summary["max_attack_success_rate"] == 0.3


@pytest.mark.parametrize("field,value", [("round", True), ("round", 10),
    ("accuracy", True), ("accuracy", float("nan")), ("accuracy", 1.01),
    ("attack_success_rate", -0.01), ("attack_success_rate", float("inf"))])
def test_author_trainer_summary_rejects_malformed_curve(field, value):
    curve = [{"round": 0, "accuracy": 0.8, "attack_success_rate": 0.1},
             {"round": 1, "accuracy": 0.8, "attack_success_rate": 0.1}]
    curve[1][field] = value
    with pytest.raises(ValueError, match="curve"):
        author_trainer_summary(curve)


def test_author_trainer_summary_rejects_missing_training():
    with pytest.raises(ValueError, match="trained rounds"):
        author_trainer_summary([])


@pytest.mark.parametrize("metadata", [[], [{}], [{"sampling_policy": "legacy"}]])
def test_export_rejects_stale_verification_of_unapplied_author_loader(tmp_path, metadata):
    source = tmp_path / "source"
    run = source / "mgf/runtime-results/run-1"
    run.mkdir(parents=True)
    (source / "provenance.json").write_text(json.dumps({"modes": ["mgf", "quantized"],
        "author_mgf": True, "case": "unit", "training": {"sampling_policy": "author-loader"}}))
    (source / "verification.json").write_text(json.dumps({"mgf": {"run_id": 1}}))
    (run / "results.json").write_text(json.dumps({"run_id": 1, "config": {"mode": "mgf"},
        "cases": [{"status": "completed", "training_meta": metadata}]}))
    with pytest.raises(ValueError, match="sampling policy"):
        export(source, tmp_path / "public")
    assert not (tmp_path / "public").exists()


@pytest.mark.parametrize("audit", [None, {}, {"sampling_policy": "author-loader", "training_calls": 1},
                                  {"sampling_policy": "author-loader", "training_calls": True}])
def test_export_requires_all_candidate_secure_sampling_audit(tmp_path, audit):
    source = tmp_path / "source"
    run = source / "aion_mgf_oracle/runtime-results/run-1"
    run.mkdir(parents=True)
    (source / "provenance.json").write_text(json.dumps({"modes": ["aion_mgf_oracle", "mgf"],
        "author_mgf": True, "case": "unit", "rounds": 4, "population": 20,
        "training": {"sampling_policy": "author-loader"}}))
    (source / "verification.json").write_text(json.dumps({"aion_mgf_oracle": {
        "run_id": 1, "training_sampling_audit": audit},
        "oracle_mgf_control": {"selected_equal_by_round": [True] * 4}}))
    (run / "results.json").write_text(json.dumps({"run_id": 1,
        "config": {"mode": "aion_mgf_oracle"}, "cases": [{"status": "completed"}]}))
    with pytest.raises(ValueError, match="secure training sampling audit"):
        export(source, tmp_path / "public")
    assert not (tmp_path / "public").exists()


@pytest.fixture
def replay_export(tmp_path):
    source = tmp_path / "source"
    run = source / "aion_mgf_beta/runtime-results/run-1"
    run.mkdir(parents=True)
    (source / "provenance.json").write_text(json.dumps({"modes": ["aion_mgf_beta"],
        "case": "unit", "rounds": 2, "population": 3, "participants": 2,
        "aggregators": 4, "seed": 0, "attack_clients": 0, "attack_rounds": [],
        "assigned_rows": 3, "checkpoint_sha256": "checkpoint"}))
    rosters = [{"body": {"members": ["c0", "c1"]}},
               {"body": {"members": ["c1", "c2"]}}]
    (run / "results.json").write_text(json.dumps({"run_id": 1,
        "config": {"mode": "aion_mgf_beta"},
        "cases": [{"status": "completed", "certified_rosters": rosters}]}))
    (run / "unit-models.npz").write_bytes(b"fixture: export hashes without opening models")
    item = {"run_id": 1, "seconds": 1, "curve": [], "selections": [],
        "selected_replay": {"rounds": 2, "replayed_training_calls": 4,
                            "model_max_abs_error": 0, "tolerance": 1e-12}}
    return source, tmp_path / "public", item


def test_export_preserves_complete_selected_replay(replay_export):
    source, output, item = replay_export
    (source / "verification.json").write_text(json.dumps({"aion_mgf_beta": item}))
    result = export(source, output)
    assert result["runs"]["aion_mgf_beta"]["selected_replay"] == item["selected_replay"]


@pytest.mark.parametrize("field,value", [("rounds", True), ("rounds", 1),
    ("replayed_training_calls", True), ("replayed_training_calls", 2),
    ("model_max_abs_error", True), ("model_max_abs_error", float("nan")),
    ("model_max_abs_error", -1), ("model_max_abs_error", 1e-6), ("tolerance", 1e-6)])
def test_export_rejects_incomplete_or_failed_selected_replay(replay_export, field, value):
    source, output, item = replay_export
    item["selected_replay"][field] = value
    (source / "verification.json").write_text(json.dumps({"aion_mgf_beta": item}))
    with pytest.raises(ValueError, match="selected-client replay"):
        export(source, output)
    assert not output.exists()
