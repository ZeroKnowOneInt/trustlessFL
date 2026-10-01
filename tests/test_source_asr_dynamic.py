"""Inactive clients keep original shares and safely rejoin a committed model."""

import json
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")
pytest.importorskip("dill")

from trustlessfl.aion_source_asr import source_request
from trustlessfl.aion_source_cohort import make_cohorts, round_clients
from trustlessfl.aion_source_server import AuthorASRWorkflow, provision_source
from trustlessfl.crypto import ProtocolError
from trustlessfl.local_grid import ProcessGrid, PooledProcessGrid
from trustlessfl.numeric import FixedPoint
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.task import local_delta


def test_individual_schedule_matches_existing_author_inclusion_rule():
    from experiments.run_fmnist_flower import scheduled_individual_cohorts
    expected = scheduled_individual_cohorts(100, 10, 2, 20, [1, 4, 7, 10], 0)
    actual = make_cohorts(100, 10, 20, malicious=2, attack_rounds=[1, 4, 7, 10], seed=0)
    assert actual == {r: [int(i.split("-")[1]) for i in row] for r, row in expected.items()}
    assert 0 in actual["1"] and 1 in actual["1"]
    assert 0 not in actual["2"] and 1 not in actual["2"]


@pytest.mark.parametrize("rounds,workers", [(4, None), (20, None), (4, 2), (20, 2)])
def test_dynamic_selected_average_and_rejoin(rounds, workers, tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not source.exists():
        pytest.skip("author source required")
    schedule = make_cohorts(10, 7, rounds, malicious=2, attack_rounds=[1, 4], seed=0)
    path, nodes = provision_source(tmp_path / "dynamic", source, rounds=rounds,
        workload="synthetic", cohort_schedule=schedule, learning_rate=0.1)
    manifest = json.loads(path.read_text())
    codec = FixedPoint(manifest["decimals"], manifest["max_abs"], 10,
        mask_backend="aion-original", original_hprf_setup=OriginalAionHPRF.from_directory(
            Path(manifest["source-root"]) / "agent/Aion/HPRF").public_setup())
    previous = np.zeros(8)
    def check(r, vectors, shares, selected, final):
        nonlocal previous
        cohort = schedule[str(r)]
        assert [v["sender"] for v in vectors] == cohort
        assert set(selected["selected"]) <= set(cohort)
        total = np.sum([codec.encode(local_delta(previous, i, 0.1)) for i in selected["selected"]], axis=0)
        mean = total / (len(selected["selected"]) * codec.scale)
        np.testing.assert_allclose(final["result"], mean, atol=1e-12, rtol=0)
        previous += mean
        np.testing.assert_allclose(final["model"], previous, atol=1e-12, rtol=0)
    transport = ProcessGrid(nodes) if workers is None else PooledProcessGrid(nodes, workers)
    with transport as grid:
        result = AuthorASRWorkflow(manifest, on_round=check).run(grid)
    assert result["key_share_deliveries"] == 40
    assert result["mask_share_deliveries"] == 0
    assert result["source_bft_completed_events"] == rounds
    (path.parent / "results.json").write_text(json.dumps(result))
    from experiments.verify_source_learning import verify_learning
    assert verify_learning(path.parent)["model_max_abs_error"] == 0
    result["history"][1]["online_clients"] = schedule["1"]
    (path.parent / "results.json").write_text(json.dumps(result))
    with pytest.raises(ValueError, match="online cohort differs"):
        verify_learning(path.parent)


def test_enrollment_retries_and_unscheduled_mask_rejected(tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not source.exists():
        pytest.skip("author source required")
    schedule = make_cohorts(10, 7, 4, malicious=2, attack_rounds=[1, 4])
    path, nodes = provision_source(tmp_path / "run", source, workload="synthetic", cohort_schedule=schedule)
    manifest = json.loads(path.read_text())
    request = dict(action="enroll", task=manifest["task"], round=1)
    state = {}
    enrolled = source_request(nodes[1], state, request)
    assert source_request(nodes[1], state, request) == enrolled
    assert len(enrolled["outbox"]) == 4
    key = state["mask_seed"]
    with pytest.raises(ProtocolError, match="not scheduled"):
        source_request(nodes[1], state, dict(action="mask", task=manifest["task"], round=2))
    assert state["mask_seed"] == key
    with pytest.raises(ProtocolError, match="one-time"):
        source_request(nodes[1], state, {**request, "round": 2})


def test_invalid_schedule_rejected_before_staging(tmp_path):
    with pytest.raises(ProtocolError, match="incomplete"):
        round_clients(dict(rounds=2, clients=list(range(10)), cohort_schedule={"1": list(range(7))}), 1)
    with pytest.raises(ProtocolError, match="participation"):
        make_cohorts(10, 6, 4)
    with pytest.raises(ValueError, match="learning"):
        provision_source(tmp_path / "bad", tmp_path / "absent", workload="ones",
                         cohort_schedule={str(i): list(range(7)) for i in range(1, 5)})
    assert not (tmp_path / "bad").exists()
