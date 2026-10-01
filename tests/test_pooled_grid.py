"""Bounded Flower ClientApp process pool for larger logical AION cohorts."""

import json

import numpy as np
import pytest

from experiments.run_aion import Case, ObservedGrid
from experiments.run_fmnist_flower import (scheduled_cohorts,
                                           scheduled_individual_cohorts)
from trustlessfl.demo import provision
from trustlessfl.crypto import ProtocolError
from trustlessfl.protocol import Parameters, certificate, check_finalized_roster
from trustlessfl.task import local_delta
from trustlessfl.workflow import AionWorkflow


def test_pooled_grid_runs_distinct_client_and_aggregator_identities(tmp_path):
    p = Parameters("pooled-grid", ("client-0", "client-1"),
                   tuple(f"aggregator-{i}" for i in range(4)), dimension=3)
    manifest, nodes = provision(tmp_path / "identities", p)
    case = Case("pool", clients=2, aggregators=4, dimension=3, rounds=1)
    with ObservedGrid(nodes, case, p, workers=2) as grid:
        assert len(grid.processes) == 2
        assert len(grid.get_node_ids()) == 6
        history = AionWorkflow(p, json.loads(manifest.read_text())["registry"],
                               timeout=30).run(grid, 1)
    actual = np.asarray(history[-1]["body"]["model"])
    expected = np.mean([p.codec.encode(local_delta(np.zeros(3), i, p.learning_rate))
                        for i in range(2)], axis=0) / p.codec.scale
    np.testing.assert_array_equal(actual, expected)


def test_pair_group_schedule_changes_participants_between_rounds(tmp_path):
    clients = tuple(f"client-{i}" for i in range(4))
    p = Parameters("pooled-dynamic", clients, tuple(f"aggregator-{i}" for i in range(4)),
                   dimension=3, privacy_groups=(clients[:2], clients[2:]))
    schedule = {"1": list(clients[:2]), "2": list(clients[2:]), "3": list(clients[:2])}
    manifest, nodes = provision(tmp_path / "identities", p)
    case = Case("pool-dynamic", clients=4, aggregators=4, dimension=3, rounds=3)

    class CompactCatchUp(AionWorkflow):
        def call(self, grid, names, action, **kwargs):
            if action == "train" and kwargs["model"]["body"]["round"] > 0:
                assert "history" not in kwargs
            return super().call(grid, names, action, **kwargs)

    registry = json.loads(manifest.read_text())["registry"]
    workflow = CompactCatchUp(p, registry, timeout=30, participation_schedule=schedule)
    with ObservedGrid(nodes, case, p, workers=2) as grid:
        history = workflow.run(grid, 3)
    assert len(history) == 4
    assert sorted(workflow.certified_rosters) == [1, 2, 3]
    for round_id, roster in workflow.certified_rosters.items():
        assert check_finalized_roster(roster, p, registry)["members"] == schedule[str(round_id)]
    expected = np.zeros(3)
    for round_id, selected in ((1, (0, 1)), (2, (2, 3)), (3, (0, 1))):
        updates = [p.codec.encode(local_delta(expected, i, p.learning_rate)) for i in selected]
        expected = expected + np.mean(updates, axis=0) / p.codec.scale
        np.testing.assert_array_equal(history[round_id]["body"]["model"], expected)
        assert len(history[round_id]["body"]["ancestry"]) == round_id


def test_artifact_scale_schedule_selects_all_attackers_only_on_attack_rounds():
    schedule = scheduled_cohorts(500, 100, 20, 3, [1, 3], 0)
    assert all(len(names) == 100 for names in schedule.values())
    assert all(f"client-{i}" in schedule["1"] and f"client-{i}" in schedule["3"]
               for i in range(20))
    assert all(f"client-{i}" not in schedule["2"] for i in range(20))


@pytest.mark.parametrize("masked", [False, True])
def test_individual_schedule_preserves_artifact_attack_order_and_oracle_accepts_it(masked):
    schedule = scheduled_individual_cohorts(12, 4, 2, 3, [1, 3], 0)
    assert all(len(names) == 4 and len(set(names)) == 4 for names in schedule.values())
    assert schedule["1"][:2] == schedule["3"][:2] == ["client-0", "client-1"]
    assert all(name not in ("client-0", "client-1") for name in schedule["2"])
    clients = tuple(f"client-{i}" for i in range(12))
    p = Parameters("individual-oracle", clients, tuple(f"aggregator-{i}" for i in range(4)),
                   dimension=61706, oracle_mgf=not masked,
                   **({"mgf_beta": "0.2", "mgf_initial_alpha": "0.1",
                       "mgf_initial_bound": "1", "mgf_initial_term": "1",
                       "mgf_projection": (1, 3), "mgf_percentile": True} if masked else {}))
    workflow = AionWorkflow(p, {}, participation_schedule=schedule)
    assert workflow.participation_schedule[1] == tuple(schedule["1"])
    with pytest.raises(ProtocolError, match="membership"):
        AionWorkflow(p, {}, participation_schedule={"1": ["client-1", "client-1"]})
    with pytest.raises(ProtocolError, match="membership"):
        AionWorkflow(p, {}, participation_schedule={"1": ["client-1", "unknown"]})


def test_staged_updates_preserve_flower_aggregate(tmp_path):
    p = Parameters("pooled-staged", ("client-0", "client-1", "client-2"),
                   tuple(f"aggregator-{i}" for i in range(4)), dimension=3)
    manifest, nodes = provision(tmp_path / "identities", p)
    case = Case("pool-staged", clients=3, aggregators=4, dimension=3, rounds=1)
    with ObservedGrid(nodes, case, p, workers=2) as grid:
        history = AionWorkflow(p, json.loads(manifest.read_text())["registry"],
                               timeout=30, staging_threshold_bytes=1).run(grid, 1)
        assert sum(event["action"] == "stage_update" for event in grid.events) == 3
    staged = list((tmp_path / "identities").glob("aggregator-*/staged-update-*.json"))
    assert not staged
    for path in (tmp_path / "identities").glob("aggregator-*/state-*.json"):
        pending = json.loads(path.read_text())["pending"]
        assert "updates" not in pending
        assert pending["claim"]["round"] == 1
    encoded = [p.codec.encode(local_delta(np.zeros(3), i, p.learning_rate)) for i in range(3)]
    expected = [sum(values) / (p.codec.scale * 3) for values in zip(*encoded)]
    np.testing.assert_array_equal(history[-1]["body"]["model"], expected)


@pytest.mark.parametrize("artifact_bound", [False, True])
@pytest.mark.parametrize("backend", ["artifact", "lwe-reference", "lwe-192-reference"])
def test_masked_percentile_pool_accepts_shuffled_cohort_and_updates_bounds(tmp_path, artifact_bound, backend):
    clients = tuple(f"client-{i}" for i in range(20))
    p = Parameters("pooled-percentile", clients,
                   tuple(f"aggregator-{i}" for i in range(4)), dimension=3,
                   mgf_beta="0.2", mgf_initial_alpha="0.1",
                   mgf_initial_bound="1", mgf_initial_term="1",
                   mgf_projection=(1, 3), mgf_percentile=True,
                   mgf_artifact_bound=artifact_bound, mask_backend=backend)
    manifest, nodes = provision(tmp_path / "identities", p)
    case = Case("pool-percentile", clients=20, aggregators=4, dimension=3, rounds=4)
    registry = json.loads(manifest.read_text())["registry"]
    workflow = AionWorkflow(p, registry, timeout=30, staging_threshold_bytes=1,
                           participation_schedule={str(i): list(reversed(clients))
                                                   for i in range(1, 5)})
    with ObservedGrid(nodes, case, p, workers=4) as grid:
        history = workflow.run(grid, 4)
    expected = np.zeros(3)
    if artifact_bound:
        from trustlessfl.fmnist_artifact_mgf import ArtifactMGF
        reference = ArtifactMGF(dimension=3, selection_slice=slice(1, 3), mask_weight=0.2)
    for round_id in range(1, 5):
        roster = check_finalized_roster(workflow.certified_rosters[round_id], p, registry)
        selected = roster["members"]
        assert len(selected) == roster["mgf_selection"]["selected_count"]
        assert len(workflow.certified_rosters[round_id]["mgf_candidates"]) == 20
        if round_id <= 3:
            assert len(selected) == 2
        updates = [p.codec.encode(local_delta(expected, clients.index(name), p.learning_rate))
                   for name in selected]
        if artifact_bound:
            probes = workflow.certified_rosters[round_id]["mgf_candidates"]
            masked = np.array([probe["body"]["vector"] for probe in probes]) / p.mgf_codec.scale
            mask_linf = float(roster["mgf_selection"]["cohort_mask_linf"])
            indices, trace = reference.select_masked(masked, mask_linf, round_id)
            assert set(selected) == {probe["sender"] for i, probe in enumerate(probes) if i in indices}
            recorded = roster["mgf_selection"]["bound"]
            bound = (np.sqrt(recorded["squared_integer"]) / p.mgf_codec.scale
                     if "squared_integer" in recorded else float(recorded["decimal"]))
            np.testing.assert_allclose(bound, trace["bound"], atol=1e-10, rtol=1e-9)
            reference.observe_aggregate(np.mean(updates, axis=0) / p.codec.scale,
                                        mask_linf, trace["bound"], round_id)
            np.testing.assert_allclose([float(n) for n in history[round_id]["body"]["mgf_state"]["norms"]],
                                       reference.previous_norms, atol=1e-12)
        expected += np.mean(updates, axis=0) / p.codec.scale
        np.testing.assert_allclose(history[round_id]["body"]["model"], expected, atol=1e-12)


def test_cohort_norm_phase_uses_flower_and_keeps_lock_after_worker_restart(tmp_path):
    clients = tuple(f"client-{i}" for i in range(20))
    p = Parameters("flower-cohort-norm", clients,
                   tuple(f"aggregator-{i}" for i in range(4)), dimension=3,
                   mgf_beta="0.2", mgf_initial_alpha="0.1",
                   mgf_initial_bound="1", mgf_initial_term="1",
                   mgf_projection=(1, 3), mgf_percentile=True)
    manifest, nodes = provision(tmp_path / "identities", p)
    registry = json.loads(manifest.read_text())["registry"]
    case = Case("flower-cohort-norm", clients=20, aggregators=4, dimension=3, rounds=1)
    workflow = AionWorkflow(p, registry, timeout=30)
    with ObservedGrid(nodes, case, p, workers=2) as grid:
        workflow.discover(grid)
        enrolled = workflow.call(grid, p.clients, "enroll")
        model = workflow.quorum_call(grid, "initialize", enrollments=enrolled)
        updates = workflow.call(grid, p.clients, "train", model=model)
        by_name = {update["sender"]: update for update in updates}
        probes = [by_name[name]["body"]["mgf_probe"] for name in p.clients]
        approvals = workflow.call(grid, p.aggregators, "mgf_cohort_vote",
                                  model=model, mgf_candidates=probes)
        cohort = certificate(approvals[0]["body"], approvals, p, registry)
        shares = workflow.call(grid, p.aggregators, "mgf_cohort_share",
                               model=model, mgf_candidates=probes, cohort_certificate=cohort)
        assert len(shares) == len(p.aggregators)
        norms = workflow.call(grid, p.aggregators, "mgf_cohort_norm", model=model,
                              mgf_candidates=probes, cohort_shares=shares, cohort_certificate=cohort)
        certified = certificate(norms[0]["body"], norms, p, registry)
        assert certified["body"]["kind"] == "mgf-cohort-norm"
        assert float(certified["body"]["mask_linf"]) >= 0
    with ObservedGrid(nodes, case, p, workers=2) as grid:
        workflow.discover(grid)
        assert not workflow.call(grid, p.aggregators, "mgf_cohort_share",
                                 model=model, mgf_candidates=probes[:10])
        retried = workflow.call(grid, p.aggregators, "mgf_cohort_norm", model=model,
                                mgf_candidates=probes, cohort_shares=shares, cohort_certificate=cohort)
        assert certificate(certified["body"], retried, p, registry)["body"] == certified["body"]


def test_staged_hotstuff_commands_keep_dynamic_rounds_compact(tmp_path):
    clients = tuple(f"client-{i}" for i in range(4))
    p = Parameters("pooled-staged-hotstuff", clients,
                   tuple(f"aggregator-{i}" for i in range(4)), dimension=3,
                   privacy_groups=(clients[:2], clients[2:]), hotstuff=True)
    schedule = {"1": list(clients[:2]), "2": list(clients[2:]), "3": list(clients[:2])}
    manifest, nodes = provision(tmp_path / "identities", p)
    case = Case("pool-staged-hotstuff", clients=4, aggregators=4, dimension=3, rounds=3)
    with ObservedGrid(nodes, case, p, workers=2) as grid:
        history = AionWorkflow(p, json.loads(manifest.read_text())["registry"], timeout=45,
                               participation_schedule=schedule,
                               staging_threshold_bytes=1).run(grid, 3)
        assert sum(event["action"] == "stage_update" for event in grid.events) == 6
    assert not list((tmp_path / "identities").glob("aggregator-*/staged-update-*.json"))
    assert len(history) == 4
    expected = np.zeros(3)
    for round_id, selected in ((1, (0, 1)), (2, (2, 3)), (3, (0, 1))):
        updates = [p.codec.encode(local_delta(expected, i, p.learning_rate)) for i in selected]
        expected += np.mean(updates, axis=0) / p.codec.scale
        np.testing.assert_array_equal(history[round_id]["body"]["model"], expected)
        assert history[round_id]["hotstuff"]["body"]["stage"] == "commit"
