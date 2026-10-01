"""Plaintext Flower controls use the same selected clients as AION rounds."""

import json

import numpy as np
from flwr.app import Context, RecordDict

from trustlessfl.aion_runtime import clear_run
from trustlessfl.demo import provision
from trustlessfl.local_grid import PooledProcessGrid
from trustlessfl.protocol import Parameters
from trustlessfl.task import local_delta


def test_plain_flower_control_uses_per_round_schedule(tmp_path):
    p = Parameters("control-schedule", tuple(f"client-{i}" for i in range(4)),
                   tuple(f"aggregator-{i}" for i in range(4)), dimension=3)
    _, nodes = provision(tmp_path / "identities", p)
    case = "seed-0--clean"
    catalog = {case: {str(i - 1): config for i, config in nodes.items()}}
    (tmp_path / "catalog.json").write_text(json.dumps(catalog))
    schedule = {"1": ["client-0", "client-1"], "2": ["client-2", "client-3"]}
    (tmp_path / "schedule.json").write_text(json.dumps(schedule))
    run_config = {"provision-dir": str(tmp_path), "participation-schedule": str(tmp_path / "schedule.json"),
                  "rounds": 2, "timeout": 30.0}
    context = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(), run_config=run_config)
    configs = {i: {"partition-id": i - 1, "num-partitions": 8}
               for i in nodes}
    with PooledProcessGrid(configs, workers=2, app_kind="plain", run_config=run_config) as grid:
        history, totals, meta, selections = clear_run(grid, context, case, p, "quantized")
    expected = np.zeros(3)
    for round_id, members in enumerate(((0, 1), (2, 3)), 1):
        delta = [p.codec.encode(local_delta(expected, i, p.learning_rate)) for i in members]
        integer_total = np.sum(delta, axis=0)
        np.testing.assert_array_equal(totals[round_id - 1], integer_total)
        expected = expected + integer_total / (len(members) * p.codec.scale)
        np.testing.assert_array_equal(history[round_id], expected)
    assert len(meta) == 4
    assert selections == []
