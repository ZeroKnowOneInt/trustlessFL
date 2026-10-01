"""Flower-delivered masked batches retain no plaintext or extra shares."""

from pathlib import Path

import pytest

from trustlessfl.aion_source_inbox import inbox_root, load_vectors, stage_vectors
from trustlessfl.crypto import ProtocolError


def setup(tmp_path):
    config = {"aion-source-manifest": str(tmp_path / "actor.json")}
    manifest = dict(task="test", aggregator=0, clients=[0, 1], rounds=2, dimension=2)
    vectors = [dict(msg="VECTOR", iteration=1, sender=i, masked_vector=[10+i, 20]) for i in range(2)]
    return config, manifest, {}, vectors


def test_batches_round_trip_and_retry(tmp_path):
    config, manifest, state, vectors = setup(tmp_path)
    refs = []
    for vector in vectors:
        response = stage_vectors(config, manifest, state, 1, [vector])
        assert stage_vectors(config, manifest, state, 1, [vector]) == response
        refs.extend(response["vector_refs"])
    assert load_vectors(config, manifest, state, 1, refs) == vectors
    assert set(state["masked_inbox"]) == {"round", "entries"}
    with pytest.raises(ProtocolError, match="conflicting"):
        stage_vectors(config, manifest, state, 1, [{**vectors[0], "masked_vector": [99, 20]}])
    with pytest.raises(ProtocolError, match="references"):
        load_vectors(config, manifest, state, 1, refs[:1])
    with pytest.raises(ProtocolError, match="references"):
        load_vectors(config, manifest, state, 1, [{**refs[0], "digest": "../bad"}, refs[1]])
    state["last_round"] = 1
    with pytest.raises(ProtocolError, match="out of order"):
        stage_vectors(config, manifest, state, 1, vectors)
    stage_vectors(config, manifest, state, 2, [{**vectors[0], "iteration": 2}])
    with pytest.raises(ProtocolError, match="missing"):
        load_vectors(config, manifest, state, 1, refs)


def test_private_fields_rejected_before_storage(tmp_path):
    config, manifest, state, vectors = setup(tmp_path)
    with pytest.raises(ProtocolError, match="invalid"):
        stage_vectors(config, manifest, state, 1, [{**vectors[0], "plaintext": [1, 2]}])
    assert not inbox_root(config, manifest, 1).exists()
    assert state == {}
    with pytest.raises(ProtocolError, match="invalid"):
        stage_vectors(config, manifest, state, 1, [{**vectors[0], "iteration": True}])
    with pytest.raises(ProtocolError, match="invalid"):
        stage_vectors(config, manifest, state, 1, [{**vectors[0], "paper_scale": {}}])


def test_corrupt_network_envelope_rejected(tmp_path):
    config, manifest, state, vectors = setup(tmp_path)
    refs = stage_vectors(config, manifest, state, 1, vectors)["vector_refs"]
    path = inbox_root(config, manifest, 1) / f'0-{refs[0]["digest"]}.json'
    path.write_bytes(b"{}")
    with pytest.raises(ProtocolError, match="hash mismatch"):
        load_vectors(config, manifest, state, 1, refs)


def test_forced_flower_batches_preserve_source_workflow(tmp_path):
    pytest.importorskip("gmpy2")
    pytest.importorskip("Cryptodome")
    pytest.importorskip("dill")
    import json
    from trustlessfl.aion_source_server import AuthorASRWorkflow, provision_source
    from trustlessfl.local_grid import PooledProcessGrid
    from experiments.verify_source_learning import verify_learning
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not source.exists():
        pytest.skip("author source required")
    path, nodes = provision_source(tmp_path / "run", source, rounds=4, workload="synthetic")
    manifest = json.loads(path.read_text())
    with PooledProcessGrid(nodes, 2) as grid:
        result = AuthorASRWorkflow(manifest, vector_batch_bytes=1).run(grid)
    assert result["key_share_deliveries"] == 40
    assert result["mask_share_deliveries"] == 0
    assert result["source_bft_completed_events"] == 4
    assert result["masked_batch_deliveries"] == 40
    assert result["masked_batch_max_bytes"] < 16 * 1024 * 1024
    (path.parent / "results.json").write_text(json.dumps(result))
    assert verify_learning(path.parent)["model_max_abs_error"] == 0
    assert list(path.parent.glob("masked-inbox/**/*.json"))
