"""Official simulation catalog binding and node-local Context persistence."""

import hashlib
import json
from pathlib import Path
import tomllib

import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")
pytest.importorskip("dill")
pytest.importorskip("tomli_w")

from flwr.app import Context, Message, RecordDict
from experiments.run_source_asr_official import stage
from trustlessfl.aion_source_official import actor_config, client_app
from trustlessfl.aion_source_server import provision_source
from trustlessfl.client_app import payload, records
from trustlessfl.crypto import ProtocolError


@pytest.fixture
def official(tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/SA_ClientAgent.py").exists():
        pytest.skip("author source required")
    prepared = tmp_path / "prepared"
    provision_source(prepared, source)
    output = stage(prepared, tmp_path / "official")
    config = tomllib.loads((output / "app/pyproject.toml").read_text())["tool"]["flwr"]["app"]["config"]
    return output, config, json.loads((output / "manifest.json").read_text())


def context(config, index, partitions=11):
    return Context(run_id=42, node_id=index + 1, node_config={"partition-id": index,
        "num-partitions": partitions}, state=RecordDict(), run_config=config)


def test_fresh_task_and_pinned_catalog(official):
    output, config, manifest = official
    old = json.loads((output.parent / "prepared/manifest.json").read_text())
    assert manifest["task"] != old["task"]
    assert manifest["source-sha256"] == old["source-sha256"]
    assert manifest["source-root"] != old["source-root"]
    assert config["num-clients"] == 11
    assert actor_config(context(config, 0))["aion-source-id"] == 0
    assert actor_config(context(config, 10))["aion-source-id"] == 10
    catalog = Path(config["source-node-configs"])
    catalog.write_bytes(catalog.read_bytes() + b" ")
    with pytest.raises(ProtocolError, match="catalog changed"):
        actor_config(context(config, 0))


def test_fresh_learning_committee_override_keeps_workload_and_pins_threshold(official):
    output, _, manifest = official
    prepared = output.parent / "prepared-learning"
    path, _ = provision_source(prepared, manifest["source-root"], clients=10,
                               committee=4, workload="synthetic", rounds=2)
    original = json.loads(path.read_text())
    new = stage(prepared, output.parent / "official-seven", committee=7, rounds=1)
    actual = json.loads((new / "manifest.json").read_text())
    assert len(actual["committee"]) == 7
    assert actual["sharing_profile"]["threshold"] == 3
    assert actual["task"] != original["task"]
    for key in ("workload", "clients", "dimension", "decimals", "learning_rate", "source-sha256"):
        assert actual[key] == original[key]
    assert json.loads(path.read_text()) == original


@pytest.mark.parametrize("committee", [1, 11, True, 7.5])
def test_invalid_committee_override_rejected_before_staging(official, committee):
    output, _, _ = official
    target = output.parent / "bad-committee"
    with pytest.raises(ValueError, match="committee size"):
        stage(output.parent / "prepared", target, committee=committee)
    assert not target.exists()


@pytest.mark.parametrize("index,count", [(0, 10), (-1, 11), (11, 11)])
def test_simulation_partition_mismatch_rejected(official, index, count):
    _, config, _ = official
    with pytest.raises(ProtocolError, match="partition mismatch"):
        actor_config(context(config, index, count))


def test_worker_reuse_keeps_separate_contexts_and_one_time_sharing(official):
    _, config, manifest = official
    contexts = [context(config, i) for i in (0, 1)]
    def call(ctx, round_id):
        message = Message(records(dict(action="mask", task=manifest["task"], round=round_id)),
                          dst_node_id=ctx.node_id, message_type="query.aion_source_asr")
        reply = client_app(message, ctx)
        assert not reply.has_error()
        return payload(reply)
    first = [call(ctx, 1) for ctx in contexts]
    for i, ctx in enumerate(contexts):
        assert call(ctx, 1) == first[i]
        assert sum(e["body"]["msg"] == "SHARED_MASK" for e in first[i]["outbox"]) == 4
        second = call(ctx, 2)
        assert [e["body"]["msg"] for e in second["outbox"]] == ["VECTOR"]
        assert second["outbox"][0]["body"]["sender"] == i
        old = Message(records(dict(action="mask", task=manifest["task"], round=1)),
                      dst_node_id=ctx.node_id, message_type="query.aion_source_asr")
        assert client_app(old, ctx).has_error()
        snapshot = json.loads(ctx.state["aion-source-state"]["snapshot"])
        assert set(snapshot["replies"]) == {"mask/2"}
        assert set(snapshot["expired_replies"]) == {"mask/1"}
    assert contexts[0].state is not contexts[1].state


def test_staged_package_hash_inventory(official):
    output, _, _ = official
    staging = json.loads((output / "staging.json").read_text())
    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (output / "app/trustlessfl").glob("*.py")}
    assert files == staging["source_sha256"]
    assert hashlib.sha256((output / "app/pyproject.toml").read_bytes()).hexdigest() == staging["app_config_sha256"]


def test_offline_verifier_rejects_staged_source_tampering(official):
    from experiments.verify_source_learning import verify_learning
    output, _, _ = official
    (output / "results.json").write_text("{}")
    source = output / "app/trustlessfl/aion_source_official.py"
    source.write_text(source.read_text() + "\n# changed after staging\n")
    with pytest.raises(ValueError, match="staged package changed"):
        verify_learning(output)


def test_attack_override_rejected_before_new_stage_for_non_fmnist(official):
    output, _, _ = official
    target = output.parent / "invalid"
    with pytest.raises(ValueError, match="attack schedule"):
        stage(output.parent / "prepared", target, attack_rounds=[1])
    assert not target.exists()


def test_official_stage_extends_dynamic_schedule_from_pinned_settings(official):
    from trustlessfl.aion_source_cohort import make_cohorts
    output, _, _ = official
    prepared = output.parent / "prepared"
    manifest = json.loads((prepared / "manifest.json").read_text())
    initial = make_cohorts(10, 7, 4, seed=3)
    manifest.update(workload="synthetic", cohort_schedule=initial,
                    participation=dict(participants=7, seed=3))
    (prepared / "manifest.json").write_text(json.dumps(manifest))
    staged = stage(prepared, output.parent / "longer", rounds=20)
    new = json.loads((staged / "manifest.json").read_text())
    assert new["cohort_schedule"] == make_cohorts(10, 7, 20, seed=3)
    assert {r: new["cohort_schedule"][r] for r in initial} == initial
    assert new["participation"] == manifest["participation"]


@pytest.mark.parametrize("numeric", [True, False])
def test_official_failure_reason_is_public_category_only(official, monkeypatch, numeric):
    from trustlessfl.paper_dmc import QuantizedLiftError
    _, config, _ = official
    def fail(*args):
        if numeric:
            raise QuantizedLiftError("ambiguous", "private-coordinate-value")
        raise ProtocolError("private-key-value")
    monkeypatch.setattr("trustlessfl.aion_source_official.flower_source_request", fail)
    ctx = context(config, 0)
    message = Message(records(dict(action="hello")), dst_node_id=ctx.node_id,
                      message_type="query.aion_source_asr")
    reply = client_app(message, ctx)
    assert reply.has_error()
    assert reply.error.reason == ("Author ASR numeric failure: ambiguous" if numeric
                                  else "Author ASR request rejected")


def test_official_failed_run_records_only_public_committed_progress(official, monkeypatch):
    from trustlessfl.aion_source_official import main
    from trustlessfl.aion_source_server import AuthorASRWorkflow
    output, config, _ = official
    def fail(self, grid):
        self.on_round(1, [], [], {"selected": [0, 1]}, {"outbox": []})
        self.last_request = dict(action="reconstruct", round=2)
        self.failure_code = "ambiguous"
        raise ProtocolError("private-mask-key-and-coordinate")
    monkeypatch.setattr(AuthorASRWorkflow, "run", fail)
    with pytest.raises(ProtocolError, match="private-mask-key"):
        main(None, context(config, 0))
    raw = (output / "failure.json").read_text()
    report = json.loads(raw)
    assert "private-mask-key" not in raw
    assert report["status"] == "failed" and report["category"] == "ambiguous"
    assert report["request"] == dict(action="reconstruct", round=2)
    assert report["completed_rounds"] == [dict(round=1, selected=[0, 1])]
    assert not (output / "results.json").exists()
    with pytest.raises(ProtocolError, match="terminal record"):
        main(None, context(config, 0))
    assert (output / "failure.json").read_text() == raw


def test_official_completed_task_cannot_be_restarted(official, monkeypatch):
    from trustlessfl.aion_source_official import main
    from trustlessfl.aion_source_server import AuthorASRWorkflow
    output, config, _ = official
    result = b'{"completed":true}'
    (output / "results.json").write_bytes(result)
    def forbidden(*args):
        raise AssertionError("terminal task must not run node actions")
    monkeypatch.setattr(AuthorASRWorkflow, "run", forbidden)
    with pytest.raises(ProtocolError, match="terminal record"):
        main(None, context(config, 0))
    assert (output / "results.json").read_bytes() == result
    assert not (output / "failure.json").exists()
