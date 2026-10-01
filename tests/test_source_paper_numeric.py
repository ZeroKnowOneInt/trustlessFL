import json
from fractions import Fraction
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("gmpy2")
pytest.importorskip("Cryptodome")

from trustlessfl.aion_source_asr import source_request
from trustlessfl.aion_source_server import AuthorASRWorkflow, provision_source
from trustlessfl.crypto import ProtocolError
from trustlessfl.local_grid import PooledProcessGrid
from trustlessfl.paper_dmc import PaperDMC
from trustlessfl.source_paper_numeric import mask_integer_wire, select_masked, recover


def test_integer_wire_matches_single_decimal_view_with_signed_models():
    codec = PaperDMC(20, 6, 1000000007).with_mgf("0.012347", hmax_domain="normalized")
    encoded, masks = [-12345, 456, 0], [123456, 1000000000, 17]
    expected = codec.mask_decimal_wire([Fraction(x, 1000000) for x in encoded], masks)
    assert mask_integer_wire(codec, encoded, masks) == [int(x * codec.denominator) for x in expected]


def test_bootstrap_masked_filter_uses_classifier_only_without_plaintext_arguments():
    codec = PaperDMC(20, 6, 1000000007)
    manifest = dict(dimension=3, paper_numerics=dict(projection=[1, 3]))
    vectors = [dict(sender=i, masked_vector=[10**9, i * 100, i * 100]) for i in range(20)]
    result = select_masked(manifest, {}, codec, vectors, 1)
    assert result["selected"] == [0, 1]
    assert result["total"][0] == 2 * 10**9


def test_recovered_norm_uses_actual_lifted_decimal_mask_sum_without_any_shares():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.paper_dmc import public_mgf_term
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    codec = PaperDMC(20, 6, hprf.p).with_mgf("0.012347", hmax_domain="normalized")
    # The known original keys (4,16) carry by exactly p in the first coordinate.
    keys, encoded = (4, 16), ([20000], [0])
    vectors = [mask_integer_wire(codec, x, hprf.hprf(k, 1, 1)) for k, x in zip(keys, encoded)]
    pending = dict(selected=[0, 1], total=[sum(v[0] for v in vectors)], bound_decimal="1")
    manifest = dict(dimension=1, decimals=6, paper_numerics=dict(projection=[0, 1]))
    decoded, metadata = recover(manifest, {}, codec, hprf, 1, pending, sum(keys))
    assert decoded == [20000]
    actual_integer_masks = [mask_integer_wire(codec, [0], hprf.hprf(k, 1, 1))[0] for k in keys]
    expected = Fraction(sum(actual_integer_masks), codec.denominator)
    assert Fraction(metadata["mask_linf"]) == expected
    assert Fraction(metadata["modular_mask_linf"]) < expected
    assert Fraction(metadata["history_term"]) == Fraction(1, 100) + expected
    assert metadata["mask_norm_source"] == "recovered-selected-decimal-mask-sum"


def test_physical_mask_bounds_remove_spurious_two_period_candidate():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    # Public r3 next_linf from the diagnostic clean run; no private keys loaded.
    codec = PaperDMC(20, 6, hprf.p).with_mgf(Fraction(59, 80000), hmax_domain="normalized")
    assert 2 * codec.period == Fraction(295, 1000000)
    assert codec.unbounded_grid_collision(2)
    total = sum(mask_integer_wire(codec, [0], hprf.hprf(k, 4, 1))[0] for k in (4, 16))
    assert codec.remove_quantized_lift([Fraction(total, codec.denominator)],
        hprf.hprf(20, 4, 1), selected_count=2, decimal_wire=True) == [0]


def test_actual_ten_round_failure_scale_remains_ambiguous_inside_mask_bounds():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.paper_dmc import QuantizedLiftError
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    codec = PaperDMC(20, 6, hprf.p).with_mgf(Fraction(253, 40000), hmax_domain="normalized")
    assert codec.period * 10**6 == 1265
    # Original public fixture keys, not private keys from the learning run.
    total = sum(mask_integer_wire(codec, [0], hprf.hprf(k, 2, 1))[0] for k in (4, 16))
    with pytest.raises(QuantizedLiftError) as exc:
        codec.remove_quantized_lift([Fraction(total, codec.denominator)],
            hprf.hprf(20, 2, 1), selected_count=2, decimal_wire=True)
    assert exc.value.code == "ambiguous"


def test_authorized_official_fourth_round_scale_has_integer_period_collision():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.paper_dmc import QuantizedLiftError
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    # Public r3 norm from the fresh authorized 10-round official run, which
    # terminated at r4. These fixture keys are NOT that run's private keys.
    codec = PaperDMC(20, 6, hprf.p).with_mgf(Fraction(1, 1250), hmax_domain="normalized")
    assert codec.period * 10**6 == 160
    assert codec.unbounded_grid_collision(2)
    total = sum(mask_integer_wire(codec, [0], hprf.hprf(k, 4, 1))[0] for k in (4, 16))
    with pytest.raises(QuantizedLiftError) as exc:
        codec.remove_quantized_lift([Fraction(total, codec.denominator)],
            hprf.hprf(20, 4, 1), selected_count=2, decimal_wire=True)
    assert exc.value.code == "ambiguous"


def test_exact_fp32_scale_is_publicly_invertible_and_rejected_by_source():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.source_paper_numeric import paper_codec
    from experiments.audit_author_scale_precision import recover_public_exact_wire
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    opts = dict(initial_linf="1", beta="0.2", projection=[0, 8],
                wire_encoding="exact-scaled-rational", scale_source="author-float32-selected-mean")
    manifest = dict(clients=list(range(20)), decimals=6, paper_numerics=opts)
    magnitude = Fraction(float(np.float32(float(Fraction(253, 40000)))))
    codec = PaperDMC(20, 6, hprf.p).with_mgf(magnitude, hmax_domain="normalized")
    model = [Fraction(1000, 10**6)] * 32
    wire = codec.mask(model, hprf.hprf(4, 2, 32))
    assert recover_public_exact_wire(wire, codec) == [1000] * 32
    with pytest.raises(ProtocolError, match="publicly invertible"):
        paper_codec(manifest, hprf, 2, magnitude)


def test_publicly_invertible_precision_cannot_be_provisioned(tmp_path):
    with pytest.raises(ValueError, match="invalid experimental paper numeric options"):
        provision_source(tmp_path / "unsafe", Path(__file__).resolve().parents[2] / "Aion",
            clients=20, committee=4, dimension=8, rounds=1, workload="synthetic",
            paper_numerics=dict(initial_linf="0.1", beta="0.2", projection=[0, 8],
                wire_encoding="exact-scaled-rational", scale_source="author-float32-selected-mean"))
    assert not (tmp_path / "unsafe").exists()


def test_existing_unsafe_manifest_rejected_before_training_or_state_changes(source_case):
    from trustlessfl.crypto import canonical
    manifest, nodes, path = source_case
    manifest["paper_numerics"].update(wire_encoding="exact-scaled-rational",
        scale_source="author-float32-selected-mean")
    path.write_bytes(canonical(manifest))
    state = {}
    with pytest.raises(ProtocolError, match="publicly invertible"):
        source_request(nodes[1], state, dict(action="mask", task=manifest["task"], round=1))
    assert state == {}


@pytest.mark.parametrize("period_quanta, count, expected", [
    (Fraction(295, 2), 2, True), (Fraction(1, 3), 2, False),
    (Fraction(1, 3), 4, True), (Fraction(17), 1, True),
    (Fraction(12347, 5), 2, False)])
def test_public_grid_collision_sufficient_condition(period_quanta, count, expected):
    modulus = 1000000007
    base = PaperDMC(20, 6, modulus)
    codec = PaperDMC(20, 6, modulus, period_quanta * base.denominator / (modulus * 10**6))
    assert codec.unbounded_grid_collision(count) is expected
    if expected:
        step = period_quanta.denominator
        # Every carry has a different candidate at the identical grid distance.
        for carry in range(-1, count + 1):
            assert any(-1 <= other <= count for other in (carry - step, carry + step))


def test_grid_collision_condition_matches_exhaustive_carry_pair_check():
    modulus = 1000000007
    base = PaperDMC(20, 6, modulus)
    for numerator in range(1, 12):
        for denominator in range(1, 12):
            period = Fraction(numerator, denominator)
            codec = PaperDMC(20, 6, modulus, period * base.denominator / (modulus * 10**6))
            for count in range(1, 21):
                carries = range(-1, count + 1)
                every_carry_has_partner = all(any(
                    other != carry and ((other - carry) * period).denominator == 1
                    for other in carries) for carry in carries)
                assert codec.unbounded_grid_collision(count) == every_carry_has_partner


def test_grid_collision_alone_does_not_reject_flower_round(source_case, monkeypatch):
    from trustlessfl.crypto import canonical
    manifest, nodes, path = source_case
    manifest["paper_numerics"]["initial_linf"] = "59/80000"
    path.write_bytes(canonical(manifest))
    actions = []
    original = AuthorASRWorkflow.call
    def observe(self, grid, actors, action, *args, **kwargs):
        actions.append(action)
        return original(self, grid, actors, action, *args, **kwargs)
    monkeypatch.setattr(AuthorASRWorkflow, "call", observe)
    workflow = AuthorASRWorkflow(manifest)
    with PooledProcessGrid(nodes, 4) as grid:
        result = workflow.run(grid)
    assert "mask" in actions
    assert len(result["history"]) == 1
    assert result["mask_share_deliveries"] == 0


@pytest.fixture
def source_case(tmp_path):
    source = Path(__file__).resolve().parents[2] / "Aion"
    if not (source / "agent/Aion/SA_ClientAgent.py").exists():
        pytest.skip("author source required")
    path, nodes = provision_source(tmp_path / "run", source, clients=20,
        committee=4, dimension=8, rounds=1, workload="synthetic",
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0, 8],
                            bootstrap="public-numerical-fixture"))
    return json.loads(path.read_text()), nodes, path


@pytest.mark.parametrize("batch_bytes", [8 * 1024 * 1024, 1])
def test_flower_single_view_source_vss_and_unique_paper_lift(source_case, batch_bytes):
    from trustlessfl.task import local_delta
    from experiments.verify_source_learning import verify_learning
    from trustlessfl.crypto import canonical
    manifest, nodes, path = source_case
    observed = []
    def observe(r, vectors, shares, selection, final):
        assert len(selection["selected"]) == 2
        assert all(set(v) == {"msg", "iteration", "sender", "masked_vector", "parent", "paper_scale",
                              "task", "signature"}
                   for v in vectors)
        assert all(len(v["masked_vector"]) == 8 for v in vectors)
        total = sum(np.round(local_delta(np.zeros(8), i, manifest["learning_rate"]) * 10**6).astype(int)
                    for i in selection["selected"])
        np.testing.assert_allclose(final["result"], total / (2 * 10**6), atol=1e-12, rtol=0)
        observed.append(final["outbox"][0]["body"]["paper_numeric"])
    with PooledProcessGrid(nodes, 4) as grid:
        result = AuthorASRWorkflow(manifest, on_round=observe,
                                   vector_batch_bytes=batch_bytes).run(grid)
    assert result["key_share_deliveries"] == 80
    assert result["mask_share_deliveries"] == 0
    assert result["selection_authorized_rounds"] == 1
    if batch_bytes == 1:
        # Each signed VECTOR was delivered to the aggregator and four
        # committee verifiers over bounded Flower messages, not shared files.
        assert result["masked_batch_deliveries"] == 20 * 5
    assert observed[0]["removal"] == "conditional-quantized-lift"
    (path.parent / "results.json").write_bytes(canonical(result))
    verified = verify_learning(path.parent)
    assert verified["model_max_abs_error"] == 0


def test_wrong_paper_scale_rejected_before_selection_state_update(source_case):
    manifest, nodes, _ = source_case
    vectors = [dict(msg="VECTOR", iteration=1, sender=i, masked_vector=[0] * 8,
                    parent=__import__("trustlessfl.crypto", fromlist=["digest"]).digest([0.0] * 8),
                    paper_scale={}) for i in range(20)]
    state = {}
    with pytest.raises(ProtocolError, match="scale differs"):
        source_request(nodes[21], state, dict(action="select", task=manifest["task"], round=1, vectors=vectors))
    assert "pending" not in state and "model" not in state


@pytest.mark.parametrize("numeric", [True, False])
def test_flower_failure_diagnostic_never_exposes_exception_values(monkeypatch, numeric):
    from flwr.app import Context, Message, RecordDict
    from trustlessfl.client_app import handle_source_asr, records
    from trustlessfl.paper_dmc import QuantizedLiftError
    def fail(*args):
        if numeric:
            raise QuantizedLiftError("ambiguous", "secret-coordinate-and-mask-value")
        raise ProtocolError("secret-key-and-share-value")
    monkeypatch.setattr("trustlessfl.aion_source_asr.flower_source_request", fail)
    ctx = Context(run_id=1, node_id=1, node_config={}, state=RecordDict(), run_config={})
    message = Message(records(dict(action="reconstruct")), dst_node_id=1,
                      message_type="query.aion_source_asr")
    reply = handle_source_asr(message, ctx)
    assert reply.has_error()
    assert reply.error.reason == ("Author ASR numeric failure: ambiguous" if numeric
                                  else "Author ASR request rejected")


def test_failure_record_keeps_only_already_committed_rounds(source_case, monkeypatch):
    from flwr.app import Context, RecordDict
    from trustlessfl.aion_source_server import main
    _, _, path = source_case
    def fail(self, grid):
        self.on_round(1, [], [], {"selected": [0, 1]},
                      {"outbox": [{"body": {"paper_numeric": {"mask_linf": "1/100"}}}]})
        self.last_request = dict(action="reconstruct", round=2)
        self.failure_code = "ambiguous"
        raise ProtocolError("public numerical failure")
    monkeypatch.setattr(AuthorASRWorkflow, "run", fail)
    ctx = Context(run_id=1, node_id=0, node_config={}, state=RecordDict(),
                  run_config={"aion-source-manifest": str(path)})
    with pytest.raises(ProtocolError):
        main(None, ctx)
    report = json.loads(ctx.state["aion-source-failure"]["failure"])
    assert report["category"] == "ambiguous"
    assert report["request"] == dict(action="reconstruct", round=2)
    assert [r["round"] for r in report["completed_rounds"]] == [1]
    assert "aion-source-result" not in ctx.state
