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
from trustlessfl.source_paper_numeric import (FILTER_RULE, LEGACY_FILTER_RULE,
    SUM_SCALE_SOURCE, LEGACY_SCALE_SOURCE, MGFSelectionError, filter_rule,
    scale_source, mask_integer_wire, select_masked, recover, paper_codec)


def test_sum_profile_history_and_next_scale_use_sum_not_optimizer_mean():
    class PublicHPRF:
        p = 1000000007

        def hprf(self, key, round_id, dimension):
            return [100 * key] * dimension

    hprf = PublicHPRF()
    manifest = dict(clients=list(range(20)), dimension=2, decimals=6,
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0, 2],
                            scale_source=SUM_SCALE_SOURCE))
    codec = paper_codec(manifest, hprf, 1)
    updates = [[3000, -4000], [3000, -4000]]
    vectors = [mask_integer_wire(codec, x, hprf.hprf(k, 1, 2))
               for k, x in zip((1, 2), updates)]
    pending = dict(selected=[0, 1], total=[sum(row[j] for row in vectors) for j in range(2)],
                   bound_decimal="1")
    decoded, meta = recover(manifest, {}, codec, hprf, 1, pending, 3)
    assert decoded == [6000, -8000]
    assert Fraction(meta["next_linf"]) == Fraction(8, 1000)
    assert Fraction(meta["history_term"]) == Fraction(1, 100) + Fraction(meta["mask_linf"])
    assert meta["scale_source"] == SUM_SCALE_SOURCE
    assert meta["history_aggregate"] == "selected-sum"
    assert meta["aggregate"] == "selected-mean"  # Optimizer convention only.
    legacy = dict(manifest, paper_numerics={k: v for k, v in manifest["paper_numerics"].items()
                                           if k != "scale_source"})
    _, old = recover(legacy, {}, codec, hprf, 1, pending, 3)
    assert scale_source(legacy) == LEGACY_SCALE_SOURCE
    assert Fraction(old["next_linf"]) == Fraction(4, 1000)
    assert Fraction(old["history_term"]) == Fraction(5, 1000) + Fraction(old["mask_linf"])
    assert "scale_source" not in old and "history_aggregate" not in old
    assert paper_codec(manifest, hprf, 2, meta["next_linf"]).period == (
        2 * paper_codec(legacy, hprf, 2, old["next_linf"]).period)


def test_fresh_paper_tasks_pin_sum_units(source_case):
    manifest, _, _ = source_case
    assert manifest["paper_numerics"]["scale_source"] == SUM_SCALE_SOURCE


def test_explicit_legacy_scale_units_preserved_and_caller_options_not_mutated(source_case, tmp_path):
    manifest, _, _ = source_case
    options = dict(initial_linf="0.012347", beta="0.2", projection=[0, 8],
                   scale_source=LEGACY_SCALE_SOURCE)
    before = dict(options)
    path, _ = provision_source(tmp_path / "legacy-units", Path(manifest["source-root"]),
        clients=20, committee=4, dimension=8, rounds=1, workload="synthetic",
        paper_numerics=options)
    assert options == before
    assert json.loads(path.read_text())["paper_numerics"]["scale_source"] == LEGACY_SCALE_SOURCE


def test_correct_sum_scale_does_not_silently_accept_public_commensurate_carry_fixture():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.paper_dmc import QuantizedLiftError
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    manifest = dict(clients=list(range(20)), dimension=8, decimals=6,
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0, 8],
                            scale_source=SUM_SCALE_SOURCE))
    # Public round-2 SUM magnitude of the new official synthetic run. These
    # fixed fixture keys are NOT that run's private keys or round-3 roster.
    codec = paper_codec(manifest, hprf, 3, "1/625")
    assert codec.period == Fraction(1, 3125)  # 320 model quanta.
    vectors = [mask_integer_wire(codec, [0] * 8, hprf.hprf(k, 3, 8)) for k in (4, 16)]
    pending = dict(selected=[0, 1], total=[sum(row[j] for row in vectors) for j in range(8)],
                   bound_decimal="1")
    with pytest.raises(QuantizedLiftError) as exc:
        recover(manifest, {}, codec, hprf, 3, pending, 20)
    assert exc.value.code == "ambiguous"


def test_unknown_scale_units_rejected_before_provisioning(tmp_path):
    output = tmp_path / "unknown-scale"
    with pytest.raises(ValueError, match="invalid experimental paper numeric"):
        provision_source(output, Path(__file__).resolve().parents[2] / "Aion",
            clients=20, workload="synthetic", paper_numerics=dict(
                initial_linf="0.012347", beta="0.2", projection=[0, 8], scale_source="unknown"))
    assert not output.exists()


def test_unknown_scale_units_cannot_reuse_cached_reply(source_case):
    manifest, nodes, path = source_case
    state = {}
    request = dict(action="enroll", task=manifest["task"], round=1)
    source_request(nodes[1], state, request)
    before = json.dumps(state)
    manifest["paper_numerics"]["scale_source"] = "unknown"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ProtocolError, match="unsupported source scale units"):
        source_request(nodes[1], state, request)
    assert json.dumps(state) == before


@pytest.mark.parametrize("valid", [2, 3, 16, 17, 19, 20])
def test_historical_filter_keeps_every_inclusive_in_bound_vector_without_cap(valid):
    codec = PaperDMC(20, 6, 101)
    manifest = dict(dimension=1, paper_numerics=dict(projection=[0, 1], filter_rule=FILTER_RULE))
    vectors = [dict(sender=i, masked_vector=[1 if i < valid else 2]) for i in range(20)]
    history = dict(paper_terms=["1", "1"], paper_bound=str(Fraction(1, codec.denominator)))
    selected = select_masked(manifest, history, codec, vectors, 4)
    assert selected["selected"] == list(range(valid))
    assert selected["total"] == [valid]
    assert all(Fraction(vectors[i]["masked_vector"][0], codec.denominator)**2
               <= Fraction(selected["bound_decimal"])**2 for i in selected["selected"])


@pytest.mark.parametrize("valid", [0, 1])
def test_historical_filter_never_forces_out_of_bound_clients_to_fill_privacy_minimum(valid):
    codec = PaperDMC(20, 6, 101)
    manifest = dict(dimension=1, paper_numerics=dict(projection=[0, 1], filter_rule=FILTER_RULE))
    vectors = [dict(sender=i, masked_vector=[1 if i < valid else 2]) for i in range(20)]
    history = dict(paper_terms=["1", "1"], paper_bound=str(Fraction(1, codec.denominator)))
    before = json.dumps(history)
    with pytest.raises(MGFSelectionError) as exc:
        select_masked(manifest, history, codec, vectors, 4)
    assert exc.value.code == "insufficient-valid"
    assert json.dumps(history) == before
    # Preserve historical manifests as historical behavior, not paper output.
    manifest["paper_numerics"].pop("filter_rule")
    assert filter_rule(manifest) == LEGACY_FILTER_RULE
    legacy = select_masked(manifest, history, codec, vectors, 4)
    assert len(legacy["selected"]) == 2


def test_legacy_ranked_cap_is_not_silently_reinterpreted():
    codec = PaperDMC(20, 6, 101)
    vectors = [dict(sender=i, masked_vector=[1]) for i in range(20)]
    manifest = dict(dimension=1, paper_numerics=dict(projection=[0, 1]))
    history = dict(paper_terms=["1", "1"], paper_bound=str(Fraction(1, codec.denominator)))
    assert len(select_masked(manifest, history, codec, vectors, 4)["selected"]) == 16
    manifest["paper_numerics"]["filter_rule"] = FILTER_RULE
    assert len(select_masked(manifest, history, codec, vectors, 4)["selected"]) == 20


@pytest.mark.parametrize("round_id", [1, 2, 3])
def test_e2_bootstrap_remains_explicitly_separate_from_historical_paper_filter(round_id):
    codec = PaperDMC(20, 6, 101)
    vectors = [dict(sender=i, masked_vector=[i]) for i in range(20)]
    manifest = dict(dimension=1, paper_numerics=dict(projection=[0, 1]))
    legacy = select_masked(manifest, {}, codec, vectors, round_id)
    manifest["paper_numerics"]["filter_rule"] = FILTER_RULE
    assert select_masked(manifest, {}, codec, vectors, round_id) == legacy


def test_unknown_mgf_rule_rejected_before_actor_state_update(source_case):
    manifest, nodes, path = source_case
    manifest["paper_numerics"]["filter_rule"] = "unknown"
    path.write_text(json.dumps(manifest))
    state = {}
    with pytest.raises(ProtocolError, match="unknown source paper MGF"):
        source_request(nodes[1], state, dict(action="enroll", task=manifest["task"], round=1))
    assert state == {}


def test_unknown_filter_rule_cannot_reuse_an_old_cached_reply(source_case):
    manifest, nodes, path = source_case
    state = {}
    request = dict(action="enroll", task=manifest["task"], round=1)
    source_request(nodes[1], state, request)
    assert "enroll/1" in state["replies"]
    before = json.dumps(state)
    manifest["paper_numerics"]["filter_rule"] = "unknown"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ProtocolError, match="unknown source paper MGF"):
        source_request(nodes[1], state, request)
    assert json.dumps(state) == before


def test_unknown_mgf_rule_rejected_before_provisioning(tmp_path):
    output = tmp_path / "unknown-filter"
    with pytest.raises(ValueError, match="invalid experimental paper numeric"):
        provision_source(output, Path(__file__).resolve().parents[2] / "Aion",
            clients=20, workload="synthetic", paper_numerics=dict(
                initial_linf="0.012347", beta="0.2", projection=[0, 8], filter_rule="unknown"))
    assert not output.exists()


def test_signed_source_selection_rejects_zero_survivors_without_pending_aggregate(source_case):
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.aion_source_sharing import identity_for
    from trustlessfl.aion_source_selection import sign_vector
    from trustlessfl.source_paper_numeric import paper_codec, descriptor
    from trustlessfl.crypto import digest
    manifest, nodes, path = source_case
    manifest["rounds"] = 4
    path.write_text(json.dumps(manifest))
    hprf = OriginalAionHPRF.from_directory(Path(manifest["source-root"]) / "agent/Aion/HPRF")
    codec = paper_codec(manifest, hprf, 4, "0.012347")
    state = dict(last_round=3, model=[0.0] * 8, paper_next_linf="0.012347",
                 paper_terms=["1", "1"], paper_bound="0")
    vectors = [sign_vector(manifest, identity_for(nodes[i + 1], manifest),
        dict(msg="VECTOR", iteration=4, sender=i, masked_vector=[1] * 8,
             parent=digest(state["model"]), paper_scale=descriptor(codec))) for i in range(20)]
    with pytest.raises(MGFSelectionError) as exc:
        source_request(nodes[21], state,
            dict(action="select", task=manifest["task"], round=4, vectors=vectors))
    assert exc.value.code == "insufficient-valid"
    assert "pending" not in state and state["last_round"] == 3
    assert "select/4" not in state.get("replies", {})


@pytest.mark.parametrize("official", [False, True])
def test_mgf_rejection_exports_only_closed_code_in_both_flower_entrypoints(monkeypatch, official):
    from flwr.app import Context, Message, RecordDict
    from trustlessfl.client_app import handle_source_asr, records
    from trustlessfl.aion_source_official import handle
    def fail(*args):
        raise MGFSelectionError("insufficient-valid")
    if official:
        monkeypatch.setattr("trustlessfl.aion_source_official.actor_config", lambda _: {})
        monkeypatch.setattr("trustlessfl.aion_source_official.flower_source_request", fail)
    else:
        monkeypatch.setattr("trustlessfl.aion_source_asr.flower_source_request", fail)
    ctx = Context(run_id=1, node_id=1, node_config={}, state=RecordDict(), run_config={})
    message = Message(records(dict(action="select")), dst_node_id=1,
                      message_type="query.aion_source_asr")
    reply = (handle if official else handle_source_asr)(message, ctx)
    assert reply.has_error()
    assert reply.error.reason == "Author ASR MGF selection failure: insufficient-valid"


def test_workflow_classifies_mgf_failure_without_numeric_or_key_fallback(source_case):
    from flwr.app import Error, Message
    manifest, _, _ = source_case
    workflow = AuthorASRWorkflow(manifest)
    workflow.nodes = {manifest["aggregator"]: 123}
    class RejectedGrid:
        def create_message(self, content, message_type, dst_node_id, group_id, ttl):
            return Message(content, dst_node_id=dst_node_id, message_type=message_type)
        def send_and_receive(self, messages, timeout):
            return [Message(error=Error(code=400,
                    reason="Author ASR MGF selection failure: insufficient-valid"), reply_to=m)
                    for m in messages]
    with pytest.raises(ProtocolError, match="category=insufficient-valid"):
        workflow.call(RejectedGrid(), [manifest["aggregator"]], "select", 4, vectors=[])
    assert workflow.failure_code == "insufficient-valid"
    assert workflow.last_request == dict(action="select", round=4)


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


@pytest.mark.parametrize("previous_linf,round_id,period_quanta", [
    (Fraction(253, 40000), 2, 1265),  # Earlier clean ten-round task.
    (Fraction(59, 50000), 3, 236),    # Aggregate-validated FMNIST attack task.
])
def test_actual_learning_failure_scales_remain_ambiguous_inside_mask_bounds(
        previous_linf, round_id, period_quanta):
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.paper_dmc import QuantizedLiftError
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    codec = PaperDMC(20, 6, hprf.p).with_mgf(previous_linf, hmax_domain="normalized")
    assert codec.period * 10**6 == period_quanta
    # Original public fixture keys, not private keys from the learning run.
    total = sum(mask_integer_wire(codec, [0], hprf.hprf(k, round_id, 1))[0] for k in (4, 16))
    with pytest.raises(QuantizedLiftError) as exc:
        codec.remove_quantized_lift([Fraction(total, codec.denominator)],
            hprf.hprf(20, round_id, 1), selected_count=2, decimal_wire=True)
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


def test_inclusive_fmnist_failure_scale_can_alias_larger_valid_cohort():
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    from trustlessfl.paper_dmc import QuantizedLiftError
    root = Path(__file__).resolve().parents[2] / "Aion/agent/Aion/HPRF"
    if not root.exists():
        pytest.skip("author matrix required")
    hprf = OriginalAionHPRF.from_directory(root)
    # Public committed round-3 norm of the inclusive FMNIST task. This is a
    # numeric fixture, NOT that task's omitted round-4 cohort or private keys.
    codec = PaperDMC(20, 6, hprf.p).with_mgf(Fraction(541, 400000), hmax_domain="normalized")
    assert codec.period * 10**6 == Fraction(541, 2)
    keys, dimension = (4, 16, 20), 8
    vectors = [mask_integer_wire(codec, [0] * dimension, hprf.hprf(k, 4, dimension)) for k in keys]
    total = [sum(v[j] for v in vectors) for j in range(dimension)]
    with pytest.raises(QuantizedLiftError) as exc:
        codec.remove_quantized_lift([Fraction(x, codec.denominator) for x in total],
            hprf.hprf(sum(keys), 4, dimension), selected_count=len(keys), decimal_wire=True)
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
    # Successful conditional lift is not evidence that simply centering the
    # scaled-ring residual would recover the same training SUM.
    from fractions import Fraction
    from experiments.audit_scaled_ring import audit_public_history
    observed = verified["scaled_ring_range_checks"]["rounds"]
    public = audit_public_history(path.parent)["rounds"]
    assert len(observed) == 1
    for name in ("sum_linf", "scaled_modulus", "half_period", "worst_case_decimal_error"):
        assert Fraction(observed[0][name]) == Fraction(public[0][name])
    assert observed[0]["selected_count"] == 2
    assert observed[0]["observed_sum_fits_centered_range"] == public[0]["observed_sum_fits_centered_range"]
    assert "not a runtime bound" in verified["scaled_ring_range_checks"]["scope"]


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
