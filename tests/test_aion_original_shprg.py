import ast
import importlib.util
import pickle
import random
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
torch = pytest.importorskip("torch")

from trustlessfl.aion_original_shprg import OriginalAionSHPRG
from trustlessfl.fmnist_artifact_mgf import AuthorArtifactMGF, SHPRG_P, SHPRG_Q


AUTHOR = Path(__file__).resolve().parents[2] / "Aion/input_validation/FL_Backdoor_CV"


@pytest.fixture
def reference(tmp_path):
    if not (AUTHOR / "shprg/shprg.py").exists():
        pytest.skip("author artifact required")
    spec = importlib.util.spec_from_file_location("author_shprg", AUTHOR / "shprg/shprg.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix = [random.Random(i).randint(0, SHPRG_Q - 1) for i in range(4)]
    path = tmp_path / "matrix"
    with path.open("wb") as stream:
        pickle.dump([matrix], stream)
    original = module.SHPRG(1, 4, SHPRG_P, SHPRG_Q, str(path))
    port = OriginalAionSHPRG(SHPRG_P, SHPRG_Q, matrix)
    return original, port


def test_shprg_output_matches_author(reference):
    original, port = reference
    for seed in (0, 1, SHPRG_Q - 1, SHPRG_Q + 17):
        assert port.G(seed) == original.G(seed)
        for length in (0, 1, 4, 9):
            for amplitude in (0.0, 0.1, 0.000123456789):
                assert port.generate(seed, length, amplitude) == original.generate(seed, length, amplitude)
    assert port.client_sum_hprg([1, 7, 29], 9, 0.1) == original.client_sum_hprg([1, 7, 29], 9, 0.1)


@pytest.mark.parametrize("resume_round", [0, 300])
def test_mgf_four_rounds_matches_actual_author_function(reference, monkeypatch, resume_round):
    original, generator = reference
    # Compile only the author's function, avoiding unrelated sklearn/CUDA/config imports.
    tree = ast.parse((AUTHOR / "roles/aggregation_rules.py").read_text())
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "aion")
    # Observe chosen indices by adding one return value; no computation is changed.
    function.body[-1].value.elts.append(ast.Name(id="indices_selected", ctx=ast.Load()))
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    selector = AuthorArtifactMGF(dimension=8, selection_slice=slice(2, 6), seed=7,
                                 layer_sizes=(2, 4, 2),
                                 resume_round=resume_round,
                                 public_setup=(generator.p, generator.q, *generator.matrix))
    reference_rng = random.Random()
    reference_rng.setstate(selector.random.getstate())
    monkeypatch.setattr(original, "generate_seeds",
                        lambda n: [reference_rng.randint(0, original.q - 1) for _ in range(n)])
    # Original uses CUDA unconditionally. Differential coverage here is CPU arithmetic.
    monkeypatch.setattr(torch.Tensor, "cuda", lambda self: self)
    import re
    namespace = {"torch": torch, "re": re,
                 "args": SimpleNamespace(dataset="fmnist", resume=bool(resume_round),
                 resumed_name=f"fmnist/avg_{resume_round}.pth",
                 weight=0.1, min_threshold=0.1), "SHPRG": lambda *a: original,
                 "load_initialization_values": lambda p: (1, 8, original.p, original.q)}
    exec(compile(module, str(AUTHOR / "roles/aggregation_rules.py"), "exec"), namespace)
    rng = np.random.default_rng(3)
    norms, linf, mask_linf, bound = [], 1.0, 1.0, 1.0
    for round_id in range(resume_round + 1, resume_round + 5):
        updates = rng.normal(0, 0.01, (20, 8)).astype(np.float32)
        updates[-4:, 2:6] += 20
        blocks = {"first": torch.from_numpy(updates[:, :2]),
                  "classifier": torch.from_numpy(updates[:, 2:6]),
                  "bias": torch.from_numpy(updates[:, 6:])}
        result = namespace["aion"](blocks, norms, linf, mask_linf, bound, round_id)
        aggregate, norms, linf, mask_linf, bound, count, indices = result
        actual, trace = selector.aggregate(updates, round_id)
        expected = torch.cat(list(aggregate.values()), dim=0).numpy().astype(np.float64)
        np.testing.assert_array_equal(actual, expected)
        assert trace["selected_indices"] == indices.tolist()
        assert trace["selected_count"] == count
        assert trace["bound"] == float(bound)
        assert selector.previous_norms == norms
        assert selector.previous_linf == linf
        assert selector.previous_mask_linf == mask_linf


def test_author_mgf_does_not_silently_change_minimum_rank():
    from trustlessfl.crypto import ProtocolError
    selector = AuthorArtifactMGF(dimension=4, selection_slice=slice(2, 4))
    with pytest.raises(ProtocolError, match="minimum rank"):
        selector.aggregate(np.ones((10, 4), dtype=np.float32), 1)


def test_author_trace_verifier_replays_float32_bound_and_sort():
    from experiments.run_fmnist_official import verify_mgf_trace
    import copy
    selector = AuthorArtifactMGF(dimension=8, selection_slice=slice(2, 6),
                                 layer_sizes=(2, 4, 2), seed=3)
    rng = np.random.default_rng(11)
    cohort = [f"client-{i}" for i in range(20)]
    history, traces = [np.zeros(8)], []
    for round_id in range(1, 5):
        values = rng.normal(0, 0.01, (20, 8)).astype(np.float32)
        values[-4:, 2:6] += 20
        mean, trace = selector.aggregate(values, round_id)
        history.append(history[-1] + mean)
        indices = trace.pop("selected_indices")
        traces.append({"round": round_id, "cohort": cohort,
                       "selected": [cohort[i] for i in indices], **trace})
    expected = {r: set(cohort) for r in range(1, 5)}
    verify_mgf_trace(traces, np.asarray(history), expected,
                     selection_slice=slice(2, 6), author_arithmetic=True)
    with pytest.raises(ValueError, match="arithmetic"):
        verify_mgf_trace(traces, np.asarray(history), expected, selection_slice=slice(2, 6))
    changed = copy.deepcopy(traces)
    changed[-1]["bound"] *= 2
    with pytest.raises(ValueError, match="selection"):
        verify_mgf_trace(changed, np.asarray(history), expected,
                         selection_slice=slice(2, 6), author_arithmetic=True)


def test_author_layout_inspection_preserves_training_rng():
    before = torch.random.get_rng_state().clone()
    selector = AuthorArtifactMGF(seed=0)
    assert torch.equal(before, torch.random.get_rng_state())
    assert sum(selector.layer_sizes) == selector.dimension


def test_author_resume_rejects_pre_checkpoint_round():
    from trustlessfl.crypto import ProtocolError
    selector = AuthorArtifactMGF(dimension=4, selection_slice=slice(2, 4), resume_round=300)
    with pytest.raises(ProtocolError, match="projection"):
        selector.select_masked(np.ones((20, 2), dtype=np.float32), 1.0, 300)
    with pytest.raises(ProtocolError, match="checkpoint"):
        selector.observe_aggregate(np.ones(4), 1.0, 1.0, 300)
    with pytest.raises(ProtocolError, match="resume round"):
        AuthorArtifactMGF(resume_round=True)


def test_supplied_matrix_preserves_author_existing_file_rng_branch(reference):
    _, generator = reference
    selector = AuthorArtifactMGF(dimension=8, selection_slice=slice(2, 6), seed=7,
                                 public_setup=(generator.p, generator.q, *generator.matrix))
    assert selector.random.getstate() == random.Random(7).getstate()


def test_author_projection_bridge_matches_control_transcript():
    from trustlessfl.aion_runtime import RuntimeWorkflow
    from trustlessfl.protocol import Parameters
    from trustlessfl.fmnist_artifact_mgf import CLASSIFIER_WEIGHT
    from trustlessfl.fmnist import DIMENSION
    p = Parameters("author-projection-bridge", tuple(f"c{i}" for i in range(20)),
                   ("a0", "a1", "a2", "a3"), dimension=DIMENSION, oracle_mgf=True)
    workflow = RuntimeWorkflow(p, {}, case="unit", author_mgf=True, mgf_seed=0)
    control = AuthorArtifactMGF(seed=0)
    rng = np.random.default_rng(9)
    model = np.zeros(DIMENSION)
    for round_id in range(1, 5):
        values = rng.normal(0, 0.01, (20, DIMENSION)).astype(np.float32)
        values[-4:, CLASSIFIER_WEIGHT] += 20
        mean, expected = control.aggregate(values, round_id)
        updates = [{"sender": name, "body": {"oracle_classifier": values[i, CLASSIFIER_WEIGHT].tolist()}}
                   for i, name in enumerate(p.clients)]
        selected = workflow.oracle_filter(updates, None, round_id)
        assert {u["sender"] for u in selected} == {p.clients[i] for i in expected["selected_indices"]}
        workflow.oracle_observe({"body": {"model": model.tolist()}},
                                {"body": {"model": (model + mean).tolist()}}, round_id)
        actual = workflow.oracle_selections[-1]
        for key in ("bound", "mask_linf", "masked_norms", "global_weight_l2", "global_weight_linf"):
            assert actual[key] == expected[key]
        model += mean
