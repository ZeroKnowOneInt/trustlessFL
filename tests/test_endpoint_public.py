import numpy as np
import pytest

torch = pytest.importorskip("torch")

from trustlessfl.endpoint_public import PublicMLP, arrays, restore, fit, evaluate_arrays, should_stop
from experiments.run_endpoint_public import profile_indices


def test_public_architecture_loss_and_checkpoint():
    torch.manual_seed(42)
    model = PublicMLP(31)
    assert sum(p.numel() for p in model.parameters()) == 2169
    x, y = torch.randn(17, 31), torch.arange(17) % 9
    logits = model.l3(torch.relu(model.l2(torch.relu(model.l1(x)))))
    torch.testing.assert_close(model(x), torch.log_softmax(logits, dim=1))
    torch.testing.assert_close(torch.nn.functional.cross_entropy(model(x), y),
                               torch.nn.functional.cross_entropy(logits, y))
    other = PublicMLP(31)
    restore(other, arrays(model))
    torch.testing.assert_close(other(x), model(x), rtol=0, atol=0)


def test_public_fit_deterministic_and_validation_only():
    torch.set_num_threads(1)
    rng = np.random.default_rng(8)
    x, y = rng.normal(size=(90, 3)), np.arange(90) % 9
    saved = x.copy()
    kwargs = dict(seed=42, device="cpu", max_epochs=4, batch_size=17, patience=5)
    a, _, best = fit(x, y, x[:45], y[:45], **kwargs)
    b, _, again = fit(x, y, x[:45], y[:45], **kwargs)
    assert a["history"] == b["history"]
    assert a["best_epoch"] == np.argmax([h["monitor"] for h in a["history"]]) + 1
    assert a["meta"]["optimizer_steps"] == 4 * 6
    for xx, yy in zip(best, again):
        np.testing.assert_array_equal(xx, yy)
    np.testing.assert_array_equal(x, saved)
    assert sum(evaluate_arrays(best, x, y)["support"]) == len(y)


def test_early_stop_ties_and_improvement():
    assert should_stop(.8, .8, 4) == (False, 5, True)
    assert should_stop(.81, .8, 4) == (True, 0, False)
    with pytest.raises(ValueError):
        should_stop(float("nan"), .8, 4)


def test_profiles_keep_independent_test_separate():
    part = np.array([0] * 60 + [1] * 20 + [2] * 20)
    profiles = profile_indices(part)
    group = profiles["group-holdout"]
    assert not np.intersect1d(group["train"], group["evaluation"]).size
    assert not np.intersect1d(group["validation"], group["evaluation"]).size
    row = profiles["row-reference"]
    assert len(row["train"]) == 80 and len(row["validation"]) == 20
    np.testing.assert_array_equal(row["validation"], row["evaluation"])
    assert not np.intersect1d(row["train"], row["evaluation"]).size
