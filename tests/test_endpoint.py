import numpy as np
import pytest

from trustlessfl.endpoint import MLP, confusion_metrics, evaluate, group_split, train_delta


def fixture():
    model = MLP(3, hidden=4)
    rng = np.random.default_rng(7)
    x = rng.normal(size=(20, 3))
    y = np.arange(20) % 9
    return model, model.initialize(42), x, y


def test_gradient_matches_finite_difference():
    model, weights, x, y = fixture()
    _, gradient = model.loss_gradient(weights, x, y)
    numerical = np.zeros_like(weights)
    for i in range(len(weights)):
        delta = np.zeros_like(weights)
        delta[i] = 1e-6
        a, _ = model.loss_gradient(weights + delta, x, y)
        b, _ = model.loss_gradient(weights - delta, x, y)
        numerical[i] = (a - b) / 2e-6
    np.testing.assert_allclose(gradient, numerical, atol=1e-8, rtol=1e-5)


def test_prox_first_step_equal_but_later_steps_differ():
    model, weights, x, y = fixture()
    args = dict(seed=42, client=0, round_id=1, learning_rate=.01, batch_size=20)
    avg = train_delta(model, weights, x, y, epochs=1, mu=0, **args)
    prox = train_delta(model, weights, x, y, epochs=1, mu=1, **args)
    np.testing.assert_array_equal(avg, prox)
    avg = train_delta(model, weights, x, y, epochs=3, mu=0, **args)
    prox = train_delta(model, weights, x, y, epochs=3, mu=1, **args)
    assert not np.array_equal(avg, prox)
    assert np.linalg.norm(prox) < np.linalg.norm(avg)


def test_prox_uses_fixed_round_anchor():
    model, weights, x, y = fixture()
    lr, mu = .02, .3
    expected = weights.copy()
    for _ in range(2):
        _, grad = model.loss_gradient(expected, x, y)
        expected -= lr * (grad + mu * (expected - weights))
    actual = train_delta(model, weights, x, y, seed=42, client=0, round_id=1,
                         learning_rate=lr, batch_size=20, epochs=2, mu=mu)
    np.testing.assert_allclose(actual, expected - weights, atol=1e-15)


def test_training_reproducible_reduces_loss_and_preserves_input():
    model, weights, x, y = fixture()
    original_w, original_y = weights.copy(), y.copy()
    args = dict(seed=42, client=1, round_id=2, learning_rate=.1, epochs=10, batch_size=5)
    a = train_delta(model, weights, x, y, **args)
    b = train_delta(model, weights, x, y, **args)
    np.testing.assert_array_equal(a, b)
    np.testing.assert_array_equal(weights, original_w)
    np.testing.assert_array_equal(y, original_y)
    assert evaluate(model, weights + a, x, y)["cross_entropy"] < evaluate(model, weights, x, y)["cross_entropy"]


def test_groups_never_leak_including_cross_device_conflicting_labels():
    x = np.repeat(np.arange(100).reshape(-1, 1), 5, axis=0)
    y = np.repeat(np.arange(100) % 9, 5)
    device = np.zeros(len(y), dtype=int)
    device[1] = 1
    y[1] = 3
    split, group, audit = group_split(x, y, device)
    for g in np.unique(group):
        assert len(np.unique(split[group == g])) == 1
    assert audit["conflicting_label_groups"] == audit["cross_file_groups"] == 1
    assert audit["duplicate_excess_rows"] == 400
    assert set(split) == {0, 1, 2}
    np.testing.assert_array_equal(split, group_split(x, y, device)[0])


def test_metrics_distinguish_malware_family_error_from_missed_detection():
    cm = np.zeros((9, 9), dtype=int)
    cm[0, 0], cm[0, 1], cm[1, 0], cm[1, 2] = 8, 2, 1, 9
    result = confusion_metrics(cm)
    assert result["normal_false_positive_rate"] == .2
    assert result["malware_false_negative_rate"] == .1
    assert result["accuracy"] == .4
    assert result["recall"][1] == 0
    assert result["support"] == [10, 10, 0, 0, 0, 0, 0, 0, 0]


@pytest.mark.parametrize("mu", [-1, float("nan"), float("inf")])
def test_invalid_mu_rejected(mu):
    model, weights, x, y = fixture()
    with pytest.raises(ValueError):
        train_delta(model, weights, x, y, seed=42, client=0, round_id=1,
                    learning_rate=.01, mu=mu)
