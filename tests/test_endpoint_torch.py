import os

import numpy as np
import pytest

from trustlessfl.endpoint import MLP, train_delta
from trustlessfl.endpoint_torch import train_delta_torch


@pytest.mark.parametrize("mu", [0.0, 0.1])
@pytest.mark.parametrize("device", ["cpu", "cuda:0"])
def test_torch_matches_numpy_and_preserves_inputs(mu, device):
    torch = pytest.importorskip("torch")
    if device.startswith("cuda") and os.environ.get("ENDPOINT_TEST_CUDA") != "1":
        pytest.skip("Set ENDPOINT_TEST_CUDA=1 for an explicit GPU test")
    torch.set_num_threads(1)
    model = MLP(3, hidden=7)
    weights = model.initialize(42)
    rng = np.random.default_rng(8)
    x, y = rng.normal(size=(23, 3)), np.arange(23) % 9
    original = [a.copy() for a in (weights, x, y)]
    kwargs = dict(seed=42, client=3, round_id=2, learning_rate=.1, epochs=3, batch_size=8, mu=mu)
    expected = train_delta(model, weights, x, y, **kwargs)
    actual, info = train_delta_torch(model, weights, x, y, device=device, **kwargs)
    np.testing.assert_allclose(actual, expected, rtol=0, atol=1e-12)
    assert actual.dtype == np.float64
    assert info["device"] == device
    assert info["dtype"] == "torch.float64"
    for before, after in zip(original, (weights, x, y)):
        np.testing.assert_array_equal(before, after)
    repeated, _ = train_delta_torch(model, weights, x, y, device=device, **kwargs)
    np.testing.assert_array_equal(actual, repeated)


def test_cuda_unavailable_does_not_fall_back(monkeypatch):
    torch = pytest.importorskip("torch")
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    model = MLP(3)
    with pytest.raises(RuntimeError, match="CUDA requested but unavailable"):
        train_delta_torch(model, model.initialize(42), np.ones((2, 3)), np.array([0, 1]),
                          seed=42, client=0, round_id=1, learning_rate=.1)


def test_proximal_anchor_is_fixed():
    pytest.importorskip("torch")
    model = MLP(3, hidden=7)
    weights = model.initialize(42)
    x, y = np.ones((10, 3)), np.arange(10) % 9
    kwargs = dict(seed=42, client=0, round_id=1, learning_rate=.1, batch_size=10, device="cpu")
    first, _ = train_delta_torch(model, weights, x, y, mu=0, epochs=1, **kwargs)
    prox_first, _ = train_delta_torch(model, weights, x, y, mu=.1, epochs=1, **kwargs)
    np.testing.assert_array_equal(first, prox_first)
    later, _ = train_delta_torch(model, weights, x, y, mu=0, epochs=3, **kwargs)
    prox_later, _ = train_delta_torch(model, weights, x, y, mu=.1, epochs=3, **kwargs)
    assert not np.array_equal(later, prox_later)
