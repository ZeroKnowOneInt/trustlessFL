"""NumPy MNIST softmax workload; no downloads or global dataset in ClientApps."""

from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from .crypto import ProtocolError

DIMENSION = 785 * 10  # 784 pixel weights plus bias, for each of ten classes.


def features(images: np.ndarray) -> np.ndarray:
    if images.dtype != np.uint8 or images.ndim != 3 or images.shape[1:] != (28, 28):
        raise ProtocolError("expected uint8 MNIST images shaped (n, 28, 28)")
    result = np.ones((len(images), 785), dtype=np.float64)
    result[:, :784] = images.reshape(-1, 784) / 255.0
    return result


@lru_cache(maxsize=4)
def load_shard(path: str) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path, allow_pickle=False) as data:
        x, y = features(data["x"]), data["y"].copy()
    if y.shape != (len(x),) or y.dtype.kind not in "iu" or len(y) == 0 or (y > 9).any() or (y < 0).any():
        raise ProtocolError("invalid MNIST labels")
    x.flags.writeable = y.flags.writeable = False
    return x, y


def probabilities(x: np.ndarray, weights: np.ndarray) -> np.ndarray:
    logits = x @ weights.reshape(785, 10)
    logits -= logits.max(axis=1, keepdims=True)
    exp = np.exp(logits)
    return exp / exp.sum(axis=1, keepdims=True)


@dataclass(frozen=True)
class MnistTrainer:
    path: str
    seed: int = 42
    batch_size: int = 256

    def __post_init__(self):
        if self.batch_size < 1 or self.seed < 0:
            raise ProtocolError("invalid MNIST trainer configuration")

    def __call__(self, weights: np.ndarray, partition: int, learning_rate: float,
                 round_id: int) -> np.ndarray:
        if weights.shape != (DIMENSION,) or not np.isfinite(weights).all():
            raise ProtocolError("invalid softmax model")
        x, y = load_shard(self.path)
        updated = weights.copy().reshape(785, 10)
        rng = np.random.default_rng(np.random.SeedSequence([self.seed, partition, round_id]))
        indices = rng.permutation(len(y))
        # One full local epoch per communication round, no optimizer state.
        for start in range(0, len(y), self.batch_size):
            batch = indices[start:start + self.batch_size]
            xb, yb = x[batch], y[batch]
            residual = probabilities(xb, updated)
            residual[np.arange(len(batch)), yb] -= 1
            updated -= learning_rate * (xb.T @ residual) / len(batch)
        return updated.ravel() - weights


def evaluate(weights: np.ndarray, images: np.ndarray, labels: np.ndarray) -> dict:
    correct, cross_entropy = 0, 0.0
    for start in range(0, len(labels), 512):
        y = labels[start:start + 512]
        prob = probabilities(features(images[start:start + 512]), weights)
        correct += int(np.sum(prob.argmax(axis=1) == y))
        cross_entropy -= float(np.log(np.maximum(prob[np.arange(len(y)), y], 1e-300)).sum())
    return {"accuracy": correct / len(labels), "cross_entropy": cross_entropy / len(labels)}


def partition_indices(labels: np.ndarray, clients: int, split: str, seed: int) -> list[np.ndarray]:
    if clients < 2 or len(labels) % (2 * clients) != 0:
        raise ValueError("equal-size two-shard partitions required")
    rng = np.random.default_rng(seed)
    indices = rng.permutation(len(labels))
    if split == "iid":
        return list(np.split(indices, clients))
    if split != "label-skew":
        raise ValueError("unknown partition method")
    # Shuffle ties before sorting labels, then assign two sorted shards per silo.
    indices = indices[np.argsort(labels[indices], kind="stable")]
    shards = np.split(indices, 2 * clients)
    order = rng.permutation(2 * clients)
    return [np.concatenate([shards[order[2*i]], shards[order[2*i+1]]]) for i in range(clients)]
