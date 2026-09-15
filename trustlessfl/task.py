"""Small non-IID least-squares workload without dataset downloads."""

import numpy as np


def dataset(partition: int, dimension: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(1000 + partition)
    x = rng.normal(loc=partition * 0.1, size=(32, dimension))
    target = np.linspace(0.2, 0.8, dimension)
    y = x @ target + rng.normal(scale=0.01, size=32)
    return x, y


def local_delta(weights: np.ndarray, partition: int, learning_rate: float) -> np.ndarray:
    x, y = dataset(partition, len(weights))
    gradient = x.T @ (x @ weights - y) / len(y)
    return -learning_rate * gradient


def loss(weights: np.ndarray, clients: int) -> float:
    return float(np.mean([np.mean((dataset(i, len(weights))[0] @ weights
                                  - dataset(i, len(weights))[1])**2)
                          for i in range(clients)]))
