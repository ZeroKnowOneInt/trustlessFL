"""Public MLP local Adam for AION; model wire values are initialization offsets."""

import os
import time
from pathlib import Path

import numpy as np
import torch

from .endpoint_public import PublicMLP, arrays, restore, checked_data


def initial_arrays(inputs, seed):
    # CPU initialization is identical regardless of the training device/worker.
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(seed)
        return arrays(PublicMLP(inputs))


def flatten(values):
    return np.concatenate([v.ravel().astype(np.float64) for v in values])


def model_arrays(offset, inputs, seed):
    initial = initial_arrays(inputs, seed)
    if offset.shape != flatten(initial).shape or not np.isfinite(offset).all():
        raise ValueError("Invalid model offset")
    result, cursor = [], 0
    for value in initial:
        count = value.size
        result.append((value.astype(np.float64) + offset[cursor:cursor + count].reshape(value.shape)).astype(np.float32))
        cursor += count
    return result


class EndpointTrainer:
    def __init__(self, path, seed, epochs=3, batch_size=500, device="cuda:0"):
        self.path, self.seed = Path(path), int(seed)
        self.epochs, self.batch_size, self.device = int(epochs), int(batch_size), device
        if min(self.epochs, self.batch_size) < 1 or self.seed < 0:
            raise ValueError("Invalid trainer settings")
        self.meta = None

    def __call__(self, offset, partition, learning_rate, round_id):
        if round_id < 1 or partition < 0 or not 0 < learning_rate <= 1:
            raise ValueError("Invalid training request")
        os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
        torch.use_deterministic_algorithms(True)
        torch.backends.cuda.matmul.allow_tf32 = False
        torch.backends.cudnn.allow_tf32 = False
        gpu = torch.device(self.device).type == "cuda"
        if gpu and not torch.cuda.is_available():
            raise RuntimeError("CUDA unavailable; no CPU fallback")
        if gpu:
            torch.cuda.reset_peak_memory_stats()
        with np.load(self.path, allow_pickle=False) as data:
            x, y = data["x"], data["y"]
        checked_data(x, y, x.shape[1])
        model = PublicMLP(x.shape[1]).to(self.device)
        restore(model, model_arrays(offset, x.shape[1], self.seed))
        before = flatten(arrays(model))
        # Deliberate FL policy: reset Adam moments each round; keep across local epochs.
        optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, foreach=False)
        xx = torch.tensor(x, dtype=torch.float32, device=self.device)
        yy = torch.tensor(y, dtype=torch.int64, device=self.device)
        shuffle_seed = int(np.random.SeedSequence([self.seed, partition, round_id]).generate_state(1)[0])
        generator = torch.Generator().manual_seed(shuffle_seed)
        started, steps = time.perf_counter(), 0
        model.train()
        for _ in range(self.epochs):
            indices = torch.randperm(len(y), generator=generator).to(self.device)
            for start in range(0, len(y), self.batch_size):
                batch = indices[start:start + self.batch_size]
                optimizer.zero_grad(set_to_none=True)
                torch.nn.functional.cross_entropy(model(xx[batch]), yy[batch]).backward()
                optimizer.step()
                steps += 1
        delta = flatten(arrays(model)) - before
        if not np.isfinite(delta).all():
            raise ValueError("Non-finite update")
        self.meta = {"pid": os.getpid(), "device": str(next(model.parameters()).device),
                     "dtype": str(next(model.parameters()).dtype), "round": round_id,
                     "partition": partition, "optimizer_steps": steps, "rows": len(y),
                     "seconds": time.perf_counter() - started, "adam_state": "reset-each-round"}
        if gpu:
            self.meta.update(gpu_name=torch.cuda.get_device_name(),
                             peak_allocated_bytes=torch.cuda.max_memory_allocated(),
                             peak_reserved_bytes=torch.cuda.max_memory_reserved())
        return delta
