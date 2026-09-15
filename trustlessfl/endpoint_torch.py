"""Optional float64 PyTorch learner matching the NumPy Endpoint baseline.

Only local SGD uses CUDA. Initialization, batch ordering, wire vectors, aggregation
and evaluation retain the existing NumPy conventions. No silent CPU fallback.
"""

import os
import time

import numpy as np


def train_delta_torch(model, weights, x, y, *, seed, client, round_id,
                      learning_rate, epochs=3, batch_size=128, mu=0.0, device="cuda:0"):
    # Must precede the first CUDA BLAS operation in each Ray worker.
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    import torch

    if (not np.isfinite([learning_rate, mu]).all() or learning_rate <= 0 or mu < 0
            or epochs < 1 or batch_size < 1 or len(y) == 0):
        raise ValueError("Invalid local training configuration")
    model.unpack(weights)
    if (x.shape != (len(y), model.inputs) or not np.isfinite(x).all()
            or y.dtype.kind not in "iu" or y.min() < 0 or y.max() >= model.classes):
        raise ValueError("Invalid local data")
    target = torch.device(device)
    if target.type not in ("cuda", "cpu"):
        raise ValueError("Only CPU/CUDA supported")
    if target.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA requested but unavailable; install the gpu extra and check GPU access")
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.backends.cudnn.benchmark = False
    if target.type == "cuda":
        torch.cuda.synchronize(target)
        torch.cuda.reset_peak_memory_stats(target)
    started = time.perf_counter()
    anchor = torch.tensor(weights, dtype=torch.float64, device=target)
    updated = anchor.clone().requires_grad_(True)
    features = torch.tensor(x, dtype=torch.float64, device=target)
    labels = torch.tensor(y, dtype=torch.int64, device=target)
    a = model.inputs * model.hidden
    b, c = a + model.hidden, a + model.hidden + model.hidden * model.classes
    rng = np.random.default_rng(np.random.SeedSequence([seed, 1, client, round_id]))
    for _ in range(epochs):
        indices = rng.permutation(len(y))
        for start in range(0, len(y), batch_size):
            batch = torch.tensor(indices[start:start + batch_size], device=target)
            hidden = torch.relu(features[batch] @ updated[:a].view(model.inputs, model.hidden) + updated[a:b])
            logits = hidden @ updated[b:c].view(model.hidden, model.classes) + updated[c:]
            loss = torch.nn.functional.cross_entropy(logits, labels[batch])
            loss.backward()
            with torch.no_grad():
                gradient = updated.grad
                if mu:
                    gradient = gradient + mu * (updated - anchor)
                updated -= learning_rate * gradient
            updated.grad = None
    delta = (updated.detach() - anchor).cpu().numpy().copy()
    if not np.isfinite(delta).all():
        raise ValueError("Non-finite local model")
    if target.type == "cuda":
        torch.cuda.synchronize(target)
    info = {"backend": "torch", "device": str(updated.device), "dtype": str(updated.dtype),
            "torch-version": str(torch.__version__), "local-training-seconds": time.perf_counter() - started}
    if target.type == "cuda":
        info.update({"gpu-name": torch.cuda.get_device_name(target),
                     "cuda-visible-devices": os.environ.get("CUDA_VISIBLE_DEVICES", ""),
                     "peak-allocated-bytes": torch.cuda.max_memory_allocated(target),
                     "peak-reserved-bytes": torch.cuda.max_memory_reserved(target)})
    return delta, info


def cuda_preflight():
    """Exercise forward/backward on the actual GPU, not merely its driver name."""
    import torch
    from .endpoint import MLP

    model = MLP(3)
    delta, info = train_delta_torch(model, model.initialize(42), np.ones((10, 3)),
                                   np.arange(10) % 9, seed=42, client=0, round_id=1,
                                   learning_rate=.1, epochs=1, batch_size=4)
    free, total = torch.cuda.mem_get_info()
    if free < 512 * 1024**2:
        raise RuntimeError("Less than 512 MiB GPU memory available; stop other workloads before retrying")
    return {**info, "cuda-runtime": torch.version.cuda,
            "compute-capability": list(torch.cuda.get_device_capability()),
            "compiled-architectures": torch.cuda.get_arch_list(),
            "free-bytes-after-probe": free, "total-bytes": total,
            "delta-norm": float(np.linalg.norm(delta))}


if __name__ == "__main__":
    import json
    print(json.dumps(cuda_preflight(), indent=2))
