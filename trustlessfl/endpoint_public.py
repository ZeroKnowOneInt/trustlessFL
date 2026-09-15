"""Port of the pinned public MLP/Adam recipe; not the original Lightning runtime."""

import os
import time

import numpy as np
import torch

from .endpoint import confusion_metrics


class PublicMLP(torch.nn.Module):
    def __init__(self, inputs):
        super().__init__()
        self.l1 = torch.nn.Linear(inputs, 30)
        self.l2 = torch.nn.Linear(30, 30)
        self.l3 = torch.nn.Linear(30, 9)

    def forward(self, x):
        x = torch.relu(self.l1(x))
        x = torch.relu(self.l2(x))
        return torch.log_softmax(self.l3(x), dim=1)


def arrays(model):
    return [p.detach().cpu().numpy().copy() for p in model.parameters()]


def restore(model, values):
    if len(values) != len(list(model.parameters())):
        raise ValueError("Wrong parameter count")
    with torch.no_grad():
        for parameter, value in zip(model.parameters(), values):
            if value.shape != tuple(parameter.shape) or not np.isfinite(value).all():
                raise ValueError("Invalid checkpoint")
            parameter.copy_(torch.as_tensor(value, device=parameter.device, dtype=parameter.dtype))


def checked_data(x, y, inputs):
    if (x.shape != (len(y), inputs) or len(y) == 0 or not np.isfinite(x).all()
            or y.dtype.kind not in "iu" or y.min() < 0 or y.max() > 8):
        raise ValueError("Invalid data")


@torch.no_grad()
def evaluate_tensor(model, x, y, batch_size=500):
    model.eval()
    cm = torch.zeros((9, 9), dtype=torch.int64, device=x.device)
    loss_sum = torch.zeros((), dtype=torch.float64, device=x.device)
    for start in range(0, len(y), batch_size):
        yy = y[start:start + batch_size]
        output = model(x[start:start + batch_size])
        pred = output.argmax(dim=1)
        cm += torch.bincount(yy * 9 + pred, minlength=81).reshape(9, 9)
        loss_sum += torch.nn.functional.cross_entropy(output, yy, reduction="sum").double()
    result = confusion_metrics(cm.cpu().numpy())
    # Explicit epoch-level metric, unlike version-dependent Lightning batch logging.
    result["macro_accuracy"] = float(np.mean(result["recall"]))
    result["cross_entropy"] = float(loss_sum.cpu()) / len(y)
    return result


def evaluate_arrays(values, x, y, *, device="cpu", batch_size=500):
    checked_data(x, y, x.shape[1])
    model = PublicMLP(x.shape[1]).to(device)
    restore(model, values)
    return evaluate_tensor(model, torch.tensor(x, dtype=torch.float32, device=device),
                           torch.tensor(y, dtype=torch.int64, device=device), batch_size)


def should_stop(score, best, wait, patience=5, min_delta=0.0):
    if not np.isfinite(score):
        raise ValueError("Non-finite validation score")
    improved = score > best + min_delta
    wait = 0 if improved else wait + 1
    return improved, wait, wait >= patience


def fit(train_x, train_y, val_x, val_y, *, seed, device="cuda:0", max_epochs=150,
        batch_size=500, patience=5, learning_rate=.01, progress=None):
    """Train/validation only API: independent test cannot influence selection."""
    if min(max_epochs, batch_size, patience) < 1 or learning_rate <= 0 or not np.isfinite(learning_rate):
        raise ValueError("Invalid training settings")
    checked_data(train_x, train_y, train_x.shape[1])
    checked_data(val_x, val_y, train_x.shape[1])
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    gpu = torch.device(device).type == "cuda"
    if gpu and not torch.cuda.is_available():
        raise RuntimeError("CUDA requested but unavailable; no CPU fallback")
    torch.use_deterministic_algorithms(True)
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.manual_seed(seed)
    if gpu:
        torch.cuda.manual_seed_all(seed)
        torch.cuda.reset_peak_memory_stats()
    model = PublicMLP(train_x.shape[1]).to(device)
    initial = arrays(model)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate, foreach=False)
    x = torch.tensor(train_x, dtype=torch.float32, device=device)
    y = torch.tensor(train_y, dtype=torch.int64, device=device)
    vx = torch.tensor(val_x, dtype=torch.float32, device=device)
    vy = torch.tensor(val_y, dtype=torch.int64, device=device)
    generator = torch.Generator().manual_seed(seed)
    history, best, wait, best_epoch, updates = [], -float("inf"), 0, 0, 0
    best_values = None
    started = time.perf_counter()
    for epoch in range(1, max_epochs + 1):
        model.train()
        indices = torch.randperm(len(y), generator=generator).to(device)
        for start in range(0, len(y), batch_size):
            batch = indices[start:start + batch_size]
            optimizer.zero_grad(set_to_none=True)
            loss = torch.nn.functional.cross_entropy(model(x[batch]), y[batch])
            loss.backward()
            optimizer.step()
            updates += 1
        train_metrics = evaluate_tensor(model, x, y, batch_size)
        val_metrics = evaluate_tensor(model, vx, vy, batch_size)
        score = val_metrics["macro_accuracy"]
        improved, wait, stop = should_stop(score, best, wait, patience)
        if improved:
            best, best_epoch, best_values = score, epoch, arrays(model)
        history.append({"epoch": epoch, "train": train_metrics, "validation": val_metrics,
                        "monitor": score, "improved": improved, "wait": wait, "optimizer_steps": updates})
        if progress is not None:
            progress(history[-1])
        if stop:
            break
    if any(not np.isfinite(a).all() for a in best_values):
        raise ValueError("Non-finite best checkpoint")
    if gpu:
        torch.cuda.synchronize()
    meta = {"device": str(next(model.parameters()).device), "dtype": str(next(model.parameters()).dtype),
            "seconds": time.perf_counter() - started, "optimizer_steps": updates,
            "torch_version": str(torch.__version__), "pid": os.getpid()}
    if gpu:
        meta.update({"gpu_name": torch.cuda.get_device_name(), "peak_allocated_bytes": torch.cuda.max_memory_allocated(),
                     "peak_reserved_bytes": torch.cuda.max_memory_reserved()})
    return {"seed": seed, "best_epoch": best_epoch, "stopped_epoch": len(history),
            "stopped_early": len(history) < max_epochs, "history": history, "meta": meta}, initial, best_values
