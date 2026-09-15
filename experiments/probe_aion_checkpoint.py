"""Bounded CPU preflight of the official FMNIST LeNet5 checkpoint.

Decode only the pinned checkpoint into inert module records and float32 arrays.
Do NOT invoke torch.load or arbitrary pickle globals. This is not an accuracy
or poisoning experiment: forward/backward use a four-example random fixture.
"""

import argparse
from collections import OrderedDict
import hashlib
import importlib.util
import io
import json
import math
import pickle
from pathlib import Path
import zipfile

import numpy as np

CHECKPOINT = "Aion/input_validation/FL_Backdoor_CV/saved_models/Revision_1/fmnist/avg_300.pth"
CHECKPOINT_SHA256 = "047d40adbfdf3c0a5c95db299bec49c48ff1cc16125f5455094e974251c143e2"
CNN = "Aion/input_validation/FL_Backdoor_CV/models/cnn.py"


class ModuleRecord:
    """Inert carrier for the saved nn.Module state, with no torch behavior."""


def rebuild_tensor(storage, offset, shape, stride, requires_grad, hooks):
    if (not isinstance(storage, np.ndarray) or storage.dtype != np.dtype("<f4")
            or type(offset) is not int or offset < 0 or len(shape) > 4
            or any(type(n) is not int or n < 1 for n in shape)):
        raise ValueError("unexpected tensor metadata")
    expected, product = [], 1
    for size in reversed(shape):
        expected.insert(0, product)
        product *= size
    if tuple(expected) != tuple(stride) or offset + product > len(storage):
        raise ValueError("only bounded contiguous float32 tensors are supported")
    return storage[offset:offset + product].reshape(shape).copy()


def rebuild_parameter(data, requires_grad, hooks):
    if not isinstance(data, np.ndarray):
        raise ValueError("unexpected parameter")
    return data


class CheckpointReader(pickle.Unpickler):
    def __init__(self, data, bundle, prefix):
        super().__init__(io.BytesIO(data))
        self.bundle, self.prefix = bundle, prefix

    def find_class(self, module, name):
        allowed = {
            ("collections", "OrderedDict"): OrderedDict,
            ("__builtin__", "set"): set,
            ("torch", "FloatStorage"): "float32-storage",
            ("torch._utils", "_rebuild_tensor_v2"): rebuild_tensor,
            ("torch._utils", "_rebuild_parameter"): rebuild_parameter,
            ("FL_Backdoor_CV.models.cnn", "LeNet5"): ModuleRecord,
            ("torch.nn.modules.container", "Sequential"): ModuleRecord,
            ("torch.nn.modules.conv", "Conv2d"): ModuleRecord,
            ("torch.nn.modules.linear", "Linear"): ModuleRecord,
            ("torch.nn.modules.activation", "ReLU"): ModuleRecord,
            ("torch.nn.modules.pooling", "MaxPool2d"): ModuleRecord,
        }
        if (module, name) not in allowed:
            raise pickle.UnpicklingError(f"global rejected: {module}.{name}")
        return allowed[module, name]

    def persistent_load(self, pid):
        if (not isinstance(pid, tuple) or len(pid) != 5 or pid[0] != "storage"
                or pid[1] != "float32-storage" or not isinstance(pid[2], str)
                or not pid[2].isdigit() or type(pid[4]) is not int or not 0 < pid[4] < 1_000_000):
            raise pickle.UnpicklingError("unexpected storage reference")
        content = self.bundle.read(self.prefix + "data/" + pid[2])
        if len(content) != pid[4] * 4:
            raise ValueError("storage length mismatch")
        return np.frombuffer(content, dtype="<f4")


def checkpoint_arrays(content: bytes) -> dict:
    if hashlib.sha256(content).hexdigest() != CHECKPOINT_SHA256:
        raise ValueError("unreviewed checkpoint; refusing to decode")
    with zipfile.ZipFile(io.BytesIO(content)) as bundle:
        candidates = [n for n in bundle.namelist() if n.endswith("/data.pkl")]
        if len(candidates) != 1:
            raise ValueError("expected one model metadata file")
        key = candidates[0]
        root = CheckpointReader(bundle.read(key), bundle, key[:-len("data.pkl")]).load()
    arrays = {}

    def walk(node, prefix=""):
        if not isinstance(node, ModuleRecord):
            raise ValueError("unexpected module record")
        for name, value in node.__dict__["_parameters"].items():
            if value is not None:
                if not isinstance(value, np.ndarray) or not np.isfinite(value).all():
                    raise ValueError("invalid model parameter")
                arrays[prefix + name] = value
        for name, value in node.__dict__["_modules"].items():
            walk(value, prefix + name + ".")

    walk(root)
    return arrays


def main():
    import torch

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=Path(".cache/aion-artifact/Aion.zip"))
    parser.add_argument("--inspection", type=Path, default=Path(".cache/aion-artifact/inspection-15870338"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inventory = json.loads((args.inspection / "inventory.json").read_text())
    from experiments.audit_artifact import hashes
    if hashes(args.archive)["sha256"] != inventory["archive"]["sha256"]:
        raise ValueError("archive changed since verification")
    with zipfile.ZipFile(args.archive) as bundle:
        arrays = checkpoint_arrays(bundle.read(CHECKPOINT))
    source = args.inspection / "source" / CNN
    expected = next(f["sha256"] for f in inventory["files"] if f["path"] == CNN)
    if hashes(source)["sha256"] != expected:
        raise ValueError("reviewed model source changed")
    # This reviewed file only imports torch.nn and defines the LeNet5 class.
    spec = importlib.util.spec_from_file_location("reviewed_lenet", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    torch.set_num_threads(1)
    torch.manual_seed(1)
    model = module.LeNet5(num_classes=10)
    model.load_state_dict({k: torch.from_numpy(v) for k, v in arrays.items()}, strict=True)
    count = sum(p.numel() for p in model.parameters())
    assert count == 61706
    fixture = torch.randn(4, 1, 28, 28)
    target = torch.tensor([0, 1, 2, 3])
    optimizer = torch.optim.SGD(model.parameters(), lr=0.001)
    optimizer.zero_grad()
    logits = model(fixture)
    loss = torch.nn.functional.cross_entropy(logits, target)
    loss.backward()
    assert all(p.grad is not None and torch.isfinite(p.grad).all() for p in model.parameters())
    optimizer.step()
    after = torch.nn.functional.cross_entropy(model(fixture), target).item()
    assert math.isfinite(after) and tuple(logits.shape) == (4, 10)
    report = {"status": "passed", "scope": "checkpoint compatibility and random-fixture forward/backward only",
              "dataset_accuracy_measured": False, "secure_aggregation_executed": False,
              "poisoning_experiment_executed": False, "checkpoint": CHECKPOINT,
              "checkpoint_sha256": CHECKPOINT_SHA256, "model_source_sha256": expected,
              "torch": torch.__version__, "numpy": np.__version__, "device": "cpu",
              "parameter_count": count, "tensor_shapes": {k: list(v.shape) for k, v in arrays.items()},
              "fixture_seed": 1, "fixture_logits_shape": list(logits.shape),
              "fixture_loss_before": loss.item(), "fixture_loss_after": after,
              "checkpoint_loader": "restricted inert-record decoder; torch.load not used"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
