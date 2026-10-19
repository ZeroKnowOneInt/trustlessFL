"""Fashion-MNIST/LeNet5 workload for the Flower AION research path.

The zero wire model is an offset from a pinned reference checkpoint. This
keeps the protocol's certified genesis model at zero while training starts
from the same weights as the input-validation artifact.
"""

from pathlib import Path
import random

import numpy as np

from .crypto import ProtocolError

DIMENSION = 61706
MEAN = 0.1307
STD = 0.3081
TARGET_LABEL = 2
TRIGGER = ((0, 4), (0, 5), (0, 6), (1, 4), (2, 4), (2, 5), (2, 6), (3, 4),
           (0, 9), (1, 9), (2, 9), (3, 9), (3, 10), (3, 11),
           (0, 15), (1, 14), (1, 16), (2, 14), (2, 15), (2, 16), (3, 14), (3, 16),
           (0, 19), (0, 20), (0, 21), (1, 20), (2, 20), (3, 19), (3, 20), (3, 21))


def artifact_dirichlet_partition(labels: np.ndarray, clients: int,
                                 alpha: float = 0.5, seed: int = 0, *,
                                 adversaries: int = 0,
                                 rng_policy: str = "artifact",
                                 numpy_rng: np.random.RandomState | None = None,
                                 python_rng: random.Random | None = None
                                 ) -> list[np.ndarray]:
    """Reproduce the artifact's per-class rounded Dirichlet allocation.

    The paper-scale artifact consumes one Python ``random.sample`` of 150
    clean participants before shuffling classes, then visits classes in their
    first-seen order. ``legacy`` retains this port's earlier seed transcript
    for existing published results. Small smoke runs skip the 150-person draw.
    """
    if (labels.ndim != 1 or labels.dtype != np.uint8 or len(labels) == 0
            or np.any(labels > 9) or clients < 2 or alpha <= 0 or seed < 0
            or type(adversaries) is not int or not 0 <= adversaries < clients
            or rng_policy not in ("artifact", "legacy")):
        raise ProtocolError("invalid FMNIST partition settings")
    py_rng = python_rng if python_rng is not None else random.Random(seed)
    np_rng = numpy_rng if numpy_rng is not None else np.random.RandomState(seed)
    if rng_policy == "artifact" and clients - adversaries >= 150:
        py_rng.sample(range(adversaries, clients), 150)
    class_order = (dict.fromkeys(labels.tolist()) if rng_policy == "artifact"
                   else range(10))
    assignments = [[] for _ in range(clients)]
    for label in class_order:
        available = np.flatnonzero(labels == label).tolist()
        py_rng.shuffle(available)
        counts = len(available) * np_rng.dirichlet(np.full(clients, alpha))
        cursor = 0
        for client, expected in enumerate(counts):
            count = min(len(available) - cursor, int(round(expected)))
            assignments[client].extend(available[cursor:cursor + count])
            cursor += count
    return [np.asarray(indices, dtype=np.int64) for indices in assignments]


def artifact_poison_indices(labels: np.ndarray, seed: int = 0,
                            requested: int = 500, batch_size: int = 64, *,
                            python_rng: random.Random | None = None) -> np.ndarray:
    """Mirror the artifact's batch-rounded, repeated test-image attack pool."""
    if labels.ndim != 1 or labels.dtype != np.uint8 or seed < 0 or requested < 1 or batch_size < 1:
        raise ProtocolError("invalid FMNIST poison-pool settings")
    eligible = np.flatnonzero(labels != TARGET_LABEL).tolist()
    if len(eligible) < batch_size:
        raise ProtocolError("too few non-target test images for poison pool")
    generator = python_rng if python_rng is not None else random.Random(seed)
    indices = []
    while len(indices) < requested:
        indices.extend(generator.sample(eligible, batch_size))
    return np.asarray(indices, dtype=np.int64)


def make_model():
    import torch.nn as nn

    class LeNet5(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv1 = nn.Sequential(nn.Conv2d(1, 6, 5, padding=2), nn.ReLU(), nn.MaxPool2d(2, 2))
            self.conv2 = nn.Sequential(nn.Conv2d(6, 16, 5), nn.ReLU(), nn.MaxPool2d(2, 2))
            self.fc1 = nn.Sequential(nn.Linear(16 * 5 * 5, 120), nn.ReLU())
            self.fc2 = nn.Sequential(nn.Linear(120, 84), nn.ReLU())
            self.classifier = nn.Linear(84, 10)

        def forward(self, x):
            x = self.conv1(x)
            x = self.conv2(x)
            x = x.reshape(-1, 16 * 5 * 5)
            return self.classifier(self.fc2(self.fc1(x)))

    return LeNet5()


def parameter_vector(model) -> np.ndarray:
    return np.concatenate([p.detach().cpu().numpy().ravel().astype(np.float64)
                           for p in model.parameters()])


def load_vector(model, vector: np.ndarray) -> None:
    import torch

    if vector.shape != (DIMENSION,) or not np.isfinite(vector).all():
        raise ProtocolError("invalid FMNIST model vector")
    cursor = 0
    with torch.no_grad():
        for parameter in model.parameters():
            count = parameter.numel()
            value = vector[cursor:cursor + count].reshape(tuple(parameter.shape))
            parameter.copy_(torch.from_numpy(value).to(parameter.device, dtype=parameter.dtype))
            cursor += count
    if cursor != DIMENSION:
        raise ProtocolError("FMNIST LeNet5 parameter count differs from artifact")


def reference_vector(path: str | Path) -> np.ndarray:
    with np.load(path, allow_pickle=False) as archive:
        if set(archive.files) != {"weights"}:
            raise ProtocolError("FMNIST reference must contain only weights")
        vector = archive["weights"].astype(np.float64)
    if vector.shape != (DIMENSION,) or not np.isfinite(vector).all():
        raise ProtocolError("invalid FMNIST reference checkpoint")
    return vector


def shard(path: str | Path) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path, allow_pickle=False) as archive:
        if set(archive.files) != {"x", "y"}:
            raise ProtocolError("invalid FMNIST shard fields")
        x, y = archive["x"], archive["y"]
    if (x.dtype != np.uint8 or x.ndim != 3 or x.shape[1:] != (28, 28)
            or y.dtype != np.uint8 or y.shape != (len(x),) or len(x) == 0
            or np.any(y > 9)):
        raise ProtocolError("invalid FMNIST shard")
    return x, y


def tensor_images(images: np.ndarray, device: str):
    import torch

    return (torch.from_numpy(images.copy()).to(device=device, dtype=torch.float32)
            .unsqueeze(1).div_(255).sub_(MEAN).div_(STD))


def trigger_images(images):
    """Artifact FMNIST MR trigger, applied after ToTensor/Normalize."""
    changed = images.clone()
    for row, column in TRIGGER:
        changed[:, 0, row, column] = MEAN * 30
    return changed


class FmnistTrainer:
    """Local workload; author-loader preserves batch semantics, not global RNG.

    Both policies use deterministic client/round streams. The author script's
    sequential shared Python/Torch stream and persistent attacker index order
    are not reproduced by this parallel Flower trainer.
    """
    def __init__(self, shard_path: str | Path, reference_path: str | Path,
                 seed: int = 1, epochs: int = 2, batch_size: int = 64,
                 momentum: float = 0.9, weight_decay: float = 0.0005,
                 device: str = "cpu", attack: dict | None = None,
                 sampling_policy: str = "legacy"):
        if seed < 0 or epochs < 1 or batch_size < 1 or not 0 <= momentum < 1 or weight_decay < 0:
            raise ProtocolError("invalid FMNIST training settings")
        self.shard_path, self.reference_path = Path(shard_path), Path(reference_path)
        self.seed, self.epochs, self.batch_size = seed, epochs, batch_size
        self.momentum, self.weight_decay, self.device = momentum, weight_decay, device
        self.attack = attack
        if sampling_policy not in ("legacy", "author-loader"):
            raise ProtocolError("invalid FMNIST sampling policy")
        self.sampling_policy = sampling_policy
        if attack is not None:
            if (set(attack) != {"rounds", "clean_path", "poison_path", "steps", "boost", "poison_batch"}
                    or not isinstance(attack["rounds"], list)
                    or any(type(r) is not int or r < 1 for r in attack["rounds"])
                    or len(set(attack["rounds"])) != len(attack["rounds"])
                    or type(attack["steps"]) is not int or attack["steps"] < 1
                    or type(attack["poison_batch"]) is not int
                    or not 0 < attack["poison_batch"] < batch_size
                    or not isinstance(attack["boost"], (int, float))
                    or not 0 < attack["boost"] <= 100):
                raise ProtocolError("invalid FMNIST attack settings")
        self.meta = None

    def _poison_delta(self, model, before: np.ndarray, partition: int, round_id: int):
        import torch

        clean_x, clean_y = shard(self.attack["clean_path"])
        poison_x, poison_y = shard(self.attack["poison_path"])
        if np.any(clean_y == TARGET_LABEL) or np.any(poison_y == TARGET_LABEL):
            raise ProtocolError("attack pools must exclude target-label images")
        clean = tensor_images(clean_x, self.device)
        poison = trigger_images(tensor_images(poison_x, self.device))
        generator = torch.Generator().manual_seed(int(np.random.SeedSequence(
            [self.seed, partition, round_id, 117]).generate_state(1)[0]))
        optimizer = torch.optim.SGD(model.parameters(), lr=0.0005,
                                    momentum=0.9, weight_decay=0.005)
        count_poison = self.attack["poison_batch"]
        count_clean = self.batch_size - count_poison
        model.train()
        if self.sampling_policy == "author-loader":
            from torch.utils.data import DataLoader, SubsetRandomSampler, TensorDataset

            if len(poison_y) < count_poison or len(clean_y) < count_clean:
                raise ProtocolError("attack pools are smaller than one author batch")
            python_rng = random.Random(int(np.random.SeedSequence(
                [self.seed, partition, round_id, 117]).generate_state(1)[0]))
            clean_order = list(range(len(clean_y)))
            python_rng.shuffle(clean_order)
            clean_labels = torch.from_numpy(clean_y.copy()).to(self.device, dtype=torch.long)
            poison_labels = torch.full((len(poison_y),), TARGET_LABEL,
                                       dtype=torch.long, device=self.device)
            poison_loader = DataLoader(TensorDataset(poison, poison_labels),
                                      batch_size=count_poison, shuffle=True, generator=generator)
            for _ in range(self.attack["steps"]):
                indices = python_rng.sample(clean_order, count_clean)
                clean_loader = DataLoader(TensorDataset(clean, clean_labels),
                    batch_size=self.batch_size,
                    sampler=SubsetRandomSampler(indices, generator=generator), generator=generator)
                # Original client.py consumes only the first paired batches.
                for (px, py), (cx, cy) in zip(poison_loader, clean_loader):
                    optimizer.zero_grad(set_to_none=True)
                    torch.nn.functional.cross_entropy(
                        model(torch.cat((px, cx))), torch.cat((py, cy))).backward()
                    optimizer.step()
                    break
            self.meta = {"round": round_id, "partition": partition, "rows": len(clean_y),
                         "optimizer_steps": self.attack["steps"], "device": self.device,
                         "attack": "artifact-style-MR", "boost": self.attack["boost"],
                         "sampling_policy": self.sampling_policy}
            return (parameter_vector(model) - before) * self.attack["boost"]
        for _ in range(self.attack["steps"]):
            poison_indices = torch.randint(len(poison_y), (count_poison,), generator=generator).to(self.device)
            clean_indices = torch.randperm(len(clean_y), generator=generator)[:count_clean].to(self.device)
            if len(clean_indices) != count_clean:
                raise ProtocolError("attack clean pool is smaller than one batch")
            batch_x = torch.cat((poison[poison_indices], clean[clean_indices]))
            labels = torch.cat((torch.full((count_poison,), TARGET_LABEL,
                                           dtype=torch.long, device=self.device),
                                torch.from_numpy(clean_y.copy()).to(
                                    self.device, dtype=torch.long)[clean_indices]))
            optimizer.zero_grad(set_to_none=True)
            torch.nn.functional.cross_entropy(model(batch_x), labels).backward()
            optimizer.step()
        delta = (parameter_vector(model) - before) * self.attack["boost"]
        self.meta = {"round": round_id, "partition": partition, "rows": len(clean_y),
                     "optimizer_steps": self.attack["steps"], "device": self.device,
                     "attack": "artifact-style-MR", "boost": self.attack["boost"]}
        return delta

    def __call__(self, offset: np.ndarray, partition: int, learning_rate: float,
                 round_id: int) -> np.ndarray:
        import torch

        if (partition < 0 or round_id < 1 or not 0 < learning_rate <= 1
                or offset.shape != (DIMENSION,) or not np.isfinite(offset).all()):
            raise ProtocolError("invalid FMNIST training request")
        images, labels = shard(self.shard_path)
        reference = reference_vector(self.reference_path)
        model = make_model().to(self.device)
        load_vector(model, reference + offset)
        before = parameter_vector(model)
        if self.attack is not None and round_id in self.attack["rounds"]:
            delta = self._poison_delta(model, before, partition, round_id)
            if not np.isfinite(delta).all():
                raise ProtocolError("non-finite FMNIST attack update")
            return delta
        xx = tensor_images(images, self.device)
        yy = torch.from_numpy(labels.copy()).to(device=self.device, dtype=torch.long)
        optimizer = torch.optim.SGD(model.parameters(), lr=learning_rate,
                                    momentum=self.momentum, weight_decay=self.weight_decay)
        generator = torch.Generator().manual_seed(int(np.random.SeedSequence(
            [self.seed, partition, round_id]).generate_state(1)[0]))
        model.train()
        steps = 0
        if self.sampling_policy == "author-loader":
            from torch.utils.data import DataLoader, SubsetRandomSampler, TensorDataset
            loader = DataLoader(TensorDataset(xx, yy), batch_size=self.batch_size,
                sampler=SubsetRandomSampler(range(len(labels)), generator=generator), generator=generator)
        for _ in range(self.epochs):
            if self.sampling_policy == "author-loader":
                for batch_x, batch_y in loader:
                    optimizer.zero_grad(set_to_none=True)
                    torch.nn.functional.cross_entropy(model(batch_x), batch_y).backward()
                    optimizer.step()
                    steps += 1
                continue
            indices = torch.randperm(len(labels), generator=generator)
            for start in range(0, len(labels), self.batch_size):
                batch = indices[start:start + self.batch_size].to(self.device)
                optimizer.zero_grad(set_to_none=True)
                torch.nn.functional.cross_entropy(model(xx[batch]), yy[batch]).backward()
                optimizer.step()
                steps += 1
        delta = parameter_vector(model) - before
        if not np.isfinite(delta).all():
            raise ProtocolError("non-finite FMNIST update")
        self.meta = {"round": round_id, "partition": partition, "rows": len(labels),
                     "optimizer_steps": steps, "device": self.device,
                     "epochs": self.epochs, "batch_size": self.batch_size}
        if self.sampling_policy != "legacy":
            self.meta["sampling_policy"] = self.sampling_policy
        return delta


def evaluate(offset: np.ndarray, reference: np.ndarray, images: np.ndarray,
             labels: np.ndarray, device: str = "cpu", batch_size: int = 256) -> dict:
    import torch

    if (images.dtype != np.uint8 or images.ndim != 3 or images.shape[1:] != (28, 28)
            or labels.shape != (len(images),) or len(images) == 0 or batch_size < 1):
        raise ProtocolError("invalid FMNIST evaluation data")
    model = make_model().to(device)
    load_vector(model, reference + offset)
    model.eval()
    correct = 0
    with torch.no_grad():
        for start in range(0, len(images), batch_size):
            xx = tensor_images(images[start:start + batch_size], device)
            prediction = model(xx).argmax(dim=1).cpu().numpy()
            correct += int(np.sum(prediction == labels[start:start + batch_size]))
    return {"accuracy": correct / len(images), "test_error_rate": 1 - correct / len(images)}


def attack_success_rate(offset: np.ndarray, reference: np.ndarray, images: np.ndarray,
                        device: str = "cpu", batch_size: int = 256) -> float:
    """Target-class prediction rate on triggered images, artifact-style ASR."""
    import torch

    if images.dtype != np.uint8 or images.ndim != 3 or images.shape[1:] != (28, 28) or not len(images):
        raise ProtocolError("invalid FMNIST attack evaluation images")
    model = make_model().to(device)
    load_vector(model, reference + offset)
    model.eval()
    hits = 0
    with torch.no_grad():
        for start in range(0, len(images), batch_size):
            xx = trigger_images(tensor_images(images[start:start + batch_size], device))
            hits += int((model(xx).argmax(dim=1) == TARGET_LABEL).sum())
    return hits / len(images)
