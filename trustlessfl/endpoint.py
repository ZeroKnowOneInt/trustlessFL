"""Plaintext Endpoint workload. No Flower transport or security claims here."""

from dataclasses import dataclass

import numpy as np

LABELS = ("Normal", "Ransomware-PoC", "TheTick", "Bashlite", "HttpBackdoor",
          "Beurk", "Backdoor", "Bdvl", "XMRig")


@dataclass(frozen=True)
class MLP:
    inputs: int
    hidden: int = 128
    classes: int = 9

    def __post_init__(self):
        if min(self.inputs, self.hidden, self.classes) < 1:
            raise ValueError("Positive model dimensions required")

    @property
    def dimension(self):
        return self.inputs * self.hidden + self.hidden + self.hidden * self.classes + self.classes

    def unpack(self, weights):
        if weights.shape != (self.dimension,) or not np.isfinite(weights).all():
            raise ValueError("Invalid model vector")
        a = self.inputs * self.hidden
        b = a + self.hidden
        c = b + self.hidden * self.classes
        return weights[:a].reshape(self.inputs, self.hidden), weights[a:b], \
            weights[b:c].reshape(self.hidden, self.classes), weights[c:]

    def initialize(self, seed):
        rng = np.random.default_rng(np.random.SeedSequence([seed, 0]))
        return np.concatenate([
            (rng.standard_normal((self.inputs, self.hidden)) * np.sqrt(2 / self.inputs)).ravel(),
            np.zeros(self.hidden),
            (rng.standard_normal((self.hidden, self.classes)) * np.sqrt(2 / self.hidden)).ravel(),
            np.zeros(self.classes),
        ])

    def forward(self, weights, x):
        w1, b1, w2, b2 = self.unpack(weights)
        hidden = np.maximum(x @ w1 + b1, 0)
        logits = hidden @ w2 + b2
        logits -= logits.max(axis=1, keepdims=True)
        log_prob = logits - np.log(np.exp(logits).sum(axis=1, keepdims=True))
        return hidden, log_prob

    def loss_gradient(self, weights, x, y):
        hidden, log_prob = self.forward(weights, x)
        residual = np.exp(log_prob)
        residual[np.arange(len(y)), y] -= 1
        residual /= len(y)
        dh = (residual @ self.unpack(weights)[2].T) * (hidden > 0)
        gradient = np.concatenate([(x.T @ dh).ravel(), dh.sum(axis=0),
                                   (hidden.T @ residual).ravel(), residual.sum(axis=0)])
        return float(-log_prob[np.arange(len(y)), y].mean()), gradient


def train_delta(model, weights, x, y, *, seed, client, round_id, learning_rate,
                epochs=3, batch_size=128, mu=0.0):
    """SGD on F_i(w) + mu/2 ||w - round_start||^2, resetting optimizer each round."""
    if (not np.isfinite([learning_rate, mu]).all() or learning_rate <= 0 or mu < 0
            or epochs < 1 or batch_size < 1 or len(y) == 0):
        raise ValueError("Invalid local training configuration")
    if (x.shape != (len(y), model.inputs) or not np.isfinite(x).all()
            or y.dtype.kind not in "iu" or y.min() < 0 or y.max() >= model.classes):
        raise ValueError("Invalid local data")
    updated = weights.copy()
    rng = np.random.default_rng(np.random.SeedSequence([seed, 1, client, round_id]))
    for _ in range(epochs):
        indices = rng.permutation(len(y))
        for start in range(0, len(y), batch_size):
            batch = indices[start:start + batch_size]
            _, gradient = model.loss_gradient(updated, x[batch], y[batch])
            # The fixed anchor is the broadcast global model, not the previous local step.
            if mu:
                gradient += mu * (updated - weights)
            updated -= learning_rate * gradient
    if not np.isfinite(updated).all():
        raise ValueError("Non-finite local model")
    return updated - weights


def confusion_metrics(cm):
    cm = np.asarray(cm, dtype=np.int64)
    if cm.shape != (9, 9) or (cm < 0).any() or not cm.sum():
        raise ValueError("Expected nonempty nine-class confusion matrix")
    support, predicted, tp = cm.sum(axis=1), cm.sum(axis=0), cm.diagonal()
    precision = np.divide(tp, predicted, out=np.zeros(9), where=predicted > 0)
    recall = np.divide(tp, support, out=np.zeros(9), where=support > 0)
    f1 = np.divide(2 * tp, support + predicted, out=np.zeros(9), where=(support + predicted) > 0)
    return {"accuracy": float(tp.sum() / cm.sum()), "macro_f1": float(f1.mean()),
            "supported_macro_f1": float(f1[support > 0].mean()),
            "normal_false_positive_rate": float(cm[0, 1:].sum() / support[0]) if support[0] else None,
            "malware_false_negative_rate": float(cm[1:, 0].sum() / support[1:].sum()) if support[1:].sum() else None,
            "precision": precision.tolist(), "recall": recall.tolist(), "f1": f1.tolist(),
            "support": support.tolist(), "confusion_matrix": cm.tolist()}


def evaluate(model, weights, x, y):
    cm = np.zeros((9, 9), dtype=np.int64)
    loss = 0.0
    for start in range(0, len(y), 1024):
        labels = y[start:start + 1024]
        _, log_prob = model.forward(weights, x[start:start + 1024])
        np.add.at(cm, (labels, log_prob.argmax(axis=1)), 1)
        loss -= float(log_prob[np.arange(len(labels)), labels].sum())
    return {**confusion_metrics(cm), "cross_entropy": loss / len(y)}


def group_split(x, y, device, seed=42):
    """Non-temporal 60/20/20 split: identical feature vectors never cross splits.

    Retain conflicting labels and original row multiplicities, but allocate each
    entire feature group once. Stratify groups by first owner and minimum label;
    counts are approximate. No artificial device reassignment is performed.
    """
    _, first, inverse, counts = np.unique(x, axis=0, return_index=True,
                                         return_inverse=True, return_counts=True)
    lo, hi = np.full(len(first), 9), np.full(len(first), -1)
    np.minimum.at(lo, inverse, y)
    np.maximum.at(hi, inverse, y)
    owner_min, owner_max = np.full(len(first), 99), np.full(len(first), -1)
    np.minimum.at(owner_min, inverse, device)
    np.maximum.at(owner_max, inverse, device)
    group_assignment = np.full(len(first), -1, dtype=np.int8)
    rng = np.random.default_rng(seed)
    for owner in np.unique(device):
        for label in range(9):
            groups = rng.permutation(np.flatnonzero((device[first] == owner) & (lo == label)))
            a, b = int(len(groups) * .6), int(len(groups) * .8)
            for part, selected in enumerate((groups[:a], groups[a:b], groups[b:])):
                group_assignment[selected] = part
    if (group_assignment < 0).any():
        raise ValueError("Unassigned feature groups")
    return group_assignment[inverse], inverse, {
        "unique_feature_groups": len(first), "duplicate_excess_rows": int(len(y) - len(first)),
        "conflicting_label_groups": int((lo != hi).sum()),
        "conflicting_label_rows": int(counts[lo != hi].sum()),
        "cross_file_groups": int((owner_min != owner_max).sum()),
        "conflict_policy": "Retained; entire feature group assigned to one split",
        "split": "Non-temporal, feature-group stratified approximately 60/20/20",
    }
