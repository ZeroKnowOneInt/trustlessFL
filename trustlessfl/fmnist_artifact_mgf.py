"""Experimental central FMNIST MGF selector matching the public artifact rule.

This deliberately receives plaintext local updates, like the artifact's
input-validation experiment. It is an ML baseline, not secure aggregation.
"""

import random

import numpy as np

from .crypto import ProtocolError
from .fmnist import DIMENSION

CLASSIFIER_WEIGHT = slice(DIMENSION - 850, DIMENSION - 10)
SHPRG_P = 173569775688864
SHPRG_Q = 5000999999999999


class ArtifactMGF:
    def __init__(self, *, dimension: int = DIMENSION,
                 selection_slice: slice = CLASSIFIER_WEIGHT,
                 seed: int = 0, mask_weight: float = 0.1,
                 min_fraction: float = 0.1):
        if (dimension < 2 or not 0 <= seed or not 0 < mask_weight < 1
                or not 0 < min_fraction < 0.5 or selection_slice.step is not None
                or selection_slice.start is None or selection_slice.stop is None
                or not 0 <= selection_slice.start < selection_slice.stop <= dimension):
            raise ProtocolError("invalid artifact MGF configuration")
        self.dimension, self.selection_slice = dimension, selection_slice
        self.mask_weight, self.min_fraction = mask_weight, min_fraction
        self.random = random.Random(seed)
        self.matrix = [self.random.randint(0, SHPRG_Q - 1)
                       for _ in range(selection_slice.stop - selection_slice.start)]
        self.previous_norms: list[float] = []
        self.previous_linf = 1.0
        self.previous_mask_linf = 1.0
        self.bound = 1.0

    def _mask(self, seed: int, amplitude: float) -> np.ndarray:
        # Artifact SHPRG has one matrix row for the FMNIST classifier layer.
        values = [((coefficient * seed % SHPRG_Q) * SHPRG_P * 2 + SHPRG_Q)
                  // (2 * SHPRG_Q) for coefficient in self.matrix]
        return np.asarray(values, dtype=np.float64) * (amplitude / SHPRG_P)

    def select_masked(self, masked: np.ndarray, mask_linf: float,
                      round_id: int) -> tuple[np.ndarray, dict]:
        """Select clients before aggregation, using only masked classifier rows.

        This does not authenticate a probe or establish that it corresponds to
        a client's ASR update. A caller using it with private updates must
        provide that binding separately.
        """
        width = self.selection_slice.stop - self.selection_slice.start
        if (type(round_id) is not int or round_id < 1 or not isinstance(masked, np.ndarray)
                or masked.ndim != 2 or masked.shape[1] != width or len(masked) < 2
                or not np.isfinite(masked).all() or not np.isfinite(mask_linf)
                or mask_linf < 0):
            raise ProtocolError("invalid artifact MGF masked projection")
        count = len(masked)
        norms = np.linalg.norm(masked.astype(np.float64), axis=1)
        order = np.argsort(norms, kind="stable")
        ordered_norms = norms[order]
        if round_id <= 3:
            bound = float(ordered_norms[int(self.min_fraction * count)])
        else:
            if len(self.previous_norms) != 2:
                raise ProtocolError("artifact MGF lacks previous global norms")
            denominator = self.previous_norms[0] + self.previous_mask_linf
            if denominator <= 0:
                raise ProtocolError("artifact MGF bound denominator is zero")
            bound = ((self.previous_norms[1] + mask_linf) / denominator) * self.bound
        rank = int(np.searchsorted(ordered_norms, bound, side="left"))
        # The paper experiment uses q=100 (min=10, max=80). Two is the safe
        # small-cohort smoke-test floor, not an assertion about the artifact.
        minimum = max(2, int(self.min_fraction * count))
        maximum = max(minimum, int(0.8 * count))
        retained = max(minimum, min(maximum, rank))
        selected = order[:retained]
        return selected, {
            "selected_indices": selected.tolist(), "selected_count": retained,
            "bound": bound, "masked_norms": norms.tolist(),
            "mask_linf": mask_linf,
            "small_cohort_floor_override": int(self.min_fraction * count) < 2,
        }

    def observe_aggregate(self, aggregate: np.ndarray, mask_linf: float,
                          bound: float, round_id: int) -> dict:
        """Advance Algorithm 6's state after the selected clients are summed."""
        if (type(round_id) is not int or round_id < 1 or not isinstance(aggregate, np.ndarray)
                or aggregate.shape != (self.dimension,) or not np.isfinite(aggregate).all()
                or not np.isfinite(mask_linf) or mask_linf < 0
                or not np.isfinite(bound) or bound < 0):
            raise ProtocolError("invalid artifact MGF aggregate")
        projected = aggregate[self.selection_slice].astype(np.float64)
        norm_new = float(np.linalg.norm(projected))
        if round_id <= 2:
            self.previous_norms.append(norm_new)
        else:
            self.previous_norms = [self.previous_norms[1], norm_new]
        self.previous_linf = float(np.max(np.abs(projected)))
        self.previous_mask_linf = mask_linf
        self.bound = bound
        return {"global_weight_l2": norm_new, "global_weight_linf": self.previous_linf}

    def aggregate(self, updates: np.ndarray, round_id: int) -> tuple[np.ndarray, dict]:
        if (type(round_id) is not int or round_id < 1 or not isinstance(updates, np.ndarray)
                or updates.ndim != 2 or updates.shape[1] != self.dimension
                or len(updates) < 2 or not np.isfinite(updates).all()):
            raise ProtocolError("invalid artifact MGF updates")
        count = len(updates)
        plain = updates.astype(np.float32)
        target = plain[:, self.selection_slice]
        amplitude = self.mask_weight * self.previous_linf
        seeds = [self.random.randint(0, SHPRG_Q - 1) for _ in range(count)]
        masks = np.stack([self._mask(seed, amplitude) for seed in seeds]).astype(np.float32)
        masked = target + masks
        mask_linf = float(np.max(np.sum(masks, axis=0, dtype=np.float64)))
        selected, trace = self.select_masked(masked, mask_linf, round_id)
        mean = np.mean(plain[selected], axis=0, dtype=np.float32).astype(np.float64)
        trace.update(self.observe_aggregate(mean, mask_linf, trace["bound"], round_id))
        return mean, trace


class AuthorArtifactMGF(ArtifactMGF):
    """Author SHPRG and torch.float32 MGF on CPU, not a secure wire protocol.

    Resume bootstrap arithmetic is supported; full Flower restart and GPU/CPU
    bitwise equivalence are not claimed. A supplied
    matrix must be the same as the reference transcript. The default matrix
    follows the author's one-row random.randint construction with a local RNG.
    """

    def __init__(self, *, public_setup=None, layer_sizes=None, resume_round=0, **kwargs):
        super().__init__(**kwargs)
        if type(resume_round) is not int or resume_round < 0:
            raise ProtocolError("author MGF resume round must be a nonnegative integer")
        self.resume_round = resume_round
        if layer_sizes is None:
            if self.dimension == DIMENSION:
                import torch
                from .fmnist import make_model
                with torch.random.fork_rng(devices=[]):
                    layer_sizes = tuple(p.numel() for p in make_model().state_dict().values())
            else:
                layer_sizes = (self.dimension,)
        if (any(type(n) is not int or n < 1 for n in layer_sizes)
                or sum(layer_sizes) != self.dimension):
            raise ProtocolError("author MGF layer sizes must partition the flattened model")
        self.layer_sizes = tuple(layer_sizes)
        from .aion_original_shprg import OriginalAionSHPRG
        if public_setup is None:
            p, q, matrix = SHPRG_P, SHPRG_Q, self.matrix
        else:
            p, q, *matrix = public_setup
            if len(matrix) != self.selection_slice.stop - self.selection_slice.start:
                raise ProtocolError("author SHPRG width differs from classifier projection")
            # The author constructor does not draw a fresh matrix when a saved
            # one exists. Do not consume unused matrix draws in this branch.
            self.random = random.Random(kwargs.get("seed", 0))
        self.shprg = OriginalAionSHPRG(p, q, matrix)
        self.matrix = list(self.shprg.matrix)

    def _mask(self, seed, amplitude):
        return np.asarray(self.shprg.generate(seed, len(self.matrix), amplitude), dtype=np.float64)

    def select_masked(self, masked, mask_linf, round_id):
        import torch
        width = self.selection_slice.stop - self.selection_slice.start
        if (type(round_id) is not int or round_id <= self.resume_round or not isinstance(masked, np.ndarray)
                or masked.ndim != 2 or masked.shape[1] != width or len(masked) < 2
                or not np.isfinite(masked).all() or not math_is_nonnegative(mask_linf)):
            raise ProtocolError("invalid author MGF projection")
        norms = torch.norm(torch.as_tensor(masked, dtype=torch.float32), dim=1)
        sorted_norms, order = torch.sort(norms)
        count = len(masked)
        minimum = int(self.min_fraction * count)
        if minimum < 2:
            raise ProtocolError("author MGF requires at least two clients at its unmodified minimum rank")
        if round_id <= self.resume_round + 3:
            bound = sorted_norms[minimum]
        else:
            if len(self.previous_norms) != 2:
                raise ProtocolError("author MGF lacks norm history")
            denominator = self.previous_norms[0] + self.previous_mask_linf
            if denominator <= 0:
                raise ProtocolError("author MGF denominator is zero")
            factor = (self.previous_norms[1] + mask_linf) / denominator
            bound = torch.tensor(self.bound, dtype=torch.float32) * factor
        retained = max(minimum, min(int(0.8 * count), int(torch.searchsorted(sorted_norms, bound))))
        selected = order[:retained].numpy()
        return selected, {"selected_indices": selected.tolist(), "selected_count": retained,
                          "bound": float(bound), "masked_norms": norms.tolist(),
                          "mask_linf": mask_linf, "small_cohort_floor_override": False,
                          "mgf_arithmetic": "author-torch-float32-cpu"}

    def observe_aggregate(self, aggregate, mask_linf, bound, round_id):
        import torch
        # Reuse validation/history bookkeeping, then replace norms with the author arithmetic.
        if type(round_id) is not int or round_id <= self.resume_round:
            raise ProtocolError("author MGF round must follow its resume checkpoint")
        super().observe_aggregate(aggregate, mask_linf, bound, round_id - self.resume_round)
        projected = torch.as_tensor(aggregate[self.selection_slice], dtype=torch.float32)
        norm = float(torch.norm(projected))
        self.previous_norms[-1] = norm
        self.previous_linf = float(torch.norm(projected, p=float("inf")))
        return {"global_weight_l2": norm, "global_weight_linf": self.previous_linf}

    def aggregate(self, updates, round_id):
        import torch
        if (not isinstance(updates, np.ndarray) or updates.ndim != 2
                or updates.shape[1] != self.dimension or not np.isfinite(updates).all()):
            raise ProtocolError("invalid author MGF updates")
        plain = torch.as_tensor(updates, dtype=torch.float32)
        masked, mask_linf = self.mask_projection(plain[:, self.selection_slice].numpy())
        selected, trace = self.select_masked(masked, mask_linf, round_id)
        offset, means = 0, []
        for width in self.layer_sizes:
            means.append(plain[:, offset:offset + width][selected].float().mean(dim=0))
            offset += width
        mean = torch.cat(means).numpy().astype(np.float64)
        trace.update(self.observe_aggregate(mean, mask_linf, trace["bound"], round_id))
        return mean, trace

    def mask_projection(self, projection):
        """Same author mask transcript for both control and ASR selection bridge."""
        import torch
        if (not isinstance(projection, np.ndarray) or projection.ndim != 2
                or projection.shape[1] != len(self.matrix) or not np.isfinite(projection).all()):
            raise ProtocolError("invalid author SHPRG projection")
        plain = torch.as_tensor(projection, dtype=torch.float32)
        amplitude = self.mask_weight * self.previous_linf
        seeds = [self.random.randint(0, self.shprg.q - 1) for _ in range(len(projection))]
        masks = torch.tensor([self.shprg.generate(seed, len(self.matrix), amplitude)
                              for seed in seeds], dtype=torch.float32)
        masked = plain + masks
        mask_sum = torch.tensor(self.shprg.client_sum_hprg(seeds, len(self.matrix), amplitude),
                                dtype=torch.float32)
        mask_linf = float(torch.norm(mask_sum, p=float("inf")))
        return masked.numpy(), mask_linf


def math_is_nonnegative(value):
    return isinstance(value, (int, float)) and np.isfinite(value) and value >= 0
