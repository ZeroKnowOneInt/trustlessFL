"""Author input-validation SHPRG arithmetic, separate from ASR HPRF.

Adapted from Aion/input_validation/FL_Backdoor_CV/shprg/shprg.py. Public
matrix and parameters are caller supplied; no claims about PRF security.
"""

import math

from .crypto import ProtocolError


class OriginalAionSHPRG:
    def __init__(self, p: int, q: int, matrix):
        # The original G() represents the seed as [[seed]], so only n=1 works.
        if (type(p) is not int or type(q) is not int or not 0 < p < q
                or not isinstance(matrix, (list, tuple)) or len(matrix) < 2
                or any(type(v) is not int or not 0 <= v < q for v in matrix)):
            raise ProtocolError("invalid original one-row SHPRG setup")
        self.p, self.q, self.matrix = p, q, tuple(matrix)

    def G(self, seed: int) -> list[int]:
        if type(seed) is not int:
            raise ProtocolError("SHPRG seed must be an integer")
        return [(2 * (coefficient * seed % self.q) * self.p + self.q)
                // (2 * self.q) for coefficient in self.matrix]

    def generate(self, seed: int, length: int, max_mask: float) -> list[float]:
        if (type(length) is not int or length < 0
                or not isinstance(max_mask, (int, float)) or not math.isfinite(max_mask)
                or max_mask < 0):
            raise ProtocolError("invalid original SHPRG output settings")
        values = self.G(seed)
        repeated = (values * (length // len(values) + 1))[:length]
        # Preserve the author's floating operation order; do not factor max_mask/p.
        return [x * max_mask / self.p for x in repeated]

    def client_sum_hprg(self, seeds, length: int, max_mask: float) -> list[float]:
        result = [0 for _ in range(length)]
        for seed in seeds:
            values = self.generate(seed, length, max_mask)
            result = [(a + b) % self.p for a, b in zip(result, values, strict=True)]
        return result
