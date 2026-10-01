"""Compatibility adapter for Aion/agent/Aion/HPRF/hprf.py.

Preserves the supplied artifact matrix, moduli, block inputs and rounding.
This is not the separate input-validation experiment's SHPRG, nor a new
security claim. The original tree is read-only; no matrix is regenerated.
"""

import io
import pickle
from pathlib import Path

from .crypto import ProtocolError


class _PrimitiveUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        raise ProtocolError("original HPRF files must contain only primitive data")

    def persistent_load(self, pid):
        raise ProtocolError("persistent references are forbidden in HPRF files")


def _read_primitive(path: Path):
    return _PrimitiveUnpickler(io.BytesIO(path.read_bytes())).load()


class OriginalAionHPRF:
    """Exact integer hprf() output compatibility, before downstream encoding."""

    def __init__(self, n: int, m: int, p: int, q: int, matrix):
        if (any(type(v) is not int for v in (n, m, p, q))
                or not 0 < n < m or not 0 < p < q
                or not isinstance(matrix, (list, tuple)) or len(matrix) != n
                or any(not isinstance(row, (list, tuple)) or len(row) != m
                       or any(type(v) is not int or not 0 <= v < q for v in row)
                       for row in matrix)):
            raise ProtocolError("invalid original Aion HPRF parameters or matrix")
        self.n, self.m, self.p, self.q = n, m, p, q
        # Exactly the column-sum optimization already present in the author code.
        self.column_sums = tuple(sum(row[j] for row in matrix) for j in range(m))

    @classmethod
    def from_directory(cls, directory):
        directory = Path(directory)
        parameters = _read_primitive(directory / "initialization_values")
        if not isinstance(parameters, (tuple, list)) or len(parameters) != 4:
            raise ProtocolError("invalid original HPRF initialization file")
        return cls(*parameters, _read_primitive(directory / "matrix"))

    def hprf(self, k: int, x: int, length: int) -> list[int]:
        if (any(type(v) is not int for v in (k, x, length)) or length < 0):
            raise ProtocolError("HPRF key, input and nonnegative length must be integers")
        result = []
        for block in range((length + self.m - 1) // self.m):
            scalar = k * (x + block) % self.q
            result.extend(((scalar * column % self.q) * self.p + self.q // 2)
                          // self.q for column in self.column_sums)
        # Deliberately no final '% p': the original hprf() has none.
        return result[:length]

    def public_setup(self) -> tuple[int, ...]:
        """Portable immutable public coefficients, bound by the task manifest."""
        return (self.n, self.m, self.p, self.q, *self.column_sums)

    @classmethod
    def from_public_setup(cls, setup):
        if (not isinstance(setup, tuple) or len(setup) < 5
                or any(type(v) is not int for v in setup)):
            raise ProtocolError("invalid original HPRF public setup")
        n, m, p, q, *columns = setup
        if (not 0 < n < m or not 0 < p < q or len(columns) != m
                or any(not 0 <= v <= n * (q - 1) for v in columns)):
            raise ProtocolError("invalid original HPRF public coefficients")
        instance = cls.__new__(cls)
        instance.n, instance.m, instance.p, instance.q = n, m, p, q
        instance.column_sums = tuple(columns)
        return instance
