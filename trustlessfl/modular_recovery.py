"""Bounded integer modular SUM recovery, with no carry enumeration.

Arithmetic only: callers must establish the honest client update bounds and
the mask/wire relation. Post-decode checks cannot prove a wrapped input was
in range. This module neither changes MGF nor authenticates VSS/mask binding.
"""

from dataclasses import dataclass
from fractions import Fraction

from .crypto import ProtocolError
from .paper_dmc import round_even


def center_p(value, modulus):
    if type(value) is not int or type(modulus) is not int or modulus < 2:
        raise ProtocolError("integer value and modulus >= 2 required")
    residue = value % modulus
    return residue-modulus if residue > modulus//2 else residue


def hprf_error_bound(count, *, p, q):
    """Bound the original nearest-rounded integer HPRF's raw residual.

    In the supplied odd-p, q=5p setup, h=(t+2)//5. Each rounding residual is
    at most 2/5; the integer aggregate error is <= floor(2*(n+1)/5).
    Otherwise use the conservative ceil((n+1)/2) nearest-round bound. This
    assumes q-domain key additivity, not an arbitrary PRF implementation.
    """
    if any(type(v) is not int for v in (count, p, q)) or count < 1 or not 1 < p < q:
        raise ProtocolError("invalid rounded HPRF parameters")
    if count == 1:
        return 0
    return 2*(count+1)//5 if q == 5*p and p % 2 else (count+2)//2


def spacing_limits(modulus, max_clients, client_bound, error_bound):
    if (any(type(v) is not int for v in (modulus, max_clients, client_bound, error_bound))
            or modulus < 2 or max_clients < 1 or client_bound < 1 or error_bound < 0):
        raise ProtocolError("invalid modular recovery bounds")
    minimum = 2*error_bound+1
    maximum = (modulus-1-2*error_bound)//(2*max_clients*client_bound)
    return dict(minimum_spacing=minimum, maximum_spacing=maximum, feasible=minimum <= maximum)


def modular_sum(vectors, modulus):
    if type(modulus) is not int or modulus < 2 or not vectors:
        raise ProtocolError("nonempty integer modular sum required")
    dimension = len(vectors[0])
    if any(len(row) != dimension or any(type(x) is not int for x in row) for row in vectors):
        raise ProtocolError("modular sum requires same-shaped integer vectors")
    # Reduce only on the server; input vectors remain unchanged for MGF.
    return [sum(row[j] for row in vectors) % modulus for j in range(dimension)]


@dataclass(frozen=True)
class ModularRecovery:
    modulus: int
    spacing: int
    max_clients: int
    client_bound: int
    error_bound: int           # Includes integer mask multiplier A.
    mask_multiplier: int = 1

    def __post_init__(self):
        limits = spacing_limits(self.modulus, self.max_clients, self.client_bound, self.error_bound)
        if (type(self.spacing) is not int or type(self.mask_multiplier) is not int
                or self.mask_multiplier < 1
                or not limits["minimum_spacing"] <= self.spacing <= limits["maximum_spacing"]):
            raise ProtocolError("infeasible modular recovery spacing or centered capacity")

    def recover(self, total, aggregate_hprf, *, selected_count):
        if type(selected_count) is not int or not 1 <= selected_count <= self.max_clients:
            raise ProtocolError("invalid modular recovery selected count")
        if (len(total) != len(aggregate_hprf) or any(type(y) is not int for y in total)
                or any(type(h) is not int or not 0 <= h <= self.modulus for h in aggregate_hprf)):
            raise ProtocolError("invalid integer total or original HPRF representative")
        decoded = []
        for y, h in zip(total, aggregate_hprf, strict=True):
            residual = center_p((y-self.mask_multiplier*h) % self.modulus, self.modulus)
            value = round_even(Fraction(residual, self.spacing))
            if abs(residual-self.spacing*value) > self.error_bound:
                raise ProtocolError("modular recovery residual exceeds HPRF error bound")
            if abs(value) > selected_count*self.client_bound:
                raise ProtocolError("modular recovery update sum exceeds declared bound")
            decoded.append(value)
        return decoded


def maximum_clients(*, modulus, spacing, client_bound, mask_multiplier, p, q):
    """Largest n satisfying BOTH constraints, recomputing E(n) for each n."""
    spacing_limits(modulus, 1, client_bound, 0)
    if (type(spacing) is not int or spacing < 1 or type(mask_multiplier) is not int
            or mask_multiplier < 1 or modulus != p):
        raise ProtocolError("invalid fixed-spacing client envelope")
    low, high = 0, (modulus-1)//(2*spacing*client_bound)
    while low < high:
        mid = (low+high+1)//2
        error = mask_multiplier*hprf_error_bound(mid, p=p, q=q)
        if spacing > 2*error and 2*(spacing*mid*client_bound+error) < modulus:
            low = mid
        else:
            high = mid-1
    return low
