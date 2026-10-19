"""Explicit local test attacks; not a production filtering policy."""
import numpy as np
from .seed_mpc_policy import SeedMPCPolicy
POLICY=SeedMPCPolicy(61706,4,20000,2500000000)

def norm2(q):
    return sum(int(v) ** 2 for v in q)


def accepted(q, policy=POLICY):
    return bool(np.all(np.abs(q) <= policy.coordinate_cap)) and norm2(q) <= policy.squared_threshold


def canonical(q, policy=POLICY):
    # A signed wire's effective representative, independent of intended input.
    half = policy.modulus // 2
    return (np.asarray(q, dtype=np.int64) + half) % policy.modulus - half


def bounded(q, fraction, policy=POLICY):
    target = int(policy.squared_threshold * fraction ** 2)
    if not np.any(q) or target == 0:
        return np.zeros_like(q)
    direction = -q.astype(np.float64)
    cap = policy.coordinate_cap
    def at(scale):
        return np.rint(np.clip(direction * scale, -cap, cap)).astype(np.int64)
    lo, hi = 0., 1.
    # Saturation can make a sparse direction unable to reach the requested norm.
    for _ in range(60):
        if norm2(at(hi)) >= target:
            break
        hi *= 2
    else:
        result = at(hi)
        assert accepted(result, policy)
        return result
    for _ in range(80):
        mid = (lo + hi) / 2
        if norm2(at(mid)) <= target:
            lo = mid
        else:
            hi = mid
    result = at(lo)
    assert accepted(result, policy) and norm2(result) <= target
    return result


def norm_overflow(q, policy=POLICY):
    """Test-only reverse own update: coordinate-valid, L2 about twice the cap.

    No honest update is used. All final entries remain canonical signed words.
    """
    target=4*policy.squared_threshold
    direction=-np.asarray(q,dtype=np.float64)
    if not np.any(direction):
        direction=np.ones_like(direction)
    def at(scale):
        return np.rint(np.clip(direction*scale,-policy.coordinate_cap,policy.coordinate_cap)).astype(np.int64)
    lo,hi=0.,1.
    for _ in range(60):
        if norm2(at(hi))>=target:break
        hi*=2
    else:raise ValueError('own-update direction cannot reach test norm target within coordinate cap')
    for _ in range(80):
        mid=(lo+hi)/2
        if norm2(at(mid))<=target:lo=mid
        else:hi=mid
    result=at(lo)
    if not (np.all(np.abs(result)<=policy.coordinate_cap) and policy.squared_threshold<norm2(result)<=target
            and np.array_equal(result,canonical(result,policy))):
        raise ValueError('noncanonical test norm-overflow vector')
    return result


def attack(q, case, policy=POLICY):
    q = np.asarray(q, dtype=np.int64)
    if case in ('clean', 'label-flip'):
        return q.copy()
    if case == 'norm-overflow':
        return norm_overflow(q,policy)
    if case == 'sign-flip':
        return -q
    if case.startswith('bounded-'):
        return bounded(q, .5 if case == 'bounded-50' else 1., policy)
    if case == 'out-of-bound':
        # Keep all values canonical so rejection isn't hidden by modulo aliasing.
        result = np.clip(q, -policy.coordinate_cap, policy.coordinate_cap)
        index = int(np.argmax(np.abs(q)))
        result[index] = (1 if q[index] >= 0 else -1) * (policy.coordinate_cap + 1)
        assert not accepted(result, policy)
        return result
    raise ValueError(case)


def flip_labels(y):
    result = y.copy()
    result[y == 0] = 6
    result[y == 6] = 0
    return result
