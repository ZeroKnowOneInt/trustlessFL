"""Plaintext ground-truth audit on public FMNIST; never a secure aggregation API."""
import hashlib

import numpy as np

from .aion_original_hprf import OriginalAionHPRF
from .crypto import ProtocolError
from .private_bound import NoWrapPolicy, ReferenceSubmission, aggregate, scale_canonical_mask

PROFILES = ((1, 1), (15, 21), (840000021, 21), (2**128, 21))


def quantize(delta, scale, cap):
    if (type(scale) is not int or type(cap) is not int or scale < 1 or not 1 <= cap <= 2**52
            or delta.dtype != np.float64 or delta.ndim != 1 or not np.isfinite(delta).all()):
        raise ProtocolError("invalid quantization configuration or delta")
    values = np.rint(delta * scale)
    if not np.isfinite(values).all() or np.any(np.abs(values) > cap):
        raise ProtocolError("update exceeds frozen coordinate cap; no clipping permitted")
    return tuple(int(value) for value in values)


def audit_updates(updates, *, scale, cap, threshold, seed, minimum=2):
    if not updates or not updates[0]:
        raise ProtocolError("empty audit cohort")
    dimension, clients = len(updates[0]), len(updates)
    if any(len(u) != dimension or any(type(v) is not int or abs(v) > cap for v in u) for u in updates):
        raise ProtocolError("invalid audit integer input")
    # Independent oracle: no mask, offset, spacing or modular operation.
    norms = [sum(v*v for v in u) for u in updates]
    accepted = [i for i, norm in enumerate(norms) if norm <= threshold]
    total = tuple(sum(updates[i][j] for i in accepted) for j in range(dimension))
    oracle = ({"status": "ok", "sum": total, "count": len(accepted)}
              if len(accepted) >= minimum else {"status": "abort"})
    hprf = OriginalAionHPRF(1, 2, 14760426300877770769, 5*14760426300877770769, [[1, 2]])
    x = int(hashlib.sha256(str(seed).encode()).hexdigest(), 16)
    representatives = [tuple(h % hprf.p for h in hprf.hprf(
        int(hashlib.sha256(f"{seed}:{i}".encode()).hexdigest(), 16) % hprf.q, x, dimension))
        for i in range(clients)]
    audits = []
    for M, d in PROFILES:
        policy = NoWrapPolicy(dimension, clients, cap, scale, d, M, threshold, minimum)
        rows = []
        for u, raw in zip(updates, representatives, strict=True):
            masks = tuple(scale_canonical_mask(h, hprf.p, M) for h in raw)
            offsets = policy.encode(u, masks)
            recovered = tuple((v-d*cap-m)//d for v, m in zip(offsets, masks, strict=True))
            if recovered != u:
                raise AssertionError("per-coordinate integer recovery differs")
            rows.append(ReferenceSubmission(offsets, masks))
        result = aggregate(policy, rows, mode="plaintext-reference")
        if result != oracle:
            raise AssertionError("masked reference differs from independent integer oracle")
        aliased = sum((d*v % M if 2*(d*v % M) < M else d*v % M-M) != d*v for v in total)
        audits.append({"M": str(M), "spacing": d, "coordinate_recovery_error": 0,
                       "sum_error": 0, "selected_count_matches": True,
                       "old_centered_modular_alias_coordinates": aliased, "widths": policy.widths()})
    return oracle, {"profiles": audits, "normal_clients": clients,
                    "excluded_normal_clients": clients-len(accepted),
                    "squared_norm_min": min(norms), "squared_norm_max": max(norms)}
