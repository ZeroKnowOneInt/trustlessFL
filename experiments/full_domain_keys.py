"""OFFLINE sampler for the author's existing scalar key ring, not a new PRF.

Never imported by the Flower runtime. Zero is algebraically valid and yields
an all-zero mask; including it gives the exact uniform Z_q experiment. The
optional nonzero subset is also uniform but is not a security repair.
"""

import secrets


def sample_full_domain(q: int, *, nonzero: bool = False) -> int:
    if type(q) is not int or q < 2 or type(nonzero) is not bool:
        raise ValueError("integer modulus >= 2 and boolean nonzero required")
    return 1 + secrets.randbelow(q - 1) if nonzero else secrets.randbelow(q)


def validate_sum_capacity(q: int, count: int, order: int) -> None:
    """ASR in ORDER must lift the INTEGER key sum before HPRF reduces mod q."""
    if (any(type(v) is not int for v in (q, count, order)) or q < 2 or count < 1
            or count * (q - 1) >= order):
        raise ValueError("full-domain integer key sum does not fit VSS field")
