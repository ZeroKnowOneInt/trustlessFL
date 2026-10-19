"""Arithmetic counterexamples and execution gate; no cryptographic MPC claims."""
from dataclasses import replace
from fractions import Fraction
from itertools import product

import pytest

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.private_bound import (
    DynamicBound, NoWrapPolicy, PrivateBackendUnavailable, PublicRound,
    ReferenceSubmission, aggregate, scale_canonical_mask,
)


def policy(**changes):
    values = dict(dimension=1, max_clients=3, coordinate_cap=2, scale=1,
                  spacing=5, mask_max=15, squared_bound=4, minimum_accepted=2)
    return NoWrapPolicy(**(values | changes))


def submission(p, update, masks):
    return ReferenceSubmission(p.encode(update, masks), tuple(masks))


def reference(p, rows):
    return aggregate(p, rows, mode="plaintext-reference")


def test_private_execution_never_falls_back_or_reads_private_inputs():
    class Exploding:
        def __iter__(self):
            pytest.fail("must fail before reading private inputs")
    with pytest.raises(PrivateBackendUnavailable, match="no plaintext fallback"):
        aggregate(policy(), Exploding())


def test_old_modular_sum_alias_is_recovered_as_exact_integer():
    p = policy()
    rows = [submission(p, [2], [m]) for m in (1, 2, 3)]
    raw_total = sum(row.offsets[0]-p.spacing*p.coordinate_cap for row in rows)
    assert (raw_total-6) % p.mask_max == 0  # Old decoder would report 0.
    assert reference(p, rows) == {"status": "ok", "sum": (6,), "count": 3}


@pytest.mark.parametrize("M,d", tuple(product((1, 15, 840000021, 2**128), (1, 21))))
@pytest.mark.parametrize("u", (-10, 10))
def test_sum_larger_than_M_and_negative_sum(M, d, u):
    p = policy(coordinate_cap=10, mask_max=M, spacing=d, squared_bound=100)
    rows = [submission(p, [u], [m]) for m in (0, M//2, M)]
    assert reference(p, rows)["sum"] == (3*u,)


def test_canonical_hprf_endpoint_and_real_author_adapter():
    hprf = OriginalAionHPRF(1, 4, 101, 505, [[1, 2, 3, 4]])
    p = policy(dimension=4, squared_bound=16, mask_max=1, spacing=1)
    updates = [(2, -2, 2, -2), (-2, 2, -2, 2), (1, 1, 1, 1)]
    rows = []
    raw_endpoint_seen = False
    for k, u in zip((504, 350, 400), updates):
        raw = hprf.hprf(k, 1, 4)
        raw_endpoint_seen |= hprf.p in raw
        masks = [scale_canonical_mask(h % hprf.p, hprf.p, p.mask_max) for h in raw]
        rows.append(submission(p, u, masks))
    assert raw_endpoint_seen  # New profile explicitly canonicalizes author's p endpoint.
    assert reference(p, rows) == {"status": "ok", "sum": (1, 1, 1, 1), "count": 3}
    with pytest.raises(ProtocolError, match="canonical"):
        scale_canonical_mask(hprf.p, hprf.p, 1)


@pytest.mark.parametrize("kind", ("off-grid", "coordinate-large", "unused-wire-code"))
def test_bad_coordinate_excludes_whole_client(kind):
    p = policy(dimension=2, squared_bound=8)
    valid = submission(p, [1, 1], [0, 0])
    offsets = list(valid.offsets)
    offsets[0] = {"off-grid": offsets[0]+1, "coordinate-large": 25,
                  "unused-wire-code": p.offset_max+1}[kind]
    invalid = ReferenceSubmission(tuple(offsets), (0, 0))
    assert reference(p, [valid, valid, invalid]) == {"status": "ok", "sum": (2, 2), "count": 2}


def test_large_wire_is_not_narrowed_before_range_check_or_square():
    p = policy(mask_max=2**128, spacing=1)
    valid = submission(p, [1], [0])
    invalid = ReferenceSubmission((p.offset_max,), (0,))
    assert reference(p, [valid, valid, invalid])["sum"] == (2,)


def test_norm_modular_alias_cannot_pass_exact_norm_check():
    p = policy(dimension=4, squared_bound=9, max_clients=3)
    assert 16 % 8 == 0 and 16 % 8 <= p.squared_bound
    zero = submission(p, [0]*4, [0]*4)
    too_large = submission(p, [2]*4, [0]*4)
    assert reference(p, [zero, zero, too_large]) == {"status": "ok", "sum": (0,)*4, "count": 2}


def test_boundary_can_change_without_changing_arithmetic_widths():
    p = policy(dimension=4, squared_bound=16)
    lower = replace(p, squared_bound=1)
    assert p.widths() == lower.widths()
    rows = [submission(p, [2]*4, [0]*4)]*2
    assert reference(p, rows)["status"] == "ok"
    assert reference(lower, rows) == {"status": "abort"}


@pytest.mark.parametrize("total, expected", [(1, 0), (3, 2), (-1, 0), (-3, -2)])
def test_mean_only_rounding_is_exact_and_hides_count_in_output(total, expected):
    p = policy(output="mean-only")
    values = (total//2, total-total//2)
    result = reference(p, [submission(p, [u], [0]) for u in values])
    assert result == {"status": "ok", "mean": (expected,)}


def test_abort_never_outputs_underpopulated_sum():
    p = policy()
    assert reference(p, [submission(p, [2], [0])]) == {"status": "abort"}
    assert reference(p, []) == {"status": "abort"}


@pytest.mark.parametrize("field,value", [("dimension", True), ("coordinate_cap", 0),
    ("spacing", 1.5), ("mask_max", 0), ("scale", False), ("squared_bound", 5),
    ("minimum_accepted", 4), ("output", "open-client-scores")])
def test_invalid_policy_is_rejected(field, value):
    with pytest.raises(ProtocolError):
        policy(**{field: value})


def test_bitwidths_at_million_coordinate_profile():
    p = policy(dimension=10**6, max_clients=20, coordinate_cap=10**6,
               scale=10000, spacing=21, mask_max=840000021, squared_bound=10**18)
    assert p.widths() == dict(offset_unsigned=30, residual_signed=31, update_signed=21,
                            norm_unsigned=60, sum_signed=26, count_unsigned=5)
    small = replace(p, mask_max=1, spacing=1)
    assert small.widths()["offset_unsigned"] == 21
    assert small.widths()["norm_unsigned"] == 60
    assert small.widths()["sum_signed"] == 26


def test_dynamic_bootstrap_and_two_successful_public_outputs():
    p = policy(coordinate_cap=100, squared_bound=10000)
    bound = DynamicBound(400, 1, 1600)
    assert bound.next_threshold(p, []) == 400
    assert bound.next_threshold(p, [PublicRound(1, (10,), 400)]) == 400
    history = [PublicRound(1, (10,), 400), PublicRound(2, (5,), 400)]
    assert bound.next_threshold(p, history) == 103  # RoundEven(400*26/101).
    assert bound.next_threshold(p, history) == 103  # Abort leaves history unchanged.


@pytest.mark.parametrize("old,new,previous,minimum,maximum,expected", [
    (0, 0, 100, 1, 1600, 100), (0, 100, 100, 1, 1600, 400),
    (100, 0, 100, 40, 1600, 40), (0, 100, 1000, 1, 1600, 1600)])
def test_dynamic_zero_history_ratio_clamp_and_safety_caps(old,new,previous,minimum,maximum,expected):
    p = policy(coordinate_cap=100, squared_bound=10000)
    bound = DynamicBound(previous, minimum, maximum)
    history = [PublicRound(1, (old,), previous), PublicRound(2, (new,), previous)]
    assert bound.next_threshold(p, history) == expected


def test_dynamic_uses_unbounded_public_intermediate_products():
    p = policy(dimension=10**6, max_clients=20, coordinate_cap=10**6,
               scale=10000, spacing=1, mask_max=1, squared_bound=10**18)
    bound = DynamicBound(10**18, 1, 10**18)
    history = [PublicRound(1, (0,)*p.dimension, 10**18),
               PublicRound(2, (10**6,)*p.dimension, 10**18)]
    assert bound.next_threshold(p, history) == 10**18


@pytest.mark.parametrize("history", [
    [PublicRound(2,(0,),4),PublicRound(1,(0,),4)],
    [PublicRound(1,(0,),4),PublicRound(1,(0,),4)],
    [PublicRound(1,(3,),4)], [PublicRound(1,(0,),5)]])
def test_invalid_public_history_cannot_drive_threshold(history):
    with pytest.raises(ProtocolError):
        DynamicBound(4,1,4).next_threshold(policy(), history)


def test_dynamic_maximum_cannot_expand_arithmetic_capacity():
    with pytest.raises(ProtocolError, match="safety envelope"):
        DynamicBound(4,1,5).next_threshold(policy(), [])


def test_dynamic_ratio_rejects_inexact_float_configuration():
    with pytest.raises(ProtocolError, match="exact rational"):
        DynamicBound(4,1,4,ratio_minimum=0.25)
