import itertools
import random
from fractions import Fraction

import pytest

from experiments.audit_aion_hprf_carry import SOURCE
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError
from trustlessfl.modular_recovery import (ModularRecovery, center_p,
    hprf_error_bound, modular_sum, maximum_clients, spacing_limits)
from trustlessfl.paper_dmc import PaperDMC
from trustlessfl.source_paper_numeric import mask_integer_wire


@pytest.mark.parametrize("p", [100, 101])
@pytest.mark.parametrize("offset", [0, 1, -1, "half", "half+1"])
def test_center_matches_positive_midpoint_convention(p, offset):
    value = p//2 if offset == "half" else p//2+1 if offset == "half+1" else offset
    actual = center_p(value, p)
    residue = value % p
    assert actual == (residue-p if residue > p//2 else residue)
    assert actual % p == value % p


@pytest.mark.parametrize("mask_rows,aggregate", [([[2], [3]], [5]),
    ([[80], [70]], [49]), ([[80], [70], [90]], [38]),
    ([[2, 80, 90], [3, 70, 80], [4, 90, 90]], [9, 38, 58])])
@pytest.mark.parametrize("sign", [-1, 0, 1])
def test_no_carry_one_carry_multiple_carry_and_signed_sums(mask_rows, aggregate, sign):
    n, dimension = len(mask_rows), len(aggregate)
    plan = ModularRecovery(101, 8, n, 1, 1)
    updates = [[sign]*dimension] + [[0]*dimension for _ in range(n-1)]
    wire = [[8*z+h for z, h in zip(u, m, strict=True)]
            for u, m in zip(updates, mask_rows, strict=True)]
    before = [row[:] for row in wire]
    final = modular_sum(wire, 101)
    stepwise = [0]*dimension
    for row in wire:
        stepwise = [(a+b) % 101 for a, b in zip(stepwise, row, strict=True)]
    assert final == stepwise
    assert wire == before  # Server reduction never changes the MGF input.
    assert plan.recover(final, aggregate, selected_count=n) == [sign]*dimension


@pytest.mark.parametrize("e", [-1, 0, 1])
def test_small_hprf_residual_removed_and_explicit_residual_checked(e):
    plan = ModularRecovery(101, 8, 2, 2, 1)
    # 150-(49-e)=101+e; model integer sum -1.
    assert plan.recover([150-8], [49-e], selected_count=2) == [-1]
    with pytest.raises(ProtocolError, match="residual exceeds"):
        plan.recover([150-8], [47], selected_count=2)


def test_error_at_half_spacing_and_update_overflow_configs_rejected():
    with pytest.raises(ProtocolError, match="infeasible"):
        ModularRecovery(101, 8, 2, 1, 4)
    with pytest.raises(ProtocolError, match="infeasible"):
        ModularRecovery(101, 8, 2, 4, 1)
    assert spacing_limits(101, 2, 4, 4)["feasible"] is False


def test_post_decode_range_check():
    plan = ModularRecovery(101, 8, 2, 2, 1)
    with pytest.raises(ProtocolError, match="sum exceeds"):
        plan.recover([40], [0], selected_count=2)  # z_sum=5 > 2*2.


def test_post_checks_cannot_certify_unseen_out_of_range_plaintext():
    plan = ModularRecovery(101, 8, 2, 1, 1)
    # A forbidden true sum 101 aliases 0. Honest client-bound enforcement is
    # a precondition; no residue-only decoder can detect every such violation.
    assert plan.recover([(8*101) % 101], [0], selected_count=2) == [0]


@pytest.mark.parametrize("n", [2, 3, 4, 5, 6])
def test_q_equals_five_p_rounding_bound_by_exhaustive_residues(n):
    p, q = 101, 505
    observed = 0
    for ts in itertools.product(range(5), repeat=n):
        total = sum(ts)
        carry, ta = divmod(total, q)
        e = sum((t*p+q//2)//q for t in ts)-(ta*p+q//2)//q-carry*p
        observed = max(observed, abs(e))
        assert abs(e) <= hprf_error_bound(n, p=p, q=q)
    assert observed == hprf_error_bound(n, p=p, q=q)


@pytest.mark.parametrize("n", [2, 3, 20, 100])
def test_original_hprf_integer_scale_recovery_is_exact_without_enumeration(n):
    if not (SOURCE/"matrix").is_file():
        pytest.skip("original author HPRF setup required")
    hprf = OriginalAionHPRF.from_directory(SOURCE)
    codec = PaperDMC(n, 6, hprf.p)
    rng = random.Random(100+n)
    keys = [rng.randint(1, 100000) for _ in range(n)]
    dimension, round_id = 513, 4
    updates = [[rng.randint(-1000, 1000) for _ in range(dimension)] for _ in keys]
    masks = [hprf.hprf(k, round_id, dimension) for k in keys]
    wire = [mask_integer_wire(codec, z, h) for z, h in zip(updates, masks, strict=True)]
    total = modular_sum(wire, hprf.p)
    aggregate = hprf.hprf(sum(keys), round_id, dimension)
    recovered = codec.remove_modular_integer_wire(total, aggregate, selected_count=n,
        client_integer_bound=1000, original_q=hprf.q)
    assert recovered == [sum(row[j] for row in updates) for j in range(dimension)]
    for j, ha in enumerate(aggregate):
        difference = sum(row[j] for row in masks)-ha
        assert abs(center_p(difference, hprf.p)) <= hprf_error_bound(n, p=hprf.p, q=hprf.q)


def test_current_fractional_mgf_scale_rejected_without_legacy_fallback(monkeypatch):
    codec = PaperDMC(20, 6, 14760426300877770769).with_mgf("0.0016", hmax_domain="normalized")
    def forbidden(*args, **kwargs):
        raise AssertionError("modular recovery must not enumerate carries")
    monkeypatch.setattr(PaperDMC, "remove_quantized_lift", forbidden)
    with pytest.raises(ProtocolError, match="fractional decimal mask scale"):
        codec.remove_modular_integer_wire([0], [0], selected_count=2,
            client_integer_bound=10**8, original_q=5*codec.modulus)


def test_maximum_clients_recomputes_error_instead_of_fixing_observed_e():
    p = 14760426300877770769
    assert maximum_clients(modulus=p, spacing=100, client_bound=10**8,
                           mask_multiplier=1, p=p, q=5*p) == 123


@pytest.mark.parametrize("value,p", [(True, 101), (0.0, 101), (0, True), (0, 1)])
def test_invalid_center_inputs_rejected(value, p):
    with pytest.raises(ProtocolError):
        center_p(value, p)
