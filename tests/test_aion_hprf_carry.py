"""Carry evidence and independent reference vs existing modular runtime."""

from fractions import Fraction

import pytest

from experiments.audit_aion_hprf_carry import (
    SOURCE, center, check_capacity, decode, decomposition, encode,
    feasibility, modular_reference,
)
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import (
    ORDER, ProtocolError, aggregate_commitments, pedersen_reconstruct,
    pedersen_split, sum_pedersen_shares,
)
from trustlessfl.numeric import FixedPoint
from trustlessfl.paper_dmc import PaperDMC


@pytest.fixture(scope="module")
def hprf():
    if not (SOURCE / "matrix").is_file():
        pytest.skip("author matrix required; toy tests do not establish real carry")
    return OriginalAionHPRF.from_directory(SOURCE)


@pytest.mark.parametrize("p,expected", [(101, [0, 1, -1, 50, -50]),
                                      (100, [0, 1, -1, 50, -49])])
def test_center_boundaries(p, expected):
    values = [0, 1, p - 1, p // 2, p // 2 + 1]
    assert [center(x, p) for x in values] == expected
    assert center(-1, p) == -1
    assert center(p + 1, p) == 1


@pytest.mark.parametrize("value", ["0", "0.12345649", "-0.12345649",
                                   "0.0000001", "9.99999949", "-9.99999949"])
def test_quantization(value):
    s = 10**6
    z = encode(value, s)
    assert abs(decode(z, s) - Fraction(value)) <= Fraction(1, 2 * s)


def test_quantization_ties_even():
    assert [encode(x, 10) for x in ("0.05", "0.15", "-0.05", "-0.15")] == [0, 2, 0, -2]


def test_toy_no_carry_and_carry():
    # Toy ring, not evidence about the actual author HPRF.
    for masks, aggregate, carry in [([[10], [20]], [30], 0),
                                    ([[80], [70]], [49], 1)]:
        assert sum(v[0] for v in masks) - aggregate[0] == carry * 101
        result = modular_reference([[2], [-3]], masks, aggregate, modulus=101,
            delta=8, max_clients=2, integer_bound=3, error_bound=0)
        assert result == [-1]


def test_actual_carry_and_literal_dmr(hprf):
    keys, r = [38298, 5945], 450
    masks = [hprf.hprf(k, r, 3) for k in keys]
    aggregate = hprf.hprf(sum(keys), r, 3)
    d, c, e, _ = decomposition(hprf, keys, r, masks, aggregate, 1)
    assert c != 0
    assert d == c * hprf.p + e
    assert abs(e) <= 2
    # Literal DMR only removes sub-quantum rounding error, not a p multiple.
    dmc = PaperDMC(2, 6, hprf.p)
    masked = [dmc.mask([0], [v[1]])[0] for v in masks]
    assert dmc.remove([sum(masked)], [aggregate[1]]) != [Fraction(0)]


def test_actual_no_carry(hprf):
    keys, r = [38298, 5945], 450
    masks = [hprf.hprf(k, r, 1025) for k in keys]
    aggregate = hprf.hprf(sum(keys), r, 1025)
    coordinates = [j for j in range(1025)
                   if decomposition(hprf, keys, r, masks, aggregate, j)[1] == 0]
    assert coordinates
    j = coordinates[0]
    recovered = modular_reference([[2], [-3]], [[v[j]] for v in masks], [aggregate[j]],
        modulus=hprf.p, delta=10, max_clients=2, integer_bound=3, error_bound=2)
    assert recovered == [-1]


def test_literal_dmr_removes_small_error_without_carry():
    # Distinct toy check of what the existing literal error elimination does.
    dmc = PaperDMC(2, 2, 101)
    total = sum(dmc.mask([0], [h])[0] for h in (20, 30))
    assert dmc.residual([total], [49]) == [Fraction(1, 1000)]
    assert dmc.remove([total], [49]) == [Fraction(0)]


def test_actual_error_runtime_mask_and_asr(hprf):
    keys = [38298, 5945, 87654]
    r, dimension = 450, 1025
    codec = FixedPoint(decimals=6, max_abs=10, max_clients=100,
                       mask_backend="aion-original", original_hprf_setup=hprf.public_setup())
    emax = 51
    limits = check_capacity(hprf.p, codec.padding, 100, codec.max_integer, emax)
    assert limits["feasible"]
    # Existing Pedersen aggregate-share reconstruction, no VSS modifications.
    assert sum(keys) < ORDER
    shared = [pedersen_split(k, 2, 4) for k in keys]
    commitments = aggregate_commitments([c for _, c in shared])
    shares = {i: sum_pedersen_shares([s[i] for s, _ in shared]) for i in (1, 3)}
    recovered_key = pedersen_reconstruct(shares, commitments)
    assert recovered_key == sum(keys)
    values = [[(-1)**(j + i) * ((j % 17) / 100 + 0.00000049)
               for j in range(dimension)] for i in range(len(keys))]
    encoded = [codec.encode(v) for v in values]
    assert encoded == [[encode(x, codec.scale) for x in v] for v in values]
    masks = [hprf.hprf(k, r, dimension) for k in keys]
    aggregate = hprf.hprf(recovered_key, r, dimension)
    errors = [decomposition(hprf, keys, r, masks, aggregate, j)[2]
              for j in range(dimension)]
    assert any(errors), "must exercise nonzero rounding error"
    assert max(map(abs, errors)) < codec.padding / 2
    plain = [sum(v) for v in zip(*encoded, strict=True)]
    reference = modular_reference(encoded, masks, aggregate, modulus=hprf.p,
        delta=codec.padding, max_clients=100, integer_bound=codec.max_integer, error_bound=emax)
    wire = [codec.mask(v, k, "carry-test", r) for v, k in zip(values, keys, strict=True)]
    assert all(type(x) is int and 0 <= x < hprf.p for v in wire for x in v)
    total = [sum(v) % hprf.p for v in zip(*wire, strict=True)]
    assert codec.unmask(total, recovered_key, "carry-test", r, len(keys)) == reference == plain
    # Too-small delta: demonstrate actual error changes a zero plaintext sum.
    j = next(i for i, e in enumerate(errors) if e)
    d = sum(v[j] for v in masks) - aggregate[j]
    assert round(Fraction(center(d, hprf.p), 1)) != 0


def test_infeasible_parameters_and_unsafe_wrap():
    assert not feasibility(101, 2, 10, 3)["feasible"]
    with pytest.raises(ValueError, match="infeasible"):
        check_capacity(101, 8, 2, 10, 0)
    with pytest.raises(ValueError, match="infeasible"):
        check_capacity(101, 2, 2, 3, 1)  # strict delta > 2E
    # Bypassing capacity checks loses information; residues cannot diagnose it.
    actual_sum = 12
    assert abs(8 * actual_sum) * 2 >= 101
    assert round(Fraction(center(8 * actual_sum, 101), 8)) != actual_sum
    with pytest.raises(ValueError, match="update bound"):
        modular_reference([[4], [0]], [[0], [0]], [0], modulus=101,
            delta=8, max_clients=2, integer_bound=3, error_bound=0)


def test_existing_runtime_rejects_unsafe_capacity(hprf):
    with pytest.raises(ProtocolError, match="capacity"):
        FixedPoint(decimals=9, max_abs=10**15, max_clients=100,
                   mask_backend="aion-original", original_hprf_setup=hprf.public_setup())


def test_existing_runtime_quantization_bounds(hprf):
    codec = FixedPoint(decimals=6, max_abs=10, max_clients=100,
                       mask_backend="aion-original", original_hprf_setup=hprf.public_setup())
    values = [0.0, 0.12345649, -0.12345649, 0.0000001, 10.0, -10.0]
    for x, z in zip(values, codec.encode(values), strict=True):
        assert abs(decode(z, codec.scale) - Fraction(str(x))) <= Fraction(1, 2 * codec.scale)
    with pytest.raises(ProtocolError, match="bound"):
        codec.encode([10.000001])
