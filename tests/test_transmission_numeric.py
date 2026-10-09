import itertools
import random
from fractions import Fraction

import pytest

from experiments.transmission_numeric import (TransmissionParameters, integer_update_bound,
    minimum_period, nearest_ratio, scale_mask, transmission_error_bound, worst_case_fixture)
from trustlessfl.crypto import ProtocolError

P = 14760426300877770769


@pytest.mark.parametrize('p', [3, 5, 11, 101])
@pytest.mark.parametrize('m', [1, 2, 3, 7, 20, 32])
def test_exhaustive_odd_denominator_scaling_translation_and_exact_fraction(p, m):
    for h in range(-p, 2*p+1):
        assert scale_mask(h, p=p, period=m) == round(Fraction(m*h, p))
        assert scale_mask(h+p, p=p, period=m) == scale_mask(h, p=p, period=m)+m
        assert (2*m*h) % (2*p) != p  # No exact half-tie.


@pytest.mark.parametrize('n', [2, 3, 4])
@pytest.mark.parametrize('m', [1, 2, 7, 31])
def test_exhaustive_composed_hprf_and_scaling_bound(n, m):
    p = 3 if n == 4 else 11
    q = 5*p
    bound = transmission_error_bound(n, p=p, q=q, period=m)
    # Exhaustive INTERNAL q representatives, not synthetic independent h/e.
    for ts in itertools.product(range(q), repeat=n):
        hs = [(t*p+q//2)//q for t in ts]
        carry, ta = divmod(sum(ts), q)
        ha = (ta*p+q//2)//q
        e = sum(scale_mask(h, p=p, period=m) for h in hs)-scale_mask(ha,p=p,period=m)-carry*m
        assert abs(e) <= bound


def test_requested_bound_requires_small_scaled_hprf_error():
    assert transmission_error_bound(20, p=P, q=5*P, period=32000) == 10
    assert transmission_error_bound(20, p=11, q=55, period=100) > 10


@pytest.mark.parametrize('d', [20, 21, 22, 32, 50, 100])
def test_actual_double_rounding_extremum_and_spacing_boundary(d):
    fixture = worst_case_fixture(p=P, period=32000)
    assert fixture['hprf_error'] == 8
    assert fixture['transmission_error'] == 10
    assert transmission_error_bound(20,p=P,q=5*P,period=32000) == 10
    # True U=1, residual d+10. d=20 -> 1.5 ties-even -> 2, not 1.
    assert nearest_ratio(d+10,d) == (2 if d == 20 else 1)
    plan = TransmissionParameters(P, 5*P, 32000, d, 10000, 20, '0.0001')
    wire_sum = d+sum(scale_mask(h,p=P,period=32000) for h in fixture['hs'])
    if d == 20:
        with pytest.raises(ProtocolError, match='infeasible'):
            plan.recover([wire_sum], [fixture['aggregate']], 20)
    else:
        assert plan.recover([wire_sum], [fixture['aggregate']], 20) == [1]


@pytest.mark.parametrize('n', [2, 20, 100])
@pytest.mark.parametrize('s', [10**4, 10**5, 10**6])
def test_minimum_period_is_strict_smallest_integer(n,s):
    d = n+1
    row = minimum_period(p=P,q=5*P,n=n,spacing=d,scale=s,real_bound='0.01')
    assert row['feasible']
    plan = TransmissionParameters(P,5*P,row['period'],d,s,n,'0.01')
    assert plan.feasible
    assert row['period'] == 2*(d*n*row['integer_bound']+row['error'])+1
    assert not TransmissionParameters(P,5*P,row['period']-1,d,s,n,'0.01').feasible


def test_random_large_hprf_integer_scaling_property():
    rng = random.Random(20261008)
    for _ in range(1000):
        m, h = rng.randint(2,10**12), rng.randint(0,P)
        assert scale_mask(h+P,p=P,period=m) == scale_mask(h,p=P,period=m)+m
        assert scale_mask(h,p=P,period=m) == round(Fraction(m*h,P))


def test_worst_case_is_reachable_with_actual_author_scalar_key():
    from experiments.audit_aion_hprf_carry import SOURCE, decomposition
    from trustlessfl.aion_original_hprf import OriginalAionHPRF
    if not (SOURCE/'matrix').is_file():
        pytest.skip('author setup required')
    hprf=OriginalAionHPRF.from_directory(SOURCE)
    keys=[79]*20  # Public valid domain fixture, not a likely random collision.
    masks=[hprf.hprf(k,451,1) for k in keys]
    aggregate=hprf.hprf(sum(keys),451,1)
    _,c,e,difference=decomposition(hprf,keys,451,masks,aggregate,0)
    assert c==1 and e==8 and difference==P+8
    transmission=sum(scale_mask(row[0],p=P,period=32000) for row in masks)-scale_mask(
        aggregate[0],p=P,period=32000)-c*32000
    assert transmission==10
    delta=Fraction(scale_mask(masks[0][0],p=P,period=32000))-Fraction(32000*masks[0][0],P)
    delta_a=Fraction(scale_mask(aggregate[0],p=P,period=32000))-Fraction(32000*aggregate[0],P)
    assert delta>0 and delta_a<0
    for d in [20,21,22,32,50,100]:
        # Same actual masks, one client u=1, nineteen clients u=0.
        total=d+sum(scale_mask(row[0],p=P,period=32000) for row in masks)
        residual=(total-scale_mask(aggregate[0],p=P,period=32000))%32000
        assert nearest_ratio(residual,d)==(2 if d==20 else 1)


def test_vectorized_quantization_matches_exact_decimal_near_boundaries():
    import numpy as np
    from experiments.audit_transmission_parameters import quantized
    from experiments.transmission_numeric import quantize
    for s in [10**4,10**5,10**6]:
        mid=np.arange(-30,31,dtype=float)/s+.5/s
        values=np.concatenate([mid,np.nextafter(mid,np.inf),np.nextafter(mid,-np.inf),
                               np.random.default_rng(0).normal(size=1000)])
        assert quantized(values,s).tolist()==quantize(values,s)


def test_wrapped_true_sum_remains_undetectable_without_bound_premise():
    plan = TransmissionParameters(P,5*P,32000,100,10**6,2,'0.000079')
    assert plan.feasible
    assert plan.recover([32000], [0], 2) == [0]  # Forbidden U=320 aliases 0.
    assert not TransmissionParameters(P,5*P,32000,100,10**6,2,'0.00008').feasible


@pytest.mark.parametrize('x,expected', [('0.00015',2), ('0.00025',2), ('0.000149',1)])
def test_monotonic_exact_quantized_clipping_bound(x,expected):
    assert integer_update_bound(10**4,x) == expected
