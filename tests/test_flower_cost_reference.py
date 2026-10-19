import numpy as np
import pytest

from trustlessfl.crypto import ProtocolError
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.research_cost_flower import aggregate_q


def test_exact_global_l2_boundary_and_signed16_minimum():
    p = SeedMPCPolicy(8,4,20000,2500000000)
    exact = np.array([20000]*6+[10000,0],dtype=np.int16)
    above = exact.copy();above[6]+=1
    invalid = np.zeros(8,dtype=np.int16);invalid[0]=-32768
    zero = np.zeros(8,dtype=np.int16)
    result,keep = aggregate_q([exact,above,invalid,zero],'plain-bound',p)
    assert keep == [True,False,False,True]
    assert result == {'status':'ok','count':2,'sum':exact.astype(np.int64).tolist()}


def test_global_norm_across_chunks_not_three_independent_checks():
    p = SeedMPCPolicy(65,4,20000,800000000)
    q = np.zeros(65,dtype=np.int16);q[[0,32,64]]=20000
    result,keep = aggregate_q([q]+[np.zeros(65,dtype=np.int16) for _ in range(3)],'plain-bound',p)
    assert keep == [False,True,True,True]
    assert result == {'status':'ok','count':3,'sum':[0]*65}


def test_unfiltered_mean_uses_wide_signed_sum():
    p = SeedMPCPolicy(1,4,20000,400000000)
    result,keep = aggregate_q([np.array([-32768],dtype=np.int16) for _ in range(4)],'plain-mean',p)
    assert keep == [True]*4
    assert result['sum'] == [-131072]


def test_below_minimum_retains_abort_semantics():
    p = SeedMPCPolicy(1,4,20000,1)
    result,keep = aggregate_q([np.array([v],dtype=np.int16) for v in (0,2,3,4)],'plain-bound',p)
    assert keep == [True,False,False,False]
    assert result == {'status':'abort'}


def test_invalid_wire_dtype_is_rejected_before_arithmetic():
    p = SeedMPCPolicy(1,4,20000,1)
    with pytest.raises(ProtocolError,match='signed16'):
        aggregate_q([np.array([0],dtype=np.uint16) for _ in range(4)],'plain-bound',p)
