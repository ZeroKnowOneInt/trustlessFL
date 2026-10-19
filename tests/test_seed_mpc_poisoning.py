import numpy as np
from experiments.run_seed_mpc_poisoning import attack, accepted, bounded, canonical, flip_labels, norm2, POLICY


def test_bounded_quantized_attack_meets_both_bounds():
    q=np.arange(-400,400,dtype=np.int64)
    for fraction in (.5,1.):
        result=bounded(q,fraction)
        assert accepted(result)
        assert norm2(result)<=int(POLICY.squared_threshold*fraction**2)
        assert norm2(result)>int(POLICY.squared_threshold*fraction**2)*.999
        assert np.all(result[q>0]<=0) and np.all(result[q<0]>=0)


def test_oversized_input_is_effective_out_of_bound():
    q=np.zeros(61706,dtype=np.int64);q[0]=10
    result=attack(q,'out-of-bound')
    assert np.array_equal(canonical(result),result)
    assert not accepted(result)


def test_zero_direction_and_label_mapping():
    assert not np.any(bounded(np.zeros(5,dtype=np.int64),1.))
    labels=np.array([0,1,6,9],dtype=np.uint8)
    assert flip_labels(labels).tolist()==[6,1,0,9]
    assert labels.tolist()==[0,1,6,9]


def test_signed_wire_alias_and_sign_norm_invariance():
    assert canonical(np.array([32767,32768,65535,65536,-32769])).tolist()==[32767,-32768,-1,0,32767]
    q=np.array([-20000,1,20000],dtype=np.int64)
    result=attack(q,'sign-flip')
    assert norm2(result)==norm2(q)
    assert accepted(result)==accepted(q)


def test_global_norm_attack_is_coordinate_valid_and_canonical():
    import numpy as np
    from trustlessfl.seed_mpc_poisoning_fixture import norm_overflow, norm2, canonical, accepted
    from trustlessfl.seed_mpc_policy import SeedMPCPolicy
    policy=SeedMPCPolicy(65,4,20000,400000000)
    q=np.arange(1,66,dtype=np.int64)
    attacked=norm_overflow(q,policy)
    assert np.all(np.abs(attacked)<=policy.coordinate_cap)
    assert policy.squared_threshold<norm2(attacked)<=4*policy.squared_threshold
    assert np.array_equal(attacked,canonical(attacked,policy))
    assert not accepted(attacked,policy)


def test_global_norm_attack_requires_no_honest_update_for_zero_input():
    import numpy as np
    from trustlessfl.seed_mpc_poisoning_fixture import norm_overflow,norm2
    from trustlessfl.seed_mpc_policy import SeedMPCPolicy
    policy=SeedMPCPolicy(65,4,20000,400000000)
    attacked=norm_overflow(np.zeros(65,dtype=np.int64),policy)
    assert policy.squared_threshold<norm2(attacked)<=4*policy.squared_threshold
