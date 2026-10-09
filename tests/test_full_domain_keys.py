"""Full scalar-domain compatibility tests, not production/security approval."""

import json
import random
from pathlib import Path

import numpy as np
import pytest

from experiments.full_domain_keys import sample_full_domain, validate_sum_capacity
from experiments.audit_full_domain_keys import (SOURCE, author_reference, boundary_keys,
    transport_audit, recovery_case)
from experiments.transmission_numeric import (TransmissionParameters, minimum_period,
    nearest_ratio, scale_mask, transmission_error_bound)
from experiments.audit_split_wire_amr import inverse_scalar_outputs
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ORDER, ProtocolError, canonical, pedersen_split, pedersen_reconstruct_pair
from trustlessfl.modular_recovery import center_p

P=14760426300877770769
Q=5*P


@pytest.fixture(scope='module')
def hprf():
    if not (SOURCE/'matrix').exists():
        pytest.skip('read-only author matrix unavailable')
    return OriginalAionHPRF.from_directory(SOURCE)


@pytest.mark.parametrize('nonzero',[False,True])
@pytest.mark.parametrize('end',[False,True])
def test_sampler_uniform_domain_mapping_without_remainder_bias(monkeypatch,nonzero,end):
    calls=[]
    def draw(bound):
        calls.append(bound)
        return bound-1 if end else 0
    monkeypatch.setattr('experiments.full_domain_keys.secrets.randbelow',draw)
    k=sample_full_domain(Q,nonzero=nonzero)
    assert calls==[Q-1 if nonzero else Q]
    assert k==(Q-1 if end else int(nonzero))


@pytest.mark.parametrize('q',[0,1,-1,True,3.5,'100'])
def test_sampler_invalid_domain(q):
    with pytest.raises(ValueError):sample_full_domain(q)


def test_os_sampler_smoke():
    # No uniqueness/randomness proof inferred from this test.
    assert all(0<=sample_full_domain(Q)<Q for _ in range(100))
    assert all(0<sample_full_domain(Q,nonzero=True)<Q for _ in range(100))


@pytest.mark.parametrize('key',boundary_keys(Q))
def test_boundaries_author_hprf_vss_and_python_json_exact(hprf,key):
    reference=author_reference(hprf)
    for r in [1,4,451]:
        values=hprf.hprf(key,r,1025)
        assert values==reference.hprf(key,r,1025)
        assert values==hprf.hprf(key+Q,r,1025)
        assert all(type(v) is int and 0<=v<=P for v in values)
    shares,commits=pedersen_split(key,2,4)
    assert pedersen_reconstruct_pair(shares,commits)[0]==key
    saved=canonical(dict(mask_seed=key,shares=shares))
    assert json.loads(saved)['mask_seed']==key
    assert np.asarray([key],dtype=object).tolist()==[key]


def test_zero_key_mathematically_valid_but_unmasked(hprf):
    assert hprf.hprf(0,4,1025)==[0]*1025


def test_vss_capacity_is_in_order_not_hprf_q():
    validate_sum_capacity(Q,100,ORDER)
    assert 100*(Q-1)>Q
    with pytest.raises(ValueError):validate_sum_capacity(Q,100,100*(Q-1))
    validate_sum_capacity(Q,100,100*(Q-1)+1)


@pytest.mark.parametrize('small',[True,False])
def test_authenticated_transport_and_existing_runtime_policy(hprf,small):
    result=transport_audit(hprf,[1,2,3,4] if small else boundary_keys(Q))
    assert result['primitive_and_authenticated_transport_exact']
    assert result['runtime_policy_result']==('accepted' if small else
        'source aggregate key outside author key domain')
    if not small:assert result['exceeds_q']


@pytest.mark.parametrize('count',[2,20,100])
@pytest.mark.parametrize('round_id',[1,4,17,451])
def test_full_domain_modular_recovery_and_error_bounds(hprf,count,round_id):
    rng=random.Random(100000+count+round_id)
    keys=[rng.randrange(Q) for _ in range(count)]
    d=2*transmission_error_bound(count,p=P,q=Q,period=32000)+1
    row=minimum_period(p=P,q=Q,n=count,spacing=d,scale=10000,real_bound='0.01')
    plan=TransmissionParameters(P,Q,row['period'],d,10000,count,'0.01')
    updates=np.asarray([[rng.randint(-100,100) for _ in range(513)] for _ in keys])
    updates[:,0]=100;updates[:,1]=-100
    result=recovery_case(hprf,keys,round_id,updates,plan)
    assert result['plaintext_exact'] and result['max_abs_transmission_error']<=plan.error


def test_large_key_reachable_spacing_boundary(hprf):
    rng=random.Random(12983)
    for _ in range(2000):
        k=rng.randrange(Q//2,Q)
        hs=hprf.hprf(k,451,1)[0];ha=hprf.hprf(20*k,451,1)[0]
        e=center_p(20*hs-ha,P);c=(20*hs-ha-e)//P
        residual=20*scale_mask(hs,p=P,period=32000)-scale_mask(ha,p=P,period=32000)-c*32000
        if abs(residual)==10:break
    else:pytest.fail('deterministic large-key extremum fixture missing')
    sign=1 if residual>0 else -1
    assert nearest_ratio(20*sign+residual,20)!=sign
    assert nearest_ratio(21*sign+residual,21)==sign


def test_growing_key_does_not_repair_raw_output_inversion(hprf):
    for k in [Q//2+12345,Q-1234567]:
        result=inverse_scalar_outputs(hprf,4,[v%P for v in hprf.hprf(k,4,32)])
        assert result['candidates']==[k]
        assert len(result['coordinate_indices'])==2


def test_large_key_does_not_repair_old_transmission_range():
    plan=TransmissionParameters(P,Q,32000,100,1000000,20,'0.1')
    assert not plan.feasible
    with pytest.raises(ProtocolError,match='infeasible'):
        plan.recover([0],[0],20)


def test_local_client_enrollment_retry_preserves_large_fixture_key(tmp_path,monkeypatch):
    from trustlessfl.aion_source_server import provision_source
    from trustlessfl.aion_source_asr import source_request
    path,nodes=provision_source(tmp_path/'fixture',SOURCE.parents[2],clients=10,
        committee=4,committee_members=[0,1,2,3],workload='synthetic',rounds=4)
    manifest=json.loads(path.read_text());state={}
    calls=[]
    def fixture_draw(self,low,high):
        calls.append((low,high))
        return Q-1  # Deliberately override ONLY in isolated unit fixture.
    monkeypatch.setattr(random.SystemRandom,'randint',fixture_draw)
    request=dict(action='enroll',round=1,task=manifest['task'])
    first=source_request(nodes[1],state,request)
    assert state['mask_seed']==Q-1 and calls==[(1,100000)]
    state=json.loads(canonical(state))
    assert source_request(nodes[1],state,request)==first
    assert state['mask_seed']==Q-1 and len(calls)==1


def test_report_all_requested_workloads_and_failure_policy():
    path=Path('.cache/full-domain-keys-20261009-v3/report.json')
    if not path.exists():pytest.skip('run offline audit to generate local ledger')
    report=json.loads(path.read_text())
    assert report['production_unchanged']
    assert report['encrypted_transport_small']['runtime_policy_result']=='accepted'
    assert report['encrypted_transport_full']['runtime_policy_result']=='source aggregate key outside author key domain'
    assert all(row['plaintext_exact'] for row in report['recovery']['results'])
    assert len(report['recovery']['results'])==24
    assert sum(row['exact_coordinates'] for row in report['recovery']['results'])==752772
    assert len(report['small_key_search']['rows'])==20
    assert all(row['unique_true_key'] and row['plaintext_quanta_exact']
               for row in report['small_key_search']['rows'])
    assert all(row['exact'] for row in report['raw_output_inversion']['rows'])
