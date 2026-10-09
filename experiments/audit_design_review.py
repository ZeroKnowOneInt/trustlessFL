"""Independent arithmetic/paper-mapping review; runtime files are read-only.

Reference rounding uses fractions.Fraction, separately from the integer
helpers under test. Small-q enumeration is labelled as a toy algebra test.
Fresh real-HPRF/FMNIST regressions and public security fixtures are rerun.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path
import random
import time

from experiments.audit_full_domain_keys import recovery_regression, output_inversion
from experiments.audit_transmission_parameters import (key_space_audit, collect_workload,
    detection_sweep)
from experiments.transmission_numeric import (scale_mask, transmission_error_bound,
    TransmissionParameters, minimum_period)
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import canonical
from trustlessfl.modular_recovery import center_p, hprf_error_bound
from trustlessfl.numeric import FixedPoint
from trustlessfl.paper_dmc import PaperDMC
from trustlessfl.source_paper_numeric import (paper_codec, mask_integer_wire,
    select_masked, FILTER_RULE, SUM_SCALE_SOURCE)

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT.parent/'Aion/agent/Aion/HPRF'


def reference_h(t,p,q):
    return round(Fraction(p*t,q))


def reference_scale(h,p,m):
    return round(Fraction(m*h,p))


def arithmetic_enumeration():
    rows=[]
    for p,n in [(3,2),(3,3),(3,4),(5,2),(5,3),(11,2),(11,3)]:
        q=5*p
        hs=[reference_h(t,p,q) for t in range(q)]
        for m in sorted({1,2,p-1,p,3*p}):
            scaled=[reference_scale(h,p,m) for h in hs]
            eh_bound=hprf_error_bound(n,p=p,q=q)
            e_bound=transmission_error_bound(n,p=p,q=q,period=m)
            max_e=max_wire=cases=0; witness=None
            for ts in itertools.product(range(q),repeat=n):
                c,ta=divmod(sum(ts),q)
                e=sum(hs[t] for t in ts)-hs[ta]-c*p
                residual=sum(scaled[t] for t in ts)-scaled[ta]-c*m
                assert abs(e)<=eh_bound
                assert abs(residual)<=e_bound
                if abs(residual)>max_wire:
                    max_wire=abs(residual);witness=dict(ts=ts,carry=c,e=e,E=residual)
                max_e=max(max_e,abs(e));cases+=1
            rows.append(dict(p=p,q=q,n=n,M=m,cases=cases,max_raw_error=max_e,
                raw_bound=eh_bound,max_scaled_error=max_wire,scaled_bound=e_bound,
                witness=witness,scope='exhaustive toy internal-q representatives'))
    return rows


def scaling_boundaries(hprf):
    rng=random.Random(193260109);cases=0
    for p in [3,5,11,hprf.p]:
        for m in [1,2,3,21,32000,p//2,p-1,p,3*p]:
            for h in [-p-1,-p,-1,0,1,p-1,p,p+1]+[rng.randrange(-3*p,3*p) for _ in range(50)]:
                assert scale_mask(h,p=p,period=m)==reference_scale(h,p,m)
                assert scale_mask(h+p,p=p,period=m)==scale_mask(h,p=p,period=m)+m
                cases+=1
    midpoint=[]
    for m in [5,6,21,22,32000,32001]:
        for z in [0,1,m-1,m//2,m//2+1,-1]:
            residue=z%m
            expected=residue if 2*residue<=m else residue-m
            assert center_p(z,m)==expected
            midpoint.append(dict(M=m,z=z,center=expected))
    # A REAL source HPRF coordinate reaching the inclusive h=p endpoint.
    coefficient=hprf.column_sums[0]%hprf.q
    from math import gcd
    assert gcd(coefficient,hprf.q)==1
    key=(hprf.q-1)*pow(coefficient,-1,hprf.q)%hprf.q
    assert hprf.hprf(key,1,1)==[hprf.p]
    assert scale_mask(hprf.p,p=hprf.p,period=32000)==32000
    # General bound is safe but not always the sharp attainable maximum.
    p=11;q=55;n=20;m=7
    ts=[3]*n;c,ta=divmod(sum(ts),q)
    hs=[reference_h(t,p,q) for t in ts];ha=reference_h(ta,p,q)
    e=sum(hs)-ha-c*p
    residual=sum(reference_scale(h,p,m) for h in hs)-reference_scale(ha,p,m)-c*m
    assert e==8 and residual==12>10
    assert residual<=transmission_error_bound(n,p=p,q=q,period=m)==14
    return dict(translation_cases=cases,midpoints=midpoint,
        real_raw_p_endpoint=dict(key=key,round=1,coordinate=0,h=hprf.p,scaled=32000),
        large_ratio=dict(p=p,q=q,n=n,M=m,ts=ts,carry=c,e=e,E=residual,bound=14,
            invalid_small_M_bound=10),
        identity_scale=dict(p=p,M=p,raw_bound=hprf_error_bound(n,p=p,q=q),
            general_scaled_bound=transmission_error_bound(n,p=p,q=q,period=p)))


def current_manifest():
    return dict(clients=list(range(20)),dimension=8,decimals=6,
        paper_numerics=dict(initial_linf='0.012347',beta='0.2',projection=[0,8],
            filter_rule=FILTER_RULE,scale_source=SUM_SCALE_SOURCE))


def adaptive_period_review(hprf):
    manifest=current_manifest()
    codec=paper_codec(manifest,hprf,4,'1/625')
    length=codec.denominator
    period=codec.coefficient*hprf.p
    assert period==32000 and length==100000000
    x_prev=Fraction(1,625)
    beta=Fraction(1,5)
    assert period/length==beta*x_prev
    # Two honest in-bound public updates; choose a zero HPRF error coordinate.
    keys=[4,16];quanta=[[0,350,-350,0,0,0,0,0]]*2
    masks=[hprf.hprf(k,4,8) for k in keys]
    wires=[mask_integer_wire(codec,u,h) for u,h in zip(quanta,masks)]
    aggregate=hprf.hprf(sum(keys),4,8)
    entries=[]
    for j in [1,2]:
        total=sum(v[j] for v in wires)
        u=sum(v[j] for v in quanta)
        residual=center_p(total-scale_mask(aggregate[j],p=hprf.p,period=32000),32000)
        got=round(Fraction(residual,100))
        raw=sum(v[j] for v in masks)-aggregate[j]
        eh=center_p(raw,hprf.p);c=(raw-eh)//hprf.p
        error=sum(scale_mask(v[j],p=hprf.p,period=32000) for v in masks)-scale_mask(
            aggregate[j],p=hprf.p,period=32000)-c*32000
        assert got!=u and abs(100*u+error)>=16000
        entries.append(dict(coordinate=j,true_U=u,decoded=got,E=error,
            true_abs_residual=abs(100*u+error),half_period=16000))
    fmnist=ROOT/'.cache/same-scale-fmnist-official-20261008/manifest.json'
    # Keep the public numerical witness reproducible without a local run cache.
    live=current_manifest()
    live['paper_numerics']['initial_linf']='9894833/16777216'
    if fmnist.exists():
        live=json.loads(fmnist.read_text())
    initial=paper_codec(live,hprf,1)
    fm=initial.coefficient*hprf.p
    assert fm.denominator!=1
    return dict(runtime_spacing=100,model_denominator=length,period=str(period),
        physical_period=str(period/length),previous_sum_linf=str(x_prev),beta=str(beta),
        necessary_implied_contraction='||X_r||inf < beta*||X_(r-1),J||inf/2 + Emax/(d*S)',
        sufficient_no_cancellation_contraction='||X_r||inf + Emax/(d*S) < beta*||X_(r-1),J||inf/2',
        sum_alias_witnesses=entries,
        fmnist_initial_integer_wire_period=str(fm),fmnist_initial_period_is_integer=False,
        fmnist_source='archived manifest' if fmnist.exists() else 'public initial-linf fixture',
        scope='current SUM scale semantics; not a universal impossibility theorem for the paper')


def history_and_weight_counterexamples():
    toy=OriginalAionHPRF(1,2,101,505,[[1,2]])
    m=21;d=3;s=1;keys=[400,350];u=[1,0]
    hs=[toy.hprf(k,1,1)[0] for k in keys]
    ha=toy.hprf(sum(keys),1,1)[0]
    masks=[reference_scale(h,101,m) for h in hs]
    ma=reference_scale(ha,101,m)
    total=sum(d*z+v for z,v in zip(u,masks))
    plan=TransmissionParameters(101,505,m,d,s,2,'1')
    assert plan.recover([total],[ha],2)==[1]
    recovered_mask_sum=total-d
    paper_term=Fraction(1)+Fraction(m*ha,d*s*101)
    actual_term=Fraction(1)+Fraction(recovered_mask_sum,d*s)
    assert actual_term!=paper_term
    # Weighted arithmetic changes the SAME-vector norm, even with valid mask.
    h=toy.hprf(70,1,1)[0];mask=reference_scale(h,101,m)
    assert mask==3
    weight=3;plain_y=d+mask;weighted_y=d*weight+mask
    original_v=Fraction(plain_y,d*s);weighted_v=Fraction(weighted_y,d*s)
    divided_v=weighted_v/weight
    assert original_v==2 and weighted_v==4 and divided_v==Fraction(4,3)
    return dict(history=dict(scope='realizable small-modulus scalar HPRF, not production parameters',
        p=101,q=505,M=m,d=d,S=s,keys=keys,hs=hs,ha=ha,scaled_masks=masks,
        aggregate_scaled_mask=ma,wire_sum=total,recovered_U=1,actual_mask_sum=recovered_mask_sum,
        prompt_history_term=str(actual_term),paper_literal_history_term=str(paper_term)),
        weighted=dict(key=70,h=h,scaled_mask=mask,weight=weight,u=1,
            unweighted_v=str(original_v),weighted_v=str(weighted_v),
            weight_divided_v=str(divided_v),bound='3',unweighted_pass=True,weighted_pass=False,
            second_bound='3/2',unweighted_second_pass=False,divided_second_pass=True))


def projection_and_postcheck_counterexamples():
    codec=PaperDMC(20,6,101)
    manifest=dict(dimension=2,paper_numerics=dict(projection=[0,1],filter_rule=FILTER_RULE))
    vectors=[dict(sender=i,masked_vector=[0,10**50]) for i in range(20)]
    selected=select_masked(manifest,dict(paper_bound='1',paper_terms=['1','1']),codec,vectors,4)
    assert len(selected['selected'])==20
    p=14760426300877770769
    plan=TransmissionParameters(p,5*p,32000,100,1000000,2,'0.000079')
    assert plan.feasible and plan.recover([32000],[0],2)==[0]
    # A non-grid-aligned bound exposes floor-vs-nearest metadata disagreement.
    numeric=FixedPoint(decimals=4,max_abs=0.00015,max_clients=2)
    encoded=numeric.encode([0.00015,-0.00015])
    assert encoded==[2,-2] and numeric.max_integer==1
    return dict(projection=dict(selected=len(selected['selected']),uninspected_coordinate=10**50,
        scope='predicate counterexample; not a signed malicious-client protocol execution'),
        postcheck=dict(period=32000,d=100,true_out_of_premise_sum=320,recovered_sum=0,
            decoded_residual_check_passes=True,scope='violates declared honest input bounds'),
        quantized_bound=dict(C='0.00015',S=10000,encoded=encoded,
            runtime_max_integer=numeric.max_integer,round_even_bound=2,
            scope='non-grid-aligned configuration; default C=100 is unaffected'))


def input_overlap(hprf):
    key=hprf.q//2+12345
    a=hprf.hprf(key,1,1024)[512:1024]
    b=hprf.hprf(key,2,512)
    assert a==b
    return dict(public_fixture_key=key,first_round=1,first_block=1,second_round=2,
                second_block=0,equal_coordinates=512,scope='existing r+block encoding; unchanged')


def mgf_replay_review(hprf, output):
    """Rerun three declared envelope choices, retaining failed selections.

    Uses the prior experiment's detector, not an independent MGF design.
    Public small keys and frozen local updates are explicit limitations.
    """
    run=ROOT/'.cache/same-scale-fmnist-official-20261008'
    workload=ROOT/'.cache/transmission-parameter-audit-20261008-v1/workload.npz'
    manifest,history,_,reference,images,labels,snapshots,malicious=collect_workload(
        run,output,reuse=workload)
    rows=[]
    for bound in ['0.001','0.01','100']:
        minimum=minimum_period(p=hprf.p,q=hprf.q,n=20,spacing=21,
            scale=10000,real_bound=bound)
        plan=TransmissionParameters(hprf.p,hprf.q,minimum['period'],21,10000,20,bound)
        assert plan.feasible
        rows.append(dict(**asdict(plan),feasible=True))
    result=detection_sweep(hprf,rows,manifest,history,snapshots,malicious,
        reference,images,labels)
    result['input_sha256']={str(path):hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [workload,run/'manifest.json',run/'results.json']}
    return result


def run(output):
    output.mkdir(parents=True,exist_ok=False)
    paths=[*sorted((ROOT/'trustlessfl').glob('*.py')),SOURCE/'hprf.py',SOURCE/'matrix',SOURCE/'initialization_values']
    before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    started=time.monotonic();hprf=OriginalAionHPRF.from_directory(SOURCE)
    result=dict(scope='independent review, runtime unchanged',p=hprf.p,q=hprf.q,
        runtime_hashes=before,paper_url='https://www.usenix.org/system/files/usenixsecurity25-liu-yizhong.pdf',
        local_paper_sha256=hashlib.sha256((ROOT/'docs/AION.pdf').read_bytes()).hexdigest())
    for name,fn in [
        ('arithmetic_enumeration',arithmetic_enumeration),
        ('scaling_boundaries',lambda:scaling_boundaries(hprf)),
        ('adaptive_period',lambda:adaptive_period_review(hprf)),
        ('counterexamples',history_and_weight_counterexamples),
        ('bound_enforcement',projection_and_postcheck_counterexamples),
        ('input_overlap',lambda:input_overlap(hprf)),
        ('fresh_recovery',lambda:recovery_regression(hprf,ROOT/'.cache/transmission-parameter-audit-20261008-v1/workload.npz')),
        ('fresh_small_key_search',lambda:key_space_audit(hprf)),
        ('fresh_raw_output_inversion',lambda:output_inversion(hprf)),
        ('fresh_mgf_replay',lambda:mgf_replay_review(hprf,output)),
    ]:
        print(name,flush=True);result[name]=fn()
    assert before=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    result.update(runtime_unchanged=True,wall_seconds=time.monotonic()-started)
    with (output/'report.json').open('xb') as f:f.write(canonical(result))
    print(str(output/'report.json'),flush=True)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    run(parser.parse_args().output)
