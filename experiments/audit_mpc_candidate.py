"""Review direct private input vs masked MPC. Compile-only cost comparison.

No native MPC runtime, Flower training, TLS tests, or production backend changes.
The clear direct evaluator is an executable ideal-function specification only.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import re
import subprocess
import sys
import uuid

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.private_bound import NoWrapPolicy, ReferenceSubmission, aggregate, scale_canonical_mask
from experiments.run_private_bound_mpc import backend_prime_for

ROOT=Path(__file__).resolve().parents[1]
DIRECT_SOURCE = """# REVIEW CIRCUIT ONLY: direct unsigned offset bits, no HPRF/key/mask.
import json
from pathlib import Path
from Compiler.types import sint, regint, Array
from Compiler.library import listen_for_clients, accept_client_connection, runtime_error_if, print_ln
config=json.loads(Path(program.args[1]).read_text())
program.active=True
D=config['dimension']; N=config['clients']; B=config['coordinate_cap']; T=config['squared_bound']
W=(2*B).bit_length()
listen_for_clients(config['client_port'])
sockets=Array(N,regint)
seen=Array(N,regint); seen.assign_all(0)
for _ in range(N):
    cid=accept_client_connection(config['client_port'])
    runtime_error_if((cid<0)+(cid>=N),'invalid registered client id')
    runtime_error_if(seen[cid]!=0,'duplicate registered client id')
    seen[cid]=1; sockets[cid]=cid
inputs=[sint.receive_from_client(D*W,sockets[i]) for i in range(N)]
check=sint(0)
for row in inputs:
    for bit in row:
        check+=sint.get_random()*bit*(bit-1)
opened=check.reveal()
full=opened.bit_decompose(config['backend_prime'].bit_length())
runtime_error_if(sum(regint.conv(bit) for bit in full)!=0,'invalid canonical private input')
count=sint(0); total=[sint(0) for _ in range(D)]
for row in inputs:
    valid=sint(1); effective=[]
    for j in range(D):
        v=sum(row[j*W+t]*(1<<t) for t in range(W))
        coordinate_ok=v.less_equal(2*B,bit_length=W+1)
        z=coordinate_ok.if_else(v-B,0)
        effective.append(z); valid*=coordinate_ok
    squared_norm=sum(z*z for z in effective)
    accepted=valid*squared_norm.less_equal(T,bit_length=(D*B*B).bit_length()+1)
    count+=accepted
    for j in range(D): total[j]+=accepted*effective[j]
ok=count.greater_equal(config['minimum_accepted'],bit_length=N.bit_length()+1)
sint.reveal_to_clients(sockets,[ok,ok*count]+[ok*z for z in total])
print_ln('DIRECT_PRIVATE_BOUND_REVIEW_STATUS %s',ok.reveal())
"""


def direct(bits_rows, *, D, B, T, minimum):
    """Plaintext oracle. Production requires authenticated malicious-secure input."""
    W=(2*B).bit_length()
    if any(len(row)!=D*W or any(type(b) is not int or b not in (0,1) for b in row) for row in bits_rows):
        return {'status':'input-abort'}
    total=[0]*D; count=0
    for row in bits_rows:
        values=[sum(row[j*W+t]<<t for t in range(W)) for j in range(D)]
        valid=all(v<=2*B for v in values)
        z=[v-B if v<=2*B else 0 for v in values]
        Q=sum(v*v for v in z)
        assert Q<=D*B*B
        accepted=valid and Q<=T
        count+=int(accepted)
        total=[a+int(accepted)*b for a,b in zip(total,z)]
    assert all(abs(v)<=len(bits_rows)*B for v in total)
    return {'status':'ok','count':count,'sum':tuple(total)} if count>=minimum else {'status':'abort'}


def encode(updates,B):
    W=(2*B).bit_length()
    assert all(abs(u)<=B for row in updates for u in row)
    return [[((u+B)>>t)&1 for u in row for t in range(W)] for row in updates]


def audits():
    exhaustive=0
    for B in range(1,6):
        for D in (1,2):
            W=(2*B).bit_length(); T=D*B*B//2
            for values in itertools.product(range(1<<W),repeat=D):
                bits=[[v>>t&1 for v in values for t in range(W)]]
                expected_u=tuple(v-B for v in values)
                accepted=all(v<=2*B for v in values) and sum(u*u for u in expected_u)<=T
                expected={'status':'ok','count':1,'sum':expected_u} if accepted else {'status':'abort'}
                assert direct(bits,D=D,B=B,T=T,minimum=1)==expected
                exhaustive+=1
    rng=random.Random(42); matched=0
    hprf=OriginalAionHPRF(1,2,101,505,[[1,2]])
    for _ in range(100):
        updates=[[rng.randint(-10,10) for _ in range(2)] for _ in range(4)]
        T=rng.randint(0,200)
        expected=direct(encode(updates,10),D=2,B=10,T=T,minimum=2)
        for M in (1,15,840000021,2**128):
            for d in (1,21):
                policy=NoWrapPolicy(2,4,10,1,d,M,T,2)
                submissions=[]
                for update in updates:
                    key=rng.randrange(hprf.q); seed=rng.randrange(1,10000)
                    mask=tuple(scale_canonical_mask(h%hprf.p,hprf.p,M) for h in hprf.hprf(key,seed,2))
                    submissions.append(ReferenceSubmission(policy.encode(update,mask),mask))
                assert aggregate(policy,submissions,mode='plaintext-reference')==expected
                matched+=1
    a=[[0],[0],[3],[6]]; b=[[0],[0],[1],[8]]
    ra=direct(encode(a,10),D=1,B=10,T=25,minimum=2)
    rb=direct(encode(b,10),D=1,B=10,T=25,minimum=2)
    assert sum(row[0] for row in a)==sum(row[0] for row in b)==9
    assert ra=={'status':'ok','count':3,'sum':(3,)}
    assert rb=={'status':'ok','count':3,'sum':(1,)}
    assert direct(encode(a,10),D=1,B=10,T=25,minimum=4)=={'status':'abort'}
    all_pass=direct(encode([[0],[0],[4],[5]],10),D=1,B=10,T=25,minimum=4)
    assert all_pass=={'status':'ok','count':4,'sum':(9,)}
    # A small field aliases the norm to 0. The width condition is indispensable.
    assert 10**2+1**2==101 and 101%101==0
    assert direct(encode([[10,1],[0,0]],10),D=2,B=10,T=25,minimum=2)=={'status':'abort'}
    malformed=encode([[0,0],[0,0]],2); malformed[0][0]=2
    assert direct(malformed,D=2,B=2,T=8,minimum=2)=={'status':'input-abort'}
    # Conditional ideal-function property: if both honest inputs are valid and
    # always pass, q-2 corrupt clients do not make one honest disappear.
    honest_valid_cases=0
    for malicious in itertools.product((-10,-5,0,5,10),repeat=2):
        accepted_malicious=[u for u in malicious if u*u<=25]
        for honest in itertools.product(range(-5,6),repeat=2):
            result=direct(encode([[u] for u in (*malicious,*honest)],10),D=1,B=10,T=25,minimum=2)
            assert result=={'status':'ok','count':2+len(accepted_malicious),
                           'sum':(sum(honest)+sum(accepted_malicious),)}
            honest_valid_cases+=1
    return dict(honest_always_pass_functional_cases=honest_valid_cases,
        honest_always_pass_scope='conditional one-round ideal function; no clipping implementation or end-to-end privacy proof',
        exhaustive_direct_wire_cases=exhaustive,masked_vs_direct_cases=matched,
        direct_eliminates_mask_without_changing_filter_output=True,
        selected_sum_leak_persists={'world_a':ra,'world_b':rb,'same_unfiltered_sum':9},
        all_pass_guard_still_has_input_dependent_abort=True,
        field_alias_example={'squared_norm':101,'too_small_P':101,'aliased_norm':0},
        nonboolean_reference_rejected=True)


def compile_comparison(installation):
    workspace=ROOT/'.cache/mpc-candidate-review'/uuid.uuid4().hex
    workspace.mkdir(parents=True)
    # Hold dimensions, cohort, cap, threshold, P and compiler L fixed.
    cfg=dict(dimension=2,clients=4,parties=4,coordinate_cap=2,scale=1,spacing=5,
        mask_max=15,squared_bound=8,minimum_accepted=2,client_port=25000,seed=42,
        backend_prime=2**127-1,hprf=dict(p=101,q=505,m=2,columns=[1,2]))
    results=[]
    for name,source in [('masked',(ROOT/'mpc/Programs/Source/aion_private_bound.mpc').read_text()),
                        ('direct',DIRECT_SOURCE)]:
        work=workspace/name; (work/'Programs/Source').mkdir(parents=True)
        source_path=work/'Programs/Source/review.mpc'; source_path.write_text(source)
        (work/'policy.json').write_text(json.dumps(cfg))
        command=[sys.executable,str(installation/'compile.py'),'-P',str(cfg['backend_prime']),'-F','14','-M','review','policy.json']
        with (work/'compile.log').open('w') as log:
            subprocess.run(command,cwd=work,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
        log=(work/'compile.log').read_text()
        requires={kind:int(count) for count,kind in re.findall(r'^\s*(\d+) (integer triples|integer randoms|integer bits|integer opens|integer simple multiplications|virtual machine rounds)\s*$',log,re.M)}
        assert 'integer triples' in requires
        W=(2*cfg['coordinate_cap']).bit_length() if name=='direct' else (cfg['mask_max']+2*cfg['spacing']*cfg['coordinate_cap']).bit_length()
        input_bits=cfg['clients']*(cfg['dimension']*W+(0 if name=='direct' else (cfg['hprf']['q']-1).bit_length()))
        results.append(dict(candidate=name,compiler_requirements_upper_bounds=requires,
            input_field_elements=input_bits,source_sha256=hashlib.sha256(source_path.read_bytes()).hexdigest(),workspace=str(work)))
    assert results[1]['compiler_requirements_upper_bounds']['integer triples']<results[0]['compiler_requirements_upper_bounds']['integer triples']
    return dict(scope='two coordinates, four clients, same P/L/compiler; compile only, no native execution',
        config=cfg,application_bit_length=14,cases=results)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mp-spdz-dir',type=Path,default=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3')
    args=parser.parse_args()
    result=dict(scope='plaintext functional audits and native compiler estimates; not a cryptographic security proof',
                functional=audits(),compile_only=compile_comparison(args.mp_spdz_dir.resolve()))
    D=61706; B=20000; N=4
    cap=D*B*B; L=max((2*B).bit_length(),1+B.bit_length(),cap.bit_length(),1+(N*B).bit_length(),N.bit_length())+2
    result['full_model_arithmetic']=dict(dimension=D,clients=N,B=B,norm_cap=cap,norm_bits=cap.bit_length(),
        direct_input_bits_per_client=D*(2*B).bit_length(),application_L=L,backend_P=backend_prime_for(L),
        note='range calculation only; no full-model compilation/runtime cost extrapolation')
    result['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream:json.dump(result,stream,indent=2)
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
