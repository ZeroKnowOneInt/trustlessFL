"""Read-only-runtime, local-fixture full-domain compatibility and cost audit.

No secret production state is loaded. Keys in the report are PUBLIC test
fixtures. Deterministic fixtures allow reproduction; the separate sampler
uses OS CSPRNG, and is not connected to Flower. No HPRF parameters change.
"""

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import random
import sys
import time
import tracemalloc

import numpy as np

from experiments.full_domain_keys import sample_full_domain, validate_sum_capacity
from experiments.transmission_numeric import (TransmissionParameters, minimum_period,
    scale_mask, transmission_error_bound)
from experiments.audit_split_wire_amr import inverse_scalar_outputs
from experiments.audit_transmission_parameters import key_space_audit, quantized
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.aion_source_sharing import (MODE, THRESHOLD_RULE, share_seed,
    receive_seed, sum_keys, recover_key_opening, open_share)
from trustlessfl.crypto import (ORDER, Identity, ProtocolError, canonical,
    pedersen_split, pedersen_verify_share, pedersen_reconstruct_pair,
    sum_pedersen_shares, aggregate_commitments)
from trustlessfl.modular_recovery import center_p, hprf_error_bound

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT.parent / 'Aion/agent/Aion/HPRF'


def stats(values):
    a = np.asarray(values, dtype=float)
    return dict(count=len(a), mean=float(a.mean()), median=float(np.median(a)),
        p95=float(np.percentile(a, 95)), p99=float(np.percentile(a, 99)),
        std=float(a.std()), minimum=float(a.min()), maximum=float(a.max()))


def timed(fn):
    start = time.perf_counter_ns()
    result = fn()
    return result, (time.perf_counter_ns()-start)/1e6


def boundary_keys(q):
    # +1 neighbors deliberately exercise float64's non-exact range too.
    return [0, 1, 100000, 2**32, 2**53, 2**53+1, 2**63-1, q//2, q-2, q-1]


def author_reference(hprf):
    spec = importlib.util.spec_from_file_location('full_domain_author_fixture', SOURCE/'hprf.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.HPRF(hprf.n, hprf.m, hprf.p, hprf.q, str(SOURCE/'matrix'))


def boundary_audit(hprf):
    from flwr.app import ConfigRecord
    from flwr.common.serde import config_record_to_proto, config_record_from_proto
    reference = author_reference(hprf)
    rows = []
    for key in boundary_keys(hprf.q):
        mask = hprf.hprf(key, 4, 1025)
        assert mask == reference.hprf(key, 4, 1025)
        assert mask == hprf.hprf(key+hprf.q, 4, 1025)
        pairs, commits = pedersen_split(key, 2, 4)
        verified = all(pedersen_verify_share(i, v, commits) for i, v in pairs.items())
        recovered, _ = pedersen_reconstruct_pair(dict(list(pairs.items())[:2]), commits)
        assert verified and recovered == key
        payload = canonical(dict(mask_seed=key, shares=pairs, commitments=commits))
        proto = config_record_to_proto(ConfigRecord({'snapshot': payload}))
        encoded = proto.SerializeToString()
        restored = config_record_from_proto(type(proto).FromString(encoded))['snapshot']
        assert restored == payload and json.loads(restored)['mask_seed'] == key
        try:
            reference.G(key)
            legacy_g = 'ok'
        except (OverflowError, ValueError) as exc:
            legacy_g = type(exc).__name__
        try:
            proto_key = config_record_to_proto(ConfigRecord({'key': key}))
            direct_ok = config_record_from_proto(type(proto_key).FromString(
                proto_key.SerializeToString()))['key'] == key
            direct = 'exact' if direct_ok else 'inexact'
        except (OverflowError, ValueError) as exc:
            direct = type(exc).__name__
        rows.append(dict(key=key, key_bits=key.bit_length(), hprf_author_equal=True,
            q_periodic=True, all_zero_mask=not any(mask), vss_verified=verified,
            vss_roundtrip=recovered == key, python_json_and_flower_bytes_exact=True,
            flower_bytes_payload=len(encoded), json_key_bytes=len(canonical(key)),
            float_roundtrip_exact=int(float(key)) == key,
            int64_fits=key <= 2**63-1, uint64_fits=key <= 2**64-1,
            direct_flower_integer=direct, author_G_int64_path=legacy_g))
    return rows


def transport_audit(hprf, keys):
    """Exercise unchanged encrypted sharing and its unchanged rejection guard.

    The primitive reconstruction below is separately labelled, NOT passed off
    as success of recover_key_opening or of a production Flower round.
    """
    count = len(keys)
    validate_sum_capacity(hprf.q, count, ORDER)
    committee = list(range(4)); aggregator = max(count, 4)
    identities = {i: Identity.generate(str(i)) for i in range(aggregator+1)}
    manifest = dict(task='public-full-domain-local-fixture', clients=list(range(aggregator)),
        committee=committee, aggregator=aggregator, prime=ORDER,
        sharing_profile=dict(kind=MODE, threshold_rule=THRESHOLD_RULE, threshold=2),
        source_transport_registry={str(i): identity.public() for i, identity in identities.items()})
    states = {i: {} for i in committee}
    packets = []
    start = time.perf_counter()
    for sender, key in enumerate(keys):
        for event in share_seed(manifest, identities[sender], key):
            # Same JSON-byte relay boundary, and recipient AEAD/signature/VSS.
            event = json.loads(canonical(event)); packets.append(event)
            receive_seed(manifest, identities[event['recipient']], states[event['recipient']], event['body'])
    sharing_ms = 1000*(time.perf_counter()-start)
    members = list(range(count))
    entries = [dict(sender=i, **sum_keys(manifest, identities[i], states[i]['shares'], members, 4))
               for i in committee]
    entries = json.loads(canonical(entries))
    opened = {}
    for entry in entries:
        body = entry['sealed_sum']
        opened[body['index']] = open_share(manifest, identities[aggregator], body,
                                          kind='AGGREGATE_KEY_SHARE', round_id=4)
    key_sum, blind = pedersen_reconstruct_pair(dict(list(opened.items())[:2]),
                                              entries[0]['sealed_sum']['commitments'])
    assert key_sum == sum(keys) and key_sum < ORDER
    assert hprf.hprf(key_sum, 4, 1025) == hprf.hprf(key_sum % hprf.q, 4, 1025)
    try:
        runtime = recover_key_opening(manifest, identities[aggregator], entries, members, 4)
        assert runtime == dict(key=key_sum, blind=blind)
        status = 'accepted'
    except ProtocolError as exc:
        status = str(exc)
    return dict(count=count, integer_key_sum=key_sum, key_sum_mod_q=key_sum % hprf.q,
        exceeds_q=key_sum >= hprf.q, primitive_and_authenticated_transport_exact=True,
        runtime_policy_result=status, enrollment_and_receive_ms=sharing_ms,
        per_recipient_share_packet_bytes=stats([len(canonical(e)) for e in packets]),
        all_enrollment_packets_bytes=sum(len(canonical(e)) for e in packets),
        aggregate_share_packets_bytes=len(canonical(entries)))


def key_groups(q, repetitions, rng):
    return dict(small=[rng.randint(1,100000) for _ in range(repetitions)],
        bits32=[rng.randrange(2**31,2**32) for _ in range(repetitions)],
        bits48=[rng.randrange(2**47,2**48) for _ in range(repetitions)],
        bits53=[rng.randrange(2**52,2**53) for _ in range(repetitions)],
        near_q_half=[q//2+rng.randrange(100000) for _ in range(repetitions)],
        near_q=[q-1-rng.randrange(100000) for _ in range(repetitions)],
        full_uniform=[rng.randrange(q) for _ in range(repetitions)])


def hprf_benchmark(hprf, repetitions):
    rng = random.Random(20261009)
    groups = key_groups(hprf.q, repetitions, rng)
    times = {name: [] for name in groups}
    # Warm matrix and Python code; random interleaving reduces drift bias.
    hprf.hprf(1, 4, 61706)
    tasks = [(name, key) for name, keys in groups.items() for key in keys]
    rng.shuffle(tasks)
    for name, key in tasks:
        _, ms = timed(lambda: hprf.hprf(key, 4, 61706))
        times[name].append(ms)
    rows = {}
    for name, keys in groups.items():
        peaks = []
        for key in keys[:3]:
            tracemalloc.start()
            output = hprf.hprf(key, 4, 61706)
            _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
            peaks.append(peak)
            assert len(output) == 61706 and all(type(v) is int for v in output)
        rows[name] = dict(milliseconds=stats(times[name]),
            peak_python_allocated_bytes=stats(peaks), key_bits=stats([k.bit_length() for k in keys]))
    return dict(dimension=61706, round=4, repeats=repetitions,
        measurement='warmed, randomized interleaving; tracemalloc measured separately; no mobile device',
        results=rows)


def vss_benchmark(hprf, repetitions):
    rng = random.Random(20961009)
    groups = {name: [rng.randint(1,100000) if name=='small' else rng.randrange(hprf.q)
                    for _ in range(20)] for name in ['small','full']}
    fixtures = {}
    for name, keys in groups.items():
        shares = [pedersen_split(k, 2, 4) for k in keys]
        summed = {i: sum_pedersen_shares([pairs[i] for pairs, _ in shares]) for i in range(1,5)}
        commitments = aggregate_commitments([c for _, c in shares])
        fixtures[name] = shares, summed, commitments
    results = {name: {field: [] for field in ['split','verify_four','sum_four_shares_20_clients',
        'aggregate_commitments_20_clients','reconstruct_two_with_verification','json_serialize',
        'share_bundle_bytes']} for name in groups}
    tasks = [(name,i) for name in groups for i in range(repetitions)]; rng.shuffle(tasks)
    for name, i in tasks:
        key = groups[name][i % 20]
        (pairs, commits), ms = timed(lambda: pedersen_split(key, 2, 4))
        results[name]['split'].append(ms)
        valid, ms = timed(lambda: all(pedersen_verify_share(j,v,commits) for j,v in pairs.items()))
        assert valid; results[name]['verify_four'].append(ms)
        shares, summed, aggregate = fixtures[name]
        _, ms = timed(lambda: {j: sum_pedersen_shares([s[j] for s,_ in shares]) for j in range(1,5)})
        results[name]['sum_four_shares_20_clients'].append(ms)
        _, ms = timed(lambda: aggregate_commitments([c for _,c in shares]))
        results[name]['aggregate_commitments_20_clients'].append(ms)
        recovered, ms = timed(lambda: pedersen_reconstruct_pair({1:summed[1],2:summed[2]},aggregate))
        assert recovered[0] == sum(groups[name])
        results[name]['reconstruct_two_with_verification'].append(ms)
        encoded, ms = timed(lambda: canonical(dict(shares=pairs,commitments=commits)))
        results[name]['json_serialize'].append(ms)
        results[name]['share_bundle_bytes'].append(len(encoded))
    return dict(threshold=2, committee=4, selected_clients=20, repeats=repetitions,
        timing_unit='milliseconds except share_bundle_bytes; component microbench, warmed caches',
        results={name:{field:stats(v) for field,v in fields.items()} for name,fields in results.items()})


def distribution_regression(hprf, repeats):
    rng = random.Random(1062026); result = []
    period = 32000
    for name in ['small','full']:
        for count in [2,20,100]:
            errors=[]; transmissions=[]; carries=[]; outputs=[]; mods=Counter(); norms=[]; mgf_masks=[]
            for repetition in range(repeats):
                keys=[rng.randint(1,100000) if name=='small' else rng.randrange(hprf.q) for _ in range(count)]
                for r in [1,4,17,451]:
                    masks=[hprf.hprf(k,r,1025) for k in keys]
                    aggregate=hprf.hprf(sum(keys)%hprf.q,r,1025)
                    assert aggregate == hprf.hprf(sum(keys),r,1025)
                    scaled=[[scale_mask(v,p=hprf.p,period=period) for v in row] for row in masks]
                    for key,row in zip(keys,masks):
                        outputs.extend(v/hprf.p for v in row)
                        mods.update(v%16 for v in row)
                        # Actual FMNIST MGF projection [60856:61696], without
                        # allocating the unused 61k prefix. Same author inputs.
                        block, offset=divmod(60856,hprf.m)
                        projection=hprf.hprf(key,r+block,offset+840)[offset:]
                        if repetition==0 and key==keys[0] and r==1:
                            assert projection==hprf.hprf(key,r,61706)[60856:61696]
                        mgf_scaled=[scale_mask(v,p=hprf.p,period=period) for v in projection]
                        mgf_masks.extend(mgf_scaled)
                        norms.append(sum(v*v for v in mgf_scaled))
                    for j,ha in enumerate(aggregate):
                        diff=sum(row[j] for row in masks)-ha
                        e=center_p(diff,hprf.p); c=(diff-e)//hprf.p
                        wire_e=sum(row[j] for row in scaled)-scale_mask(ha,p=hprf.p,period=period)-c*period
                        assert abs(e)<=hprf_error_bound(count,p=hprf.p,q=hprf.q)
                        assert abs(wire_e)<=transmission_error_bound(count,p=hprf.p,q=hprf.q,period=period)
                        errors.append(e); transmissions.append(wire_e); carries.append(c)
            histogram,_=np.histogram(outputs,bins=np.linspace(0,1,17))
            scaled_histogram,_=np.histogram(mgf_masks,bins=np.linspace(0,period,17))
            result.append(dict(sampling=name,clients=count,repeats=repeats,rounds=[1,4,17,451],
                coordinates=len(errors),error_histogram=dict(sorted(Counter(errors).items())),
                transmission_error_histogram=dict(sorted(Counter(transmissions).items())),
                carry_histogram=dict(sorted(Counter(carries).items())),
                carry_frequency=sum(c!=0 for c in carries)/len(carries),
                normalized_output=stats(outputs),normalized_output_variance=float(np.var(outputs)),
                output_histogram_16_bins=histogram.tolist(),output_mod16=dict(sorted(mods.items())),
                scaled_mask_coordinate=stats(mgf_masks),scaled_mask_variance=float(np.var(mgf_masks)),
                scaled_mask_histogram_16_bins=scaled_histogram.tolist(),mgf_projection=[60856,61696],
                mgf_mask_squared_norm=stats(norms),mgf_mask_norm=stats(np.sqrt(norms)),
                period=period,mgf_dimension=840,mask_representation='uncentered 0..M, inclusive endpoint'))
    return result


def recovery_case(hprf, keys, round_id, updates, plan):
    dimension=updates.shape[1]; count=len(keys)
    validate_sum_capacity(hprf.q,count,ORDER)
    masks=[hprf.hprf(k,round_id,dimension) for k in keys]
    aggregate=hprf.hprf(sum(keys)%hprf.q,round_id,dimension)
    total=[sum(plan.spacing*int(updates[i,j])+scale_mask(masks[i][j],p=hprf.p,
        period=plan.period) for i in range(count)) for j in range(dimension)]
    true=[sum(int(row[j]) for row in updates) for j in range(dimension)]
    recovered=plan.recover(total,aggregate,count)
    assert recovered==true
    maximum=0
    for j in range(dimension):
        residual=center_p(total[j]-scale_mask(aggregate[j],p=hprf.p,period=plan.period),plan.period)
        maximum=max(maximum,abs(residual-plan.spacing*true[j]))
        assert scale_mask(aggregate[j]+hprf.p,p=hprf.p,period=plan.period)==scale_mask(
            aggregate[j],p=hprf.p,period=plan.period)+plan.period
    return dict(parameters=asdict(plan),count=count,round=round_id,exact_coordinates=dimension,
        plaintext_exact=True,max_abs_transmission_error=maximum,
        max_abs_true_sum=max(map(abs,true)),period_translation_exact=True)


def recovery_regression(hprf, workload):
    rng=random.Random(426109); results=[]
    for n in [2,20,100]:
        d=2*transmission_error_bound(n,p=hprf.p,q=hprf.q,period=32000)+1
        minimum=minimum_period(p=hprf.p,q=hprf.q,n=n,spacing=d,scale=10000,real_bound='0.01')
        plan=TransmissionParameters(hprf.p,hprf.q,minimum['period'],d,10000,n,'0.01')
        keys=[rng.randrange(hprf.q) for _ in range(n)]
        for r in [1,4,17,451]:
            updates=np.asarray([[rng.randint(-100,100) for _ in range(1025)] for _ in keys])
            updates[:,0]=100; updates[:,1]=-100
            results.append(dict(workload='bounded synthetic',**recovery_case(hprf,keys,r,updates,plan)))
    with np.load(workload,allow_pickle=False) as data:
        frames=data['updates']
    keys=[rng.randrange(hprf.q) for _ in range(20)]  # one key per fixture client, reused all rounds
    for s in [10000,100000,1000000]:
        # C=.1 exceeds every cached benign coordinate; no clipping or resampling.
        assert np.max(np.abs(frames))<.1
        row=minimum_period(p=hprf.p,q=hprf.q,n=20,spacing=21,scale=s,real_bound='0.1')
        plan=TransmissionParameters(hprf.p,hprf.q,row['period'],21,s,20,'0.1')
        for r,frame in enumerate(frames,1):
            results.append(dict(workload='FMNIST frozen real updates, all20, no MGF selection claim',
                **recovery_case(hprf,keys,r,quantized(frame,s),plan)))
    return dict(results=results,workload_sha256=hashlib.sha256(workload.read_bytes()).hexdigest(),
        caveat='arithmetic replay only: new feasible periods; not old synthetic period fixed; no model retraining')


def output_inversion(hprf):
    rng=random.Random(6662026);rows=[]
    for key in [31337,hprf.q//2+12345,hprf.q-1234567]+[rng.randrange(hprf.q) for _ in range(30)]:
        outputs=[v%hprf.p for v in hprf.hprf(key,4,32)]
        inverse,ms=timed(lambda:inverse_scalar_outputs(hprf,4,outputs))
        rows.append(dict(public_fixture_key=key,milliseconds=ms,**inverse,
            exact=inverse['candidates']==[key]))
    return dict(rows=rows,raw_output_required=True,
        caveat='NOT a proof of full-domain masked-wire key recovery; shows scalar primitive is not a secure PRF')


def exhaustive_benchmark(hprf):
    # Preserve and repeat the exact previous 20-fixture, 100000-candidate PoC.
    # Small batches per fixture also give individual throughput measurements.
    original=key_space_audit(hprf)
    for row in original['rows']:
        key=row['true_public_seed']; r=row['round'];d=row['d'];m=row['period'];s=row['S']
        updates=[(i-4)*(s//10000) for i in range(8)]
        wire=[d*z+scale_mask(h,p=hprf.p,period=m) for z,h in zip(updates,hprf.hprf(key,r,8))]
        bound=round(float(row['C_real'])*s)
        start=time.perf_counter();survivors=[]
        for candidate in range(1,100001):
            valid=True
            for j,y in enumerate(wire):
                t=(candidate*r%hprf.q)*hprf.column_sums[j]%hprf.q
                h=(t*hprf.p+hprf.q//2)//hprf.q
                residual=y-scale_mask(h,p=hprf.p,period=m)
                if abs(residual)>d*bound or residual%d:
                    valid=False;break
            if valid:survivors.append(candidate)
        seconds=time.perf_counter()-start
        assert survivors==row['surviving_public_fixture_seeds']
        row.update(optimized_seconds=seconds,keys_per_second=100000/seconds,
            linear_full_domain_worst_years=hprf.q/(100000/seconds)/(365.25*86400),
            linear_full_domain_mean_years=(hprf.q+1)/(2*(100000/seconds))/(365.25*86400))
    # Large-operand throughput control, only 100000 PUBLIC candidate keys per
    # fixture. A singleton here is not uniqueness over the full q domain.
    original['large_operand_subset_benchmarks']=[]
    for period,d,s,bound in [(32000,100,1000000,100000000),(8441,21,10000,10)]:
        base=hprf.q//2
        key=base+31337
        updates=[(i-4)*(s//10000) for i in range(8)]
        wire=[d*z+scale_mask(h,p=hprf.p,period=period) for z,h in zip(updates,hprf.hprf(key,4,8))]
        start=time.perf_counter(); survivors=[]
        for candidate in range(base,base+100000):
            valid=True
            for j,y in enumerate(wire):
                t=(candidate*4%hprf.q)*hprf.column_sums[j]%hprf.q
                h=(t*hprf.p+hprf.q//2)//hprf.q
                residual=y-scale_mask(h,p=hprf.p,period=period)
                if abs(residual)>d*bound or residual%d:
                    valid=False;break
            if valid:survivors.append(candidate)
        seconds=time.perf_counter()-start
        assert key in survivors
        original['large_operand_subset_benchmarks'].append(dict(period=period,
            range_start=base,range_stop_exclusive=base+100000,candidate_count=100000,
            true_public_fixture_key=key,subset_survivors=survivors,
            seconds=seconds,keys_per_second=100000/seconds,
            linear_full_domain_worst_years=hprf.q/(100000/seconds)/(365.25*86400),
            caveat='subset count is NOT surviving candidate count for full domain'))
    return original


def audit(output, repetitions, workload):
    start=time.monotonic(); output.mkdir(parents=True,exist_ok=False)
    paths=[*sorted((ROOT/'trustlessfl').glob('*.py')),SOURCE/'hprf.py',SOURCE/'matrix',SOURCE/'initialization_values']
    before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    hprf=OriginalAionHPRF.from_directory(SOURCE)
    report=dict(scope='local public fixtures only; NO production changes, no HPRF/VSS redesign',
        p=hprf.p,q=hprf.q,dimension_parameters=[hprf.n,hprf.m],vss_order_bits=ORDER.bit_length(),
        keyspace=dict(old=100000,new=hprf.q,old_entropy=math.log2(100000),
            new_entropy=math.log2(hprf.q),nonzero_entropy=math.log2(hprf.q-1),
            search_multiplier=hprf.q/100000,additional_candidates=hprf.q-100000),
        environment=dict(python=sys.version,platform=platform.platform(),machine=platform.machine(),
            cpu_model=next((v.split(':',1)[1].strip() for v in Path('/proc/cpuinfo').read_text().splitlines()
                            if v.startswith('model name')),'unknown'),cpu_count=os.cpu_count(),
            mobile_measured=False),production_sha256=before)
    sample=[sample_full_domain(hprf.q) for _ in range(128)]
    report['csprng_sampler']=dict(count=len(sample),all_valid=all(0<=k<hprf.q for k in sample),
        distinct=len(set(sample)),warning='range/smoke test is not a statistical proof of randomness')
    phases=[('boundaries',lambda:boundary_audit(hprf)),
        ('encrypted_transport_small',lambda:transport_audit(hprf,list(range(1,21)))),
        ('encrypted_transport_full',lambda:transport_audit(hprf,boundary_keys(hprf.q)*2)),
        ('hprf_benchmark',lambda:hprf_benchmark(hprf,repetitions)),
        ('vss_benchmark',lambda:vss_benchmark(hprf,repetitions)),
        ('distribution',lambda:distribution_regression(hprf,5)),
        ('recovery',lambda:recovery_regression(hprf,workload)),
        ('small_key_search',lambda:exhaustive_benchmark(hprf)),
        ('raw_output_inversion',lambda:output_inversion(hprf))]
    for name,fn in phases:
        print(name,flush=True);report[name]=fn()
    assert before=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    report.update(production_unchanged=True,wall_seconds=time.monotonic()-start)
    with (output/'report.json').open('xb') as stream:stream.write(canonical(report))
    print(json.dumps(dict(output=str(output/'report.json'),wall_seconds=report['wall_seconds'])),flush=True)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--repetitions',type=int,default=40)
    parser.add_argument('--workload',type=Path,default=ROOT/'.cache/transmission-parameter-audit-20261008-v1/workload.npz')
    args=parser.parse_args()
    if args.repetitions<10:parser.error('at least 10 repetitions required')
    audit(args.output,args.repetitions,args.workload)
