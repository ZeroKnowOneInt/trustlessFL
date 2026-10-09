"""Offline integer transmission/MGF/ML/key-space audit. NO runtime integration.

All seed attacks target fresh public fixtures only. Learning uses staged local
FMNIST data and public committed models, not private actor state. The large
parameter grid uses frozen local updates, explicitly NOT closed-loop training;
the S ablation separately retrains selected clients in closed loop.
"""

import argparse
from dataclasses import asdict
from fractions import Fraction
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
import time

import numpy as np

from experiments.audit_aion_hprf_carry import SOURCE, decomposition
from experiments.transmission_numeric import (TransmissionParameters, minimum_period,
    nearest_ratio, quantize, scale_mask, transmission_error_bound, worst_case_fixture)
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.paper_dmc import public_mgf_term, PaperDMC, evolve_bound
from trustlessfl.source_paper_numeric import select_masked, mask_integer_wire, MGFSelectionError


PERCENTILES = [50,90,95,99,99.9,100]


def stats(values):
    array = np.abs(np.asarray(values, dtype=np.float64)).ravel()
    return dict(mean=float(array.mean()), percentiles=dict(zip(
        map(str,PERCENTILES), map(float,np.percentile(array,PERCENTILES)))), max=float(array.max()))


def quantized(values, scale):
    # Float is ONLY at the x -> integer quantization boundary, never masking.
    # Vectorize non-boundaries; decimal-spelling exact arithmetic resolves all
    # near-half cases (including nextafter). Conservative guard exceeds both
    # multiplication and binary<->shortest-decimal rounding uncertainty.
    product=np.asarray(values,dtype=np.float64)*scale
    if not np.isfinite(product).all() or np.max(np.abs(product)) >= 2**62:
        raise ValueError('quantization outside supported int64 range')
    result=np.rint(product).astype(np.int64)
    near=np.abs((product-np.floor(product))-.5) <= 4*np.finfo(float).eps*np.maximum(1,np.abs(product))
    if np.any(near):
        result[near]=quantize(np.asarray(values)[near],scale)
    return result


def scale_rows(masks, p, period):
    return [[scale_mask(int(h), p=p, period=period) for h in row] for row in masks]


def numeric_sweep(hprf):
    rng = random.Random(20261008)
    rows, cache = [], {}
    for n,s,c in itertools.product([2,20,100], [10**4,10**5,10**6], ['0.0001','0.001','0.01','100']):
        if n not in cache:
            keys = [rng.randint(1,100000) for _ in range(n)]
            cache[n] = (keys,[hprf.hprf(k,4,16) for k in keys],hprf.hprf(sum(keys),4,16))
        keys,masks,aggregate = cache[n]
        small_error = transmission_error_bound(n,p=hprf.p,q=hprf.q,period=32000)
        for d in sorted(set([21,24,32,50,100,2*small_error+1])):
            if d <= 2*small_error:
                continue  # Unsafe spacings appear in boundary tests, not normal grid.
            minimum = minimum_period(p=hprf.p,q=hprf.q,n=n,spacing=d,scale=s,real_bound=c)
            for m in sorted(set([32000, minimum['period'], 2*minimum['period']])):
                plan = TransmissionParameters(hprf.p,hprf.q,m,d,s,n,c)
                row = dict(**asdict(plan), integer_bound=plan.bound,error_bound=plan.error,
                    minimum_period=minimum['period'],feasible=plan.feasible,
                    physical_mask_period=m/(d*s), spacing_safe=d>2*plan.error,
                    centered_margin_twice=m-2*(d*n*plan.bound+plan.error))
                if plan.feasible:
                    updates = [[rng.randint(-plan.bound,plan.bound) for _ in range(16)] for _ in keys]
                    # Deliberately exercise positive and negative worst-case sums.
                    for z in updates:
                        z[0],z[1] = plan.bound,-plan.bound
                    scaled = scale_rows(masks,hprf.p,m)
                    wire = [[d*z+h for z,h in zip(u,hs,strict=True)]
                            for u,hs in zip(updates,scaled,strict=True)]
                    total = [sum(v[j] for v in wire) for j in range(16)]
                    expected = [sum(v[j] for v in updates) for j in range(16)]
                    recovered = plan.recover(total,aggregate,n)
                    assert recovered == expected
                    stepwise = [0]*16
                    for vector in wire:
                        stepwise = [(a+b)%m for a,b in zip(stepwise,vector,strict=True)]
                    assert stepwise == [v%m for v in total]
                    observed = []
                    for j in range(16):
                        _,_,e,difference = decomposition(hprf,keys,4,masks,aggregate,j)
                        carry = (difference-e)//hprf.p
                        observed.append(sum(v[j] for v in scaled)-scale_mask(
                            aggregate[j],p=hprf.p,period=m)-carry*m)
                    assert max(map(abs,observed)) <= plan.error
                    row.update(exact_match=True, verified_coordinates=16,
                               observed_error_max=max(map(abs,observed)))
                rows.append(row)
    return rows


def float_boundary_examples(hprf):
    examples=[]
    for m in [32000,10**8,10**12]:
        for j in range(min(m,3000)):
            # Adjacent integers bracketing a half boundary, without float search.
            threshold=(2*j+1)*hprf.p//(2*m)
            for h in (threshold,threshold+1):
                exact=scale_mask(h,p=hprf.p,period=m)
                naive=round(m*h/hprf.p)
                if naive != exact:
                    examples.append(dict(period=m,h=h,integer=exact,float=naive,
                        exact_ratio=str(Fraction(m*h,hprf.p))))
                    break
            if examples and examples[-1]['period']==m:
                break
    return examples


def evaluate_split(offset,reference,images,labels):
    from trustlessfl.fmnist import evaluate
    return dict(validation=evaluate(offset,reference,images[:1000],labels[:1000])['accuracy'],
                test=evaluate(offset,reference,images[1000:],labels[1000:])['accuracy'])


def collect_workload(run, output, *, reuse=None):
    import torch
    from trustlessfl.fmnist import FmnistTrainer, reference_vector, shard
    torch.set_num_threads(1)
    manifest=json.loads((run/'manifest.json').read_text())
    history=json.loads((run/'results.json').read_text())['history']
    inputs=Path(manifest['training']['input_root'])
    training=manifest['training']
    for name,sha in training['input_sha256'].items():
        if hashlib.sha256((inputs/name).read_bytes()).hexdigest()!=sha:
            raise ValueError('staged training data hash differs')
    reference=reference_vector(inputs/'reference.npz')
    images,labels=shard(inputs/'test.npz')
    snapshots=[]
    previous=np.zeros(len(reference))
    if reuse is not None:
        with np.load(reuse,allow_pickle=False) as data:
            snapshots=[data['updates'][r] for r in range(len(history))]
            malicious=data['malicious']
    else:
        for r,entry in enumerate(history,1):
            print(f'collect FMNIST r{r}, 20 client updates',flush=True)
            snapshots.append(np.stack([FmnistTrainer(inputs/f'client-{i}.npz',inputs/'reference.npz',
                seed=training['seed'],epochs=training['epochs'],sampling_policy='author-loader')(
                previous,i,manifest['learning_rate'],r) for i in manifest['clients']]))
            previous=np.asarray(entry['model'])
        print('collect existing artifact-style MR attack: 4 clients, 120 steps, boost 20',flush=True)
        previous=np.asarray(history[-2]['model'])
        attack=dict(rounds=[4],clean_path=str(inputs/'attack-clean.npz'),
                    poison_path=str(inputs/'attack-poison.npz'),steps=training['attack_steps'],
                    boost=training['attack_boost'],poison_batch=training['poison_batch'])
        malicious=np.stack([FmnistTrainer(inputs/f'client-{i}.npz',inputs/'reference.npz',
            seed=training['seed'],epochs=training['epochs'],sampling_policy='author-loader',attack=attack)(
            previous,i,manifest['learning_rate'],4) for i in range(4)])
        with (output/'workload.npz').open('xb') as stream:
            np.savez_compressed(stream,updates=np.stack(snapshots),malicious=malicious)
    return manifest,history,inputs,reference,images,labels,snapshots,malicious


def distribution_audit(manifest,history,snapshots):
    rows=[]
    for r,(entry,updates) in enumerate(zip(history,snapshots,strict=True),1):
        selected=entry['selected']
        u=quantized(updates,10**6)
        total=u[selected].sum(axis=0)
        coefficient=Fraction(entry['paper_numeric']['scale']['coefficient'])
        # p from current supplied setup; exact Fraction retained in report.
        p=14760426300877770769
        m=coefficient*p
        rows.append(dict(round=r,selected_count=len(selected),S=10**6,d=100,M=str(m),
            client_abs=stats(updates),client_quanta_abs=stats(u),selected_sum_quanta_abs=stats(total),
            max_spacing_sum_abs=100*int(np.max(np.abs(total))),half_period=str(m/2),
            observed_spacing_sum_fits=200*int(np.max(np.abs(total)))<m))
    return rows


def synthetic_distribution_audit(run,hprf):
    from trustlessfl.task import local_delta
    from experiments.audit_modular_mgf_recovery import synthetic_fixture
    manifest=json.loads((run/'manifest.json').read_text())
    failure=json.loads((run/'failure.json').read_text())
    previous=np.zeros(manifest['dimension']);rows=[]
    for entry in failure['completed_rounds']:
        r=entry['round']
        updates=np.stack([local_delta(previous,i,manifest['learning_rate']) for i in manifest['clients']])
        u=quantized(updates,10**6);members=entry['selected'];total=u[members].sum(axis=0)
        assert Fraction(entry['paper_numeric']['next_linf'])==Fraction(int(np.max(np.abs(total))),10**6)
        m=Fraction(entry['paper_numeric']['scale']['coefficient'])*hprf.p
        rows.append(dict(round=r,selected_count=len(members),selected=members,S=10**6,d=100,M=str(m),
            client_abs=stats(updates),client_quanta_abs=stats(u),selected_sum_quanta_abs=stats(total),
            max_spacing_sum_abs=100*int(np.max(np.abs(total))),half_period=str(m/2),
            observed_spacing_sum_fits=200*int(np.max(np.abs(total)))<m))
        previous+=total/(10**6*len(members))
    updates=np.stack([local_delta(previous,i,manifest['learning_rate']) for i in manifest['clients']])
    fixture=synthetic_fixture(archived_run=run)
    return dict(scope='replayed actual first 3 committed rosters; original r4 private selected masks unavailable',
        committed_rounds=rows,round4_all_client_abs=stats(updates),
        round4_all_client_quanta_abs=stats(quantized(updates,10**6)),
        round4_minimal_ambiguity_fixture=fixture)


def detection_baseline(hprf,manifest,history,snapshots,malicious,keys):
    """Matched original adaptive scaling replay plus pinned-r4-bound control.

    Oracle sums are OFFLINE ML labels, not a working runtime carry decoder.
    Source MGF predicate/history/representation are unchanged.
    """
    projection=slice(*manifest['paper_numerics']['projection']);width=projection.stop-projection.start
    local_manifest=dict(manifest,dimension=width,
        paper_numerics=dict(manifest['paper_numerics'],projection=[0,width]))
    state={};previous=None;rounds=[]
    for r,updates in enumerate(snapshots,1):
        codec=PaperDMC(20,6,hprf.p).with_mgf(
            manifest['paper_numerics']['initial_linf'] if previous is None else previous,
            beta=manifest['paper_numerics']['beta'],hmax_domain='normalized')
        u=quantized(updates,10**6)
        masks=[hprf.hprf(k,r,projection.stop)[projection] for k in keys]
        wires=[mask_integer_wire(codec,row[projection].tolist(),h) for row,h in zip(u,masks,strict=True)]
        vectors=[dict(sender=i,masked_vector=v) for i,v in enumerate(wires)]
        try:
            selected=select_masked(local_manifest,state,codec,vectors,r)
            members=selected['selected'];bound=Fraction(selected['bound_decimal'])
            status='success'
        except MGFSelectionError:
            members=[];status='insufficient-valid'
            bound=evolve_bound(state['paper_bound'],older_term=state['paper_terms'][0],
                               newer_term=state['paper_terms'][1])
        row=dict(round=r,status=status,selected=members,coefficient=str(codec.coefficient),
            period=str(codec.period*codec.denominator),bound=float(bound),benign=confusion(members,[],20))
        if r==4:
            attacked=[v[:] for v in wires]
            attack_u=quantized(malicious,10**6)
            for i in range(4):
                attacked[i]=mask_integer_wire(codec,attack_u[i][projection].tolist(),masks[i])
            accepted=[i for i,v in enumerate(attacked)
                      if Fraction(sum(x*x for x in v),codec.denominator**2)<=bound**2]
            row['attack']=confusion(accepted,range(4),20)
            row['attack_selected']=accepted
            # Second control uses actual archived r4 scale and committed bound.
            pinned=PaperDMC(20,6,hprf.p,Fraction(history[-1]['paper_numeric']['scale']['coefficient']))
            pinned_wires=[mask_integer_wire(pinned,v[projection].tolist(),h) for v,h in zip(u,masks,strict=True)]
            for i in range(4):
                pinned_wires[i]=mask_integer_wire(pinned,attack_u[i][projection].tolist(),masks[i])
            pinned_bound=Fraction(history[-1]['paper_numeric']['bound'])
            pinned_accepted=[i for i,v in enumerate(pinned_wires)
                if Fraction(sum(x*x for x in v),pinned.denominator**2)<=pinned_bound**2]
            row['archived_bound_control']=dict(period=str(pinned.period*pinned.denominator),
                bound=float(pinned_bound),attack=confusion(pinned_accepted,range(4),20))
        rounds.append(row)
        if members:
            total=u[members].sum(axis=0)
            previous=Fraction(int(np.max(np.abs(total[projection]))),10**6)
            mask_sum=[sum(wires[i][j]-100*int(u[i,projection.start+j]) for i in members) for j in range(width)]
            term=public_mgf_term([Fraction(int(v),10**6) for v in total[projection]],
                [0]*width,codec)+Fraction(max(mask_sum),codec.denominator)
            terms=state.get('paper_terms',[])+[str(term)]
            state=dict(paper_bound=str(bound),paper_terms=terms[-2:])
    return dict(scope='original adaptive scaling, frozen updates/public keys, offline oracle history only',rounds=rounds)


def quantization_training(manifest,history,inputs,reference,images,labels):
    from trustlessfl.fmnist import FmnistTrainer
    modes=['float',10**4,10**5,10**6]
    models={s:np.zeros(len(reference)) for s in modes}
    curves={str(s):[] for s in modes}
    for r,entry in enumerate(history,1):
        print(f'closed-loop fixed-roster quantization ablation r{r}',flush=True)
        for s in modes:
            updates=np.stack([FmnistTrainer(inputs/f'client-{i}.npz',inputs/'reference.npz',
                seed=manifest['training']['seed'],epochs=manifest['training']['epochs'],
                sampling_policy='author-loader')(models[s],i,manifest['learning_rate'],r)
                for i in entry['selected']])
            if s=='float':
                models[s]+=updates.mean(axis=0)
                error=None
            else:
                encoded=quantized(updates,s)
                rounded=encoded/s
                error=stats(rounded-updates)
                models[s]+=encoded.sum(axis=0)/(s*len(updates))
            accuracy=evaluate_split(models[s],reference,images,labels)
            deviation=stats(models[s]-models['float'])
            curves[str(s)].append(dict(round=r,selected=entry['selected'],
                quantization_error=error,global_model_deviation=deviation,accuracy=accuracy,
                accuracy_difference={k:accuracy[k]-curves['float'][-1]['accuracy'][k]
                    for k in accuracy} if s!='float' else dict(validation=0,test=0)))
    return dict(scope='closed-loop retraining, archived fixed roster, no MGF reselection',
                validation_rows=1000,test_rows=len(labels)-1000,curves=curves)


def confusion(selected,malicious_ids,count):
    accepted=set(selected); bad=set(malicious_ids); good=set(range(count))-bad
    tp,fn=len(bad-accepted),len(bad&accepted)
    fp,tn=len(good-accepted),len(good&accepted)
    return dict(TP=tp,FP=fp,FN=fn,TN=tn,
        true_positive_rate=tp/len(bad) if bad else None,
        false_negative_rate=fn/len(bad) if bad else None,
        false_positive_rate=fp/len(good),true_negative_rate=tn/len(good),
        attack_detection_rate=tp/len(bad) if bad else None,benign_rejection_rate=fp/len(good))


def mask_statistics(masks,plan):
    scaled=np.asarray(scale_rows(masks,plan.p,plan.period),dtype=np.float64)/(plan.spacing*plan.scale)
    squares=np.sum(scaled**2,axis=1)
    physical=plan.period/(plan.spacing*plan.scale)
    dimension=scaled.shape[1]
    return dict(representation='uncentered [0,M] including rounded endpoint; physical / (d*S)',
        dimension=dimension,mean_coordinate=float(scaled.mean()),std_coordinate=float(scaled.std()),
        mean_l2=float(np.sqrt(squares).mean()),mean_l2_squared=float(squares.mean()),
        std_l2_squared=float(squares.std()),uniform_theory_mean_coordinate=physical/2,
        uniform_theory_std_coordinate=physical/math.sqrt(12),
        uniform_theory_mean_l2_squared=dimension*physical**2/3,
        uniform_theory_std_l2_squared=math.sqrt(4*dimension/45)*physical**2,
        caveat='iid uniform continuous benchmark only; original scalar masks are correlated')


def detection_sweep(hprf,rows,manifest,history,snapshots,malicious,reference,images,labels):
    projection=slice(*manifest['paper_numerics']['projection'])
    width=projection.stop-projection.start
    rng=random.Random(20261008)
    keys=[rng.randint(1,100000) for _ in range(20)]
    masks=[[hprf.hprf(k,r,projection.stop)[projection] for k in keys] for r in range(1,5)]
    results=[]; evaluation_cache={}; update_cache={}; attack_cache={}
    full_mask_cache={}; aggregate_cache={}
    # n_max is a selected-count envelope, NOT the bootstrap candidate count.
    # Every feasible row is assessed against the SAME 20-candidate workload.
    # A selection larger than n_max is an operational failure, never capped.
    configs=[row for row in rows if row['feasible']]
    manifest_small=dict(manifest,dimension=width,
        paper_numerics=dict(manifest['paper_numerics'],projection=[0,width]))
    for index,row in enumerate(configs):
        if index%20==0:
            print(f'MGF frozen-update parameter {index+1}/{len(configs)}',flush=True)
        plan=TransmissionParameters(**{k:row[k] for k in asdict(TransmissionParameters(
            hprf.p,hprf.q,32000,100,10**6,20,'100'))})
        c=float(plan.real_bound)
        # Offline parameter change is explicit: physical Y = u/S + m/(d*S).
        # Same vector/scale for detection and arithmetic, no MGF predicate change.
        codec=PaperDMC(20,6,hprf.p,Fraction(plan.period*10**8,plan.spacing*plan.scale*hprf.p))
        states={}; model=np.zeros(len(reference)); rounds=[]
        for r,updates in enumerate(snapshots,1):
            cache_key=(r,plan.scale,c)
            if cache_key not in update_cache:
                update_cache[cache_key]=quantized(np.clip(updates,-c,c),plan.scale)
            u=update_cache[cache_key]
            scaled=scale_rows(masks[r-1],hprf.p,plan.period)
            wires=[[plan.spacing*int(z)+m for z,m in zip(us[projection],hs,strict=True)]
                   for us,hs in zip(u,scaled,strict=True)]
            # Convert only exact ratios for existing predicate's wire units.
            # Since L=1e8 may not be divisible by d*S, use a common integer
            # multiplier to preserve EXACT squared-norm/bound comparisons.
            common=math.lcm(codec.denominator,plan.spacing*plan.scale)
            mgf_codec=PaperDMC(20,6,hprf.p,Fraction(plan.period*common,plan.spacing*plan.scale*hprf.p))
            # select_masked divides by codec.denominator. Supply exact common
            # physical representation through a tiny denominator-only adapter.
            class NormCodec:
                denominator=common
                clients=20
                decimals=6
                coefficient=mgf_codec.coefficient
                modulus=hprf.p
            norm_codec=NormCodec()
            multiplier=common//(plan.spacing*plan.scale)
            vectors=[dict(sender=i,masked_vector=[v*multiplier for v in wire])
                     for i,wire in enumerate(wires)]
            # public_mgf_term needs residual validation during bootstrap.
            norm_codec.residual=mgf_codec.residual
            failed=False
            try:
                selection=select_masked(manifest_small,states,norm_codec,vectors,r)
            except MGFSelectionError:
                bound=evolve_bound(states['paper_bound'],older_term=states['paper_terms'][0],
                                   newer_term=states['paper_terms'][1])
                selection=dict(selected=[],bound_decimal=str(bound))
                failed=True
            members=selection['selected']; bound=Fraction(selection['bound_decimal'])
            oversized=len(members)>plan.max_clients
            can_recover=bool(members) and not oversized
            if can_recover:
                total=u[members].sum(axis=0)
                for i in members:
                    if (r,i) not in full_mask_cache:
                        full_mask_cache[r,i]=hprf.hprf(keys[i],r,len(reference))
                aggregate_key=(r,tuple(sorted(members)))
                if aggregate_key not in aggregate_cache:
                    aggregate_cache[aggregate_key]=hprf.hprf(sum(keys[i] for i in members),r,len(reference))
                # Full SINGLE vector Y, not an auxiliary aggregation encoding.
                full_total=[sum(plan.spacing*int(u[i,j])+scale_mask(full_mask_cache[r,i][j],
                    p=hprf.p,period=plan.period) for i in members) for j in range(len(reference))]
                assert full_total[projection] == [sum(wires[i][j] for i in members) for j in range(width)]
                recovered=plan.recover(full_total,aggregate_cache[aggregate_key],len(members))
                assert recovered == total.tolist()
                model+=np.asarray(recovered)/(plan.scale*len(members))
                mask_total=[sum(scaled[i][j] for i in members) for j in range(width)]
                term=public_mgf_term([Fraction(int(z),plan.scale) for z in total[projection]],
                    [0]*width,codec)+Fraction(max(mask_total),plan.spacing*plan.scale)
                terms=states.get('paper_terms',[])+[str(term)]
                states=dict(paper_bound=str(bound),paper_terms=terms[-2:])
            scores=[math.sqrt(sum(v*v for v in wire))/(plan.spacing*plan.scale) for wire in wires]
            predicate_members=[i for i,wire in enumerate(wires) if Fraction(
                sum(v*v for v in wire),(plan.spacing*plan.scale)**2)<=bound**2] if r==4 else members
            info=dict(round=r,status=('insufficient-valid' if failed else
                'selected-count-exceeds-envelope' if oversized else 'success'),
                selected=members,predicate_selected=predicate_members,bound=float(bound),
                benign=confusion(predicate_members,[],20),scores=scores,
                clipping_fraction=float(np.mean(np.abs(updates)>c)),
                exact_modular_model_coordinates=len(reference) if can_recover else 0,
                plaintext_sum_exact_match=True if can_recover else None)
            if r==4:
                attacked=[wire[:] for wire in wires]
                # Existing attack strength is retained, not clipped to force
                # correctness for malicious inputs (outside the recovery proof).
                if plan.scale not in attack_cache:
                    attack_cache[plan.scale]=quantized(malicious,plan.scale)
                attack_u=attack_cache[plan.scale]
                for i in range(4):
                    attacked[i]=[plan.spacing*int(z)+m for z,m in zip(
                        attack_u[i][projection],scaled[i],strict=True)]
                attacked_scores=[math.sqrt(sum(v*v for v in wire))/(plan.spacing*plan.scale)
                                 for wire in attacked]
                accepted=[i for i,wire in enumerate(attacked) if Fraction(
                    sum(v*v for v in wire),(plan.spacing*plan.scale)**2)<=bound**2]
                sensitivity=[]
                for factor in [0.5,0.75,1,1.25,1.5,2]:
                    cutoff=bound*Fraction(str(factor))
                    chosen=[i for i,wire in enumerate(attacked) if Fraction(
                        sum(v*v for v in wire),(plan.spacing*plan.scale)**2)<=cutoff**2]
                    sensitivity.append(dict(threshold_factor=factor,**confusion(chosen,range(4),20)))
                info.update(attack=confusion(accepted,range(4),20),attack_selected=accepted,
                    benign_score_distribution=stats(attacked_scores[4:]),
                    malicious_score_distribution=stats(attacked_scores[:4]),
                    attack_scores=attacked_scores,threshold_sensitivity=sensitivity,
                    attack_projection_abs=stats(malicious[:,projection]))
            # Frozen replay accuracy, cached by full model, not by parameters.
            signature=hashlib.sha256(model.tobytes()).hexdigest()
            if signature not in evaluation_cache:
                evaluation_cache[signature]=evaluate_split(model,reference,images,labels)
            info['frozen_replay_accuracy']=evaluation_cache[signature]
            rounds.append(info)
        results.append(dict(parameter_index=rows.index(row),parameters=asdict(plan),
            physical_mask_period=plan.period/(plan.spacing*plan.scale),rounds=rounds,
            mask_statistics=dict(mask_statistics(masks[-1],plan),model_dimension=len(reference))))
    return dict(scope='frozen-update replay, SAME integer Y for MGF/SUM, unchanged predicate/bootstrap/history',
        attack='repository artifact-style-MR, four attackers only at r4; unclipped malicious updates',
        public_fixture_keys=keys,results=results,unique_model_evaluations=len(evaluation_cache),
        candidate_clients=20,selected_count_envelopes=[2,20,100],
        baseline=detection_baseline(hprf,manifest,history,snapshots,malicious,keys),
        accuracy_scope='frozen local updates from archived public model trajectory, NOT independent closed-loop convergence')


def key_space_audit(hprf):
    started=time.monotonic();rows=[]
    for period,d,s,bound in [(32000,100,10**6,'100'),(8441,21,10**4,'0.001')]:
        for r,key in itertools.product([1,4],[4,16,31337,64221,99999]):
            updates=[nearest_ratio((Fraction(i-4,10000)*s).numerator,
                                   (Fraction(i-4,10000)*s).denominator) for i in range(8)]
            hs=hprf.hprf(key,r,8)
            wire=[d*u+scale_mask(h,p=hprf.p,period=period) for u,h in zip(updates,hs,strict=True)]
            c=nearest_ratio((Fraction(bound)*s).numerator,(Fraction(bound)*s).denominator)
            bound_survivors=0;grid_survivors=[]
            for candidate in range(1,100001):
                possible=True;grid=True
                for j,y in enumerate(wire):
                    t=((candidate*r)%hprf.q)*hprf.column_sums[j]%hprf.q
                    h=(t*hprf.p+hprf.q//2)//hprf.q
                    residual=y-scale_mask(h,p=hprf.p,period=period)
                    if abs(residual)>d*c:
                        possible=False;break
                    if residual%d:
                        grid=False
                if possible:
                    bound_survivors+=1
                    if grid:
                        grid_survivors.append(candidate)
            assert key in grid_survivors
            # Reconstruct ONLY with the surviving candidate; true seed is used
            # to grade the public-fixture attack, never as its recovery oracle.
            recovered=None
            if len(grid_survivors)==1:
                candidate_masks=hprf.hprf(grid_survivors[0],r,8)
                recovered=[(y-scale_mask(h,p=hprf.p,period=period))//d
                           for y,h in zip(wire,candidate_masks,strict=True)]
            rows.append(dict(period=period,d=d,S=s,C_real=bound,round=r,true_public_seed=key,
                tested_seeds=100000,bound_only_survivors=bound_survivors,
                quantization_and_bound_survivors=len(grid_survivors),
                surviving_public_fixture_seeds=grid_survivors,
                unique_true_key=len(grid_survivors)==1,plaintext_quanta_exact=recovered==updates,
                recovered_quanta=recovered))
    return dict(scope='local public fixtures ONLY, no private node secrets, no external targets',
        entropy_bits=math.log2(100000),scalar=True,rng='random.SystemRandom (OS CSPRNG)',
        range=[1,100000],round_reuse=True,rows=rows,
        unique_fraction=sum(row['unique_true_key'] for row in rows)/len(rows),
        runtime_seconds=time.monotonic()-started)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,default=Path('.cache/same-scale-fmnist-official-20261008'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--reuse-workload',type=Path)
    parser.add_argument('--synthetic-run',type=Path,default=Path('.cache/same-scale-synthetic-official-20261008'))
    args=parser.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    started=time.monotonic();hprf=OriginalAionHPRF.from_directory(SOURCE)
    print('numeric parameter sweep',flush=True)
    rows=numeric_sweep(hprf)
    data=dict(scope='offline audit, NO Flower runtime changes',parameters=rows,
        source_sha256={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()
                       for name in ('initialization_values','matrix')},
        float_boundary_examples=float_boundary_examples(hprf),
        worst_case={k:v for k,v in worst_case_fixture(p=hprf.p,period=32000).items() if k!='hs'})
    manifest,history,inputs,reference,images,labels,snapshots,malicious=collect_workload(
        args.run,args.output,reuse=args.reuse_workload)
    data['fmnist_distributions']=distribution_audit(manifest,history,snapshots)
    data['synthetic_distributions']=synthetic_distribution_audit(args.synthetic_run,hprf)
    data['quantization_training']=quantization_training(manifest,history,inputs,reference,images,labels)
    data['mgf']=detection_sweep(hprf,rows,manifest,history,snapshots,malicious,reference,images,labels)
    print('exhaustive local key-space audit',flush=True)
    data['key_space']=key_space_audit(hprf)
    data['runtime_seconds']=time.monotonic()-started
    data['conclusion']='F'
    data['runtime_integrated']=False
    if args.reuse_workload is not None:
        data['reused_workload_sha256']=hashlib.sha256(args.reuse_workload.read_bytes()).hexdigest()
    with (args.output/'report.json').open('x') as stream:
        json.dump(data,stream,indent=2)
    print(json.dumps(dict(output=str(args.output),parameter_rows=len(rows),
        feasible=sum(r['feasible'] for r in rows),runtime_seconds=data['runtime_seconds']),indent=2),flush=True)


if __name__=='__main__':
    main()
