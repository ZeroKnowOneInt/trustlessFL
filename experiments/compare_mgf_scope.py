"""Public FMNIST masked-MGF scope comparison; no privacy/security claim.

Frozen comparison uses identical Y. Closed loops train on their own selected
models with the SAME initial data/RNG/encoding/keys. This is a local numeric
and learning experiment, not a full Flower-network/BFT/ASR replay. The source
runtime functions themselves perform selection, decoding and actual history.
Public seeded fixture keys are intentionally reproducible, not production RNG.
"""

import argparse
import copy
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import platform
import random
import time
import tracemalloc

import numpy as np

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError, canonical, digest
from trustlessfl.modular_recovery import center_p
from trustlessfl.source_profiles import scale_mask, validate_profile
from trustlessfl.source_paper_numeric import (paper_codec, mask_integer_wire, selection_statistics,
    select_masked, recover, history_statistics, scope_span, MGFSelectionError)

ROOT=Path(__file__).resolve().parents[1]
SCOPES=("projection","full-vector")
BASE_PROFILE=dict(recovery="transmission-centered-v1",key_domain="author-full-q",
    period_policy="fixed-integer",history="actual-mask-sum",S=10000,d=21,M=840000021,
    nmax=20,C="100",aggregation="unweighted",rounding="nearest-even")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()


def dump(path,value):
    with Path(path).open("xb") as stream:stream.write(canonical(value))


def norm_text(square,denominator):
    with localcontext() as context:
        context.prec=60
        return str((Decimal(int(square))/Decimal(denominator**2)).sqrt())


def model_hash(model):
    return hashlib.sha256(np.asarray(model,dtype="<f8").tobytes()).hexdigest()


def confusion(accepted,bad,count):
    accepted,bad=set(accepted),set(bad);good=set(range(count))-bad
    return dict(benign_submitted=len(good),benign_accepted=len(good&accepted),
        benign_rejected=len(good-accepted),malicious_submitted=len(bad),
        malicious_accepted=len(bad&accepted),malicious_rejected=len(bad-accepted),
        benign_FPR=len(good-accepted)/len(good) if good else None,
        attack_TPR=len(bad-accepted)/len(bad) if bad else None)


def counterfactual_changes(clean,attacked,bad):
    """Distinguish pre-existing rejection from rejection caused by the update."""
    clean,attacked,bad=set(clean),set(attacked),set(bad)
    return dict(selection_changed=clean!=attacked,
        already_rejected_attacker_ids=sorted(bad-clean),
        newly_rejected_attacker_ids=sorted((clean-attacked)&bad),
        newly_accepted_attacker_ids=sorted((attacked-clean)&bad),
        selection_removed_ids=sorted(clean-attacked),selection_added_ids=sorted(attacked-clean))


def verify_controlled_pair(closed):
    """Only round one must have identical updates; later models can diverge."""
    a,b=(closed[s] for s in SCOPES)
    same={name:a["rounds"][0][name]==b["rounds"][0][name] for name in
          ("parent_model_hash","client_update_set_sha256","masked_Y_sha256")}
    if a["initial_model_hash"]!=b["initial_model_hash"] or not all(same.values()):
        raise ProtocolError("scope comparison does not start from identical model/update/Y")
    return dict(initial_model_equal=True,first_round_equal=same,
        later_rounds="separate selected-model trajectories; NOT identical updates")


def decision(manifest,state,codec,vectors,r):
    scores=selection_statistics(manifest,state,codec,vectors,r)
    try:
        pending=select_masked(manifest,state,codec,vectors,r)
        selected=pending["selected"];failure=None
    except MGFSelectionError as exc:
        if r<=3:raise
        # Eligible set for detector metrics only. No recovery/aggregate below 2.
        selected=[scores["names"][i] for i in scores["order"]
                  if Fraction(scores["squares"][i],codec.denominator**2)<=scores["bound"]**2]
        pending=None;failure=exc.code
    return dict(selected=selected,pending=pending,failure=failure,scores=scores,
                continuation=pending is not None)


def advance(state,meta):
    state.update(paper_bound=meta["bound"],paper_next_linf=meta["next_linf"],
        paper_mgf_scope=meta["mgf_scope"],paper_terms=(state.get("paper_terms",[])+[meta["history_term"]])[-2:])


def recovery_check(manifest,state,codec,hprf,keys,quanta,decision_result,r,context):
    pending=decision_result["pending"]
    if pending is None:
        return None,dict(context=context,scope=manifest["source_profile"]["mgf_scope"],
            round=r,status="not-attempted-insufficient-valid",selected_count=len(decision_result["selected"]))
    selected=pending["selected"];key=sum(keys[i] for i in selected)
    true=[sum(quanta[i][j] for i in selected) for j in range(manifest["dimension"])]
    decoded,meta=recover(manifest,state,codec,hprf,r,pending,key)
    hs=hprf.hprf(key,r,manifest["dimension"])
    residual=[center_p(y-codec.spacing*u-scale_mask(h,hprf.p,codec.transmission_period),
                      codec.transmission_period) for y,u,h in zip(pending["total"],true,hs,strict=True)]
    differences=[a-b for a,b in zip(decoded,true,strict=True)]
    realized=max(abs(codec.spacing*u+e) for u,e in zip(true,residual,strict=True))
    check=dict(context=context,scope=manifest["source_profile"]["mgf_scope"],round=r,status="recovered",
        selected_count=len(selected),plaintext_integer_sum=true,recovered_integer_sum=decoded,
        mismatch_count=sum(x!=0 for x in differences),max_absolute_difference=max(map(abs,differences)),
        realized_residual=residual,residual_max_abs=max(map(abs,residual)),
        residual_bound=codec.error,capacity_margin=str(Fraction(codec.transmission_period,2)-realized),
        raw_Y_sum_sha256=digest(pending["total"]),raw_Y_sum_preserved=True,
        model_mean_denominator=codec.scale*len(selected))
    if check["mismatch_count"] or max(map(abs,residual))>codec.error or Fraction(check["capacity_margin"])<=0:
        raise ProtocolError("public-fixture recovery correctness/capacity failure")
    return (decoded,meta),check


def compare_rows(vectors,decisions,codec):
    rows=[]
    for idx,v in enumerate(vectors):
        row=dict(client=v["sender"])
        for scope,label in zip(SCOPES,("projection","full"),strict=True):
            result=decisions[scope];scores=result["scores"]
            row["norm_"+label]=norm_text(scores["squares"][idx],codec.denominator)
            row["threshold_"+label]=str(scores["bound"])
            row["selected_"+label]=v["sender"] in result["selected"]
            row["predicate_pass_"+label]=Fraction(scores["squares"][idx],codec.denominator**2)<=scores["bound"]**2
        rows.append(row)
    a=set(decisions["projection"]["selected"]);b=set(decisions["full-vector"]["selected"])
    all_ids={v["sender"] for v in vectors}
    return dict(clients=rows,both_accept=sorted(a&b),projection_only=sorted(a-b),
                full_vector_only=sorted(b-a),both_reject=sorted(all_ids-(a|b)))


def outside_fixture():
    # Same predicate-only fixture as independent review §14; not wire-authenticated.
    from trustlessfl.paper_dmc import PaperDMC
    codec=PaperDMC(20,6,101)
    vectors=[dict(sender=i,masked_vector=[0,10**50]) for i in range(20)]
    results={}
    for scope in SCOPES:
        manifest=dict(dimension=2,source_profile={"mgf_scope":scope},
            paper_numerics=dict(projection=[0,1],filter_rule="inclusive-historical-bound-v1"))
        state=dict(paper_bound="1",paper_terms=["1","1"],paper_mgf_scope=scope)
        result=decision(manifest,state,codec,vectors,4)
        results[scope]=dict(selected=result["selected"],round_continuation=result["continuation"],
            norm=norm_text(result["scores"]["squares"][0],codec.denominator),threshold="1",
            failure=result["failure"])
    return dict(scope="predicate-only, outside declared input bounds; NOT signed protocol attack success",
                raw_Y_sha256=digest(vectors),results=results)


def frozen_compare(manifests,hprf,keys,updates,malicious,checks):
    states={scope:{} for scope in SCOPES};rounds=[];last_bundle=None
    for r,update in enumerate(updates,1):
        print(f"frozen identical Y r{r}",flush=True)
        codecs={s:paper_codec(manifests[s],hprf,r,states[s].get("paper_next_linf")) for s in SCOPES}
        codec=codecs["projection"]
        quanta=[codec.encode(row) for row in update]
        masks=[hprf.hprf(k,r,manifests["projection"]["dimension"]) for k in keys]
        vectors=[dict(sender=i,masked_vector=mask_integer_wire(codec,u,h))
                 for i,(u,h) in enumerate(zip(quanta,masks,strict=True))]
        # Encoding/keys/masks are shared; only profile-bound selection/history differs.
        decisions={s:decision(manifests[s],states[s],codecs[s],vectors,r) for s in SCOPES}
        row=dict(round=r,update_set_sha256=model_hash(update),masked_Y_sha256=digest(vectors),
            comparison=compare_rows(vectors,decisions,codec),scopes={})
        if r==len(updates):
            attacked=copy.deepcopy(vectors)
            for i,delta in enumerate(malicious):
                attacked[i]["masked_vector"]=mask_integer_wire(codec,codec.encode(delta),masks[i])
            attack_decisions={s:decision(manifests[s],states[s],codecs[s],attacked,r) for s in SCOPES}
            row["attack_comparison"]=compare_rows(attacked,attack_decisions,codec)
            row["attack_masked_Y_sha256"]=digest(attacked)
            row["attack_scopes"]={s:dict(**confusion(v["selected"],range(len(malicious)),len(vectors)),
                **counterfactual_changes(decisions[s]["selected"],v["selected"],range(len(malicious))),
                selected=v["selected"],round_continuation=v["continuation"],failure=v["failure"],
                threshold=str(v["scores"]["bound"])) for s,v in attack_decisions.items()}
        for scope,result in decisions.items():
            recovered,check=recovery_check(manifests[scope],states[scope],codecs[scope],hprf,keys,
                quanta,result,r,"frozen-benign")
            checks.append(check)
            row["scopes"][scope]=dict(**confusion(result["selected"],[],len(vectors)),
                selected=result["selected"],round_continuation=result["continuation"],failure=result["failure"],
                threshold=str(result["scores"]["bound"]),
                history_term=recovered[1]["history_term"] if recovered else None)
            if recovered:advance(states[scope],recovered[1])
        rounds.append(row);last_bundle=(vectors,quanta,masks,codecs)
    return dict(mode="four-round frozen identical-update, independent per-scope histories",
        selected_semantics="MGF eligible/bootstrap-selected; if <2, NO aggregate/key release",
        frozen_attack="existing artifact-style MR replaces clients 0..3 ONLY in the r4 counterfactual",
        rounds=rounds,outside_J_fixture=outside_fixture()),last_bundle


def measure(callback,repeats):
    callback()  # Warmup excluded, identical for both scopes.
    times=[]
    for _ in range(repeats):
        start=time.perf_counter();callback();times.append(time.perf_counter()-start)
    tracemalloc.start()
    callback();_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    return dict(mean_seconds=float(np.mean(times)),median_seconds=float(np.median(times)),
        p95_seconds=float(np.percentile(times,95)),runs=times,python_allocation_peak_bytes=peak,
        memory_scope="tracemalloc allocation peak of callback, NOT total/native process RSS")


def performance(manifests,hprf,keys,bundle,repeats):
    vectors,quanta,masks,codecs=bundle
    members=[0,1];values=[Fraction(quanta[0][j]+quanta[1][j],codecs["projection"].scale)
                        for j in range(manifests["projection"]["dimension"])]
    mask_sum=[sum(scale_mask(masks[i][j],hprf.p,codecs["projection"].transmission_period) for i in members)
              for j in range(len(values))]
    aggregate=hprf.hprf(sum(keys[i] for i in members),4,len(values))
    rows={}
    for scope in SCOPES:
        m=manifests[scope];codec=codecs[scope];start,stop=scope_span(m)
        # r4 avoids bootstrap sqrt; includes exact per-client Fraction comparison.
        state=dict(paper_bound="10000000",paper_terms=["1","1"],paper_mgf_scope=scope)
        rows[scope]=dict(vector_dimension=len(values),evaluated_coordinate_count=stop-start,
            client_count=len(vectors),predicate=measure(lambda:selection_statistics(m,state,codec,vectors,4),repeats),
            history=measure(lambda:history_statistics(m,codec,values,mask_sum,aggregate,2),repeats),
            serialized_vector_batch_bytes=len(canonical(vectors)),
            serialized_mean_client_vector_bytes=len(canonical(vectors))/len(vectors))
    return dict(environment=dict(python=platform.python_version(),platform=platform.platform(),
                processor=platform.processor(),mobile_measured=False),scopes=rows,
        network_scope="canonical complete Y-vector batch payload, not Flower framing/signatures/fanout",
        network_finding="source sends full Y in both scopes; projection saves norm computation, NOT vector bandwidth",
        benchmark_threshold="fixed PUBLIC timing-only b=10000000; not used for any experiment selection")


def evaluate_loss_accuracy(offset,reference,images,labels,batch=256):
    import torch
    from trustlessfl.fmnist import make_model,load_vector,tensor_images
    model=make_model();load_vector(model,reference+offset);model.eval()
    loss=0.;correct=0
    with torch.no_grad():
        for pos in range(0,len(labels),batch):
            xx=tensor_images(images[pos:pos+batch],"cpu")
            yy=torch.from_numpy(labels[pos:pos+batch].copy()).long()
            logits=model(xx)
            loss+=float(torch.nn.functional.cross_entropy(logits,yy,reduction="sum"))
            correct+=int((logits.argmax(1)==yy).sum())
    return dict(loss=loss/len(labels),accuracy=correct/len(labels),examples=len(labels))


def closed_loop(manifest,hprf,keys,inputs,reference,test,train,training,checks,*,attack=False):
    import torch
    from trustlessfl.fmnist import FmnistTrainer,attack_success_rate
    torch.manual_seed(training["seed"])
    scope=manifest["source_profile"]["mgf_scope"];state={};model=np.zeros(len(reference));rows=[]
    initial=model_hash(model);completed=0;failure=None
    attack_config=dict(rounds=[4],clean_path=str(inputs/"attack-clean.npz"),
        poison_path=str(inputs/"attack-poison.npz"),steps=training["attack_steps"],
        boost=training["attack_boost"],poison_batch=training["poison_batch"])
    for r in range(1,5):
        print(f"closed {'MR' if attack else 'benign'} {scope} r{r} train 20 clients",flush=True)
        parent=model_hash(model);t0=time.perf_counter()
        updates=[]
        for i in manifest["clients"]:
            updates.append(FmnistTrainer(inputs/f"client-{i}.npz",inputs/"reference.npz",
                seed=training["seed"],epochs=training["epochs"],batch_size=64,
                sampling_policy="author-loader",attack=attack_config if attack and i<4 else None)(
                    model,i,manifest["learning_rate"],r))
        update_array=np.stack(updates);training_seconds=time.perf_counter()-t0
        codec=paper_codec(manifest,hprf,r,state.get("paper_next_linf"))
        quanta=[codec.encode(row) for row in updates]  # Reject, NEVER auto-clip.
        vectors=[dict(sender=i,masked_vector=mask_integer_wire(codec,u,hprf.hprf(keys[i],r,len(reference))))
                 for i,u in enumerate(quanta)]
        result=decision(manifest,state,codec,vectors,r)
        recovered,check=recovery_check(manifest,state,codec,hprf,keys,quanta,result,r,
                                      "closed-MR" if attack else "closed-benign")
        checks.append(check);applied_norm=0.;term=None
        if recovered:
            decoded,meta=recovered
            update=np.asarray(decoded,dtype=np.float64)/(codec.scale*len(result["selected"]))
            model=model+update;applied_norm=float(np.linalg.norm(update));term=meta["history_term"]
            advance(state,meta);completed+=1
        else:failure=result["failure"]
        validation=evaluate_loss_accuracy(model,reference,test[0][:1000],test[1][:1000])
        evaluation=evaluate_loss_accuracy(model,reference,test[0][1000:],test[1][1000:])
        train_eval=evaluate_loss_accuracy(model,reference,*train)
        row=dict(round=r,scope=scope,**confusion(result["selected"],range(4) if attack and r==4 else [],20),
            selected=result["selected"],selected_count=len(result["selected"]),
            round_continuation=result["continuation"],failure=result["failure"],
            b_r=str(result["scores"]["bound"]),T_r=term,training_loss=train_eval["loss"],
            training_loss_definition="global model cross-entropy on all staged client shards after applied update",
            test_accuracy=evaluation["accuracy"],validation_accuracy=validation["accuracy"],
            global_update_norm=applied_norm,global_model_hash=model_hash(model),parent_model_hash=parent,
            client_update_set_sha256=model_hash(update_array),masked_Y_sha256=digest(vectors),
            max_client_update_abs=float(np.max(np.abs(update_array))),local_training_seconds=training_seconds,
            recovery_status=check["status"],mismatch_count=check.get("mismatch_count"),
            max_absolute_difference=check.get("max_absolute_difference"),capacity_margin=check.get("capacity_margin"))
        if attack:
            good=test[1]!=2
            row["triggered_target_rate"]=attack_success_rate(model,reference,test[0][good])
        rows.append(row)
        if not result["continuation"]:break
    return dict(scope=scope,mode="MR-closed-loop" if attack else "benign-closed-loop",rounds=rows,
        rounds_target=4,rounds_completed=completed,stop_reason=failure,initial_model_hash=initial,
        final_test_accuracy=rows[-1]["test_accuracy"],final_validation_accuracy=rows[-1]["validation_accuracy"],
        key_reconstruction="public-fixture INTEGER key sum, NOT actual network VSS/ASR execution",
        threshold_adjustment=False,clipping=False)


def report(config,side,perf,closed,attacks,checks):
    last=side["rounds"][-1]
    rows=[]
    for name in ("coordinates checked","MGF compute time (median s)","history time (median s)",
                 "benign FPR (last attempted round)","frozen MR attack TPR (r4)",
                 "rounds completed","final test accuracy","recovery mismatch"):
        values=[]
        for scope in SCOPES:
            p=perf["scopes"][scope];c=closed[scope];a=last["attack_scopes"][scope]
            value={"coordinates checked":p["evaluated_coordinate_count"],
                "MGF compute time (median s)":p["predicate"]["median_seconds"],
                "history time (median s)":p["history"]["median_seconds"],
                "benign FPR (last attempted round)":c["rounds"][-1]["benign_FPR"],
                "frozen MR attack TPR (r4)":a["attack_TPR"],"rounds completed":c["rounds_completed"],
                "final test accuracy":c["final_test_accuracy"],
                "recovery mismatch":sum(x.get("mismatch_count",0) for x in checks if x["scope"]==scope)}[name]
            values.append(str(value))
        rows.append("| "+name+" | "+" | ".join(values)+" |")
    section=["# MGF scope comparison", "## 1. Scope",
        "Same public FMNIST frozen updates, followed by two independent benign closed loops. "
        "Local learning + source numeric functions; NOT full Flower-network/BFT/ASR deployment.",
        "## 2. Implementation",
        "source_profile.mgf_scope -> source_paper_numeric.scope_span -> selection_statistics/select_masked "
        "and history_statistics/recover. Server/committee/offline replay use the same manifest. "
        "Missing scope retains projection, old metadata and legacy recovery.",
        "## 3. Mathematical definition",
        "Projection: sum(Y[J]^2)/(dS)^2 <= b_proj^2. Full: sum(Y^2)/(dS)^2 <= b_full^2. "
        "T_proj=||U[J]/S||2+||B[J]/(dS)||inf; T_full=||U/S||2+||B/(dS)||inf. "
        "Each b uses its OWN two terms: b_r=b_(r-1)*T_(r-1)/T_(r-2). "
        "Integer squares/Fraction comparisons; history sqrt retains 60-digit Decimal. "
        "First three rounds retain percentile/ranking bootstrap, NOT literal inclusive predicate selection.",
        "Benign FPR here means fraction of benign submissions not selected. In rounds 1-3 it includes "
        "intentional bootstrap downselection, not a standalone inclusive-bound false-alarm estimate.",
        "## 4. Aion correspondence",
        "Full-vector masked norm is closer to Algorithm 6; projection is the Flower adaptation. "
        "actual-mask-sum != paper-hprf history. Neither variant is complete Aion reproduction.",
        "## 5. Side-by-side result",
        "Same Y hash for both scopes; different history/threshold trajectories. See side_by_side.json. "
        "selected flags denote MGF eligibility (including bootstrap); fewer than 2 means NO aggregation.",
        "| Round | both accept | projection only | full only | both reject |",
        "|---|---:|---:|---:|---:|"]
    for r in side["rounds"]:
        c=r["comparison"];section.append(f"| {r['round']} | {len(c['both_accept'])} | {len(c['projection_only'])} | {len(c['full_vector_only'])} | {len(c['both_reject'])} |")
    section += ["## 6. Projection-outside-J fixture",json.dumps(side["outside_J_fixture"],ensure_ascii=False),
        "Predicate-only and deliberately outside input bounds; NOT signed-protocol attack success.",
        "## 7. Performance","Measured on identical full Y payloads; projection does not reduce vector network size. "
        "performance.json contains repeats, medians, p95 and separate tracemalloc peaks (not total RSS).",
        "## 8. Benign closed-loop","No threshold tuning or automatic clipping. On abort the model stays at its last committed value.",
        "| Scope | Round | accepted | benign FPR | continue | test accuracy |",
        "|---|---:|---:|---:|---|---:|"]
    for scope in SCOPES:
        for r in closed[scope]["rounds"]:
            section.append(f"| {scope} | {r['round']} | {r['benign_accepted']} | {r['benign_FPR']} | {r['round_continuation']} | {r['test_accuracy']} |")
    section += ["Full thresholds/T_r/loss/model hashes are in projection_rounds.json and full_vector_rounds.json.",
        "## 9. Attack evaluation",json.dumps(last["attack_scopes"],ensure_ascii=False),
        "Frozen r4 existing MR counterfactual uses the same pre-attack history. Compare newly_rejected_attacker_ids "
        "to already_rejected_attacker_ids: TPR alone does NOT establish attack-specific sensitivity. " + attacks["status"],
        "| Scope | MR completed rounds | r4 attack TPR | r4 benign FPR | malicious accepted | benign accepted | final test accuracy | triggered target rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for scope,c in attacks["experiments"].items():
        r=c["rounds"][-1]
        section.append(f"| {scope} | {c['rounds_completed']} | {r['attack_TPR']} | {r['benign_FPR']} | {r['malicious_accepted']} | {r['benign_accepted']} | {c['final_test_accuracy']} | {r['triggered_target_rate']} |")
    section += [
        "## 10. Recovery correctness",
        f"Mismatch sum={sum(x.get('mismatch_count',0) for x in checks)}. "
        "Only recovered rounds count; aborted rounds are not successes. recovery_checks.json records exact "
        "plain/recovered integer arrays, realized residuals and capacity margins. "
        f"Recovered coordinate comparisons={sum(len(x.get('plaintext_integer_sum',[])) for x in checks)}. "
        "Scope-independent recovery is tested for the SAME selected sum; different selected sets legitimately "
        "produce different update sums.",
        "## 11. Trade-off","| Metric | Projection | Full-vector |","|---|---:|---:|",*rows,
        "One fixed configuration/seed, short trajectories; no general robustness or convergence inference. "
        "At matching frozen Y the predicate sees more coordinates, but thresholds and later models differ.",
        "### Answers to the six comparison questions",
        "1. In this fixture full-vector rejects more designated MR clients, but the frozen selection did not "
        "change when MR was inserted: they were already rejected while benign. No independent attack-specific "
        "detection gain is established. See counterfactual changes and attacked closed-loop outcomes.",
        "2. No benefit without benign cost is established: the observed full-vector benign r4 rejection is high. "
        "Do not interpret high TPR as a usable detector independently of FPR.",
        "3. Exact coordinate counts, predicate/history medians and allocation peaks are in performance.json. "
        "Full-vector evaluates all 61706 coordinates rather than 840; full Y bytes are unchanged.",
        "4. Projection cannot observe an outside-J change in its norm; the public predicate-only fixture confirms "
        "that difference. It is NOT evidence that an authenticated bounded protocol attack succeeds.",
        "5. Four rounds can continue without threshold tuning, but with only two full-vector survivors the "
        "current bootstrap/history policy is not shown practically usable. Longer convergence is untested.",
        "6. No recovery mismatch was observed. Changing scope changes selected clients/history, NOT the "
        "encoding/modular-centered arithmetic; see equal-selected-sum regression and recovery_checks.json.",
        "## 12. Limitations",
        "actual-mask-sum != paper-hprf; scalar HPRF privacy unresolved; raw-output inversion unresolved; "
        "r+block overlap unresolved; multi-round aggregate-key leakage unresolved; share-mask inconsistency "
        "unresolved; weighted FedAvg unsupported; production security not established. "
        "Reproducible public keys are not a production key sampler. "
        "No complete signed malicious-protocol experiment or actual network/VSS execution in these learning loops."]
    # Preserve adjacent table rows; blank separators would break Markdown tables.
    lines=[]
    for item in section:
        if item.startswith("#"):lines.extend(["",item,""])
        else:lines.append(item)
    return "\n".join(lines).lstrip()+"\n"


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",type=Path,default=ROOT/".cache/same-scale-fmnist-official-20261008")
    parser.add_argument("--frozen",type=Path,default=ROOT/".cache/transmission-parameter-audit-20261008-v1/workload.npz")
    parser.add_argument("--output",type=Path)
    parser.add_argument("--benchmark-repeats",type=int,default=7)
    args=parser.parse_args()
    if args.benchmark_repeats<3:parser.error("at least 3 benchmark repeats required")
    output=args.output or ROOT/"experiments/results"/("mgf_scope_comparison_"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    manifest=json.loads((args.run/"manifest.json").read_text())
    training=manifest["training"];inputs=Path(training["input_root"])
    hashes={name:sha(inputs/name) for name in training["input_sha256"]}
    if hashes!=training["input_sha256"]:raise ValueError("staged data hashes changed")
    hprf=OriginalAionHPRF.from_directory(Path(manifest["source-root"])/"agent/Aion/HPRF")
    from trustlessfl.fmnist import shard,reference_vector
    import torch
    torch.set_num_threads(1);torch.manual_seed(training["seed"])
    with np.load(args.frozen,allow_pickle=False) as data:
        updates=data["updates"].copy();malicious=data["malicious"].copy()
    if updates.shape!=(4,20,manifest["dimension"]) or malicious.shape!=(4,manifest["dimension"]):
        raise ValueError("expected published four-round 20-client frozen FMNIST fixture")
    generator=random.Random(20261009);keys=[generator.randrange(hprf.q) for _ in range(20)]
    manifests={}
    for scope in SCOPES:
        m=copy.deepcopy(manifest);m["source_profile"]={**BASE_PROFILE,"mgf_scope":scope}
        m["key_profile"].update(minimum=0,maximum=hprf.q-1,modulus=hprf.q)
        m["max_abs"]=100.0
        validate_profile(m,hprf);manifests[scope]=m
    reference=reference_vector(inputs/"reference.npz");test=shard(inputs/"test.npz")
    pieces=[shard(inputs/f"client-{i}.npz") for i in manifest["clients"]]
    train=(np.concatenate([p[0] for p in pieces]),np.concatenate([p[1] for p in pieces]))
    config=dict(profile_origin="source-profile-integration-2026-10-09.md fixed smoke envelope, NOT tuned for MGF",
        profiles={s:m["source_profile"] for s,m in manifests.items()},projection=manifest["paper_numerics"]["projection"],
        initial_model="zero offset from pinned reference",dataset="staged public FMNIST",client_count=20,
        training=training,learning_rate=manifest["learning_rate"],optimizer="SGD",
        momentum=.9,weight_decay=.0005,batch_size=64,sampling_policy="author-loader",
        source_manifest=str(args.run/"manifest.json"),source_manifest_sha256=sha(args.run/"manifest.json"),
        vector_dimension=manifest["dimension"],training_examples=len(train[1]),
        validation_examples=1000,test_examples=len(test[1])-1000,
        model_hash_definition="SHA256 of little-endian float64 model offset from pinned reference",
        frozen_updates_path=str(args.frozen),frozen_updates_sha256=sha(args.frozen),input_sha256=hashes,
        extra_input_sha256={name:sha(inputs/name) for name in ("test.npz","attack-clean.npz","attack-poison.npz")},
        public_fixture_key_seed=20261009,public_fixture_keys=keys,clipping=False,
        key_sampling_note="seeded Random full-domain public fixture ONLY; runtime still uses secrets.randbelow",
        baseline_models_sha256=sha(args.run/"results.json"),
        implementation_sha256={str(p.relative_to(ROOT)):sha(p) for p in [Path(__file__),
            ROOT/"trustlessfl/source_paper_numeric.py",ROOT/"trustlessfl/source_profiles.py",ROOT/"trustlessfl/fmnist.py"]})
    output.mkdir(parents=True,exist_ok=False)
    print(f"artifact {output}",flush=True);dump(output/"config.json",config)
    checks=[]
    side,bundle=frozen_compare(manifests,hprf,keys,updates,malicious,checks)
    dump(output/"side_by_side.json",side)
    perf=performance(manifests,hprf,keys,bundle,args.benchmark_repeats);dump(output/"performance.json",perf)
    closed={}
    for scope in SCOPES:
        closed[scope]=closed_loop(manifests[scope],hprf,keys,inputs,reference,test,train,training,checks)
        dump(output/("projection_rounds.json" if scope=="projection" else "full_vector_rounds.json"),closed[scope])
    controlled=verify_controlled_pair(closed)
    dump(output/"controlled_comparison.json",controlled)
    attacks=dict(status="not-run: benign-only pair did not BOTH complete four rounds",experiments={})
    if all(c["rounds_completed"]>=4 for c in closed.values()):
        attacks["status"]="executed existing MR after benign pair completed four rounds"
        for scope in SCOPES:
            attacks["experiments"][scope]=closed_loop(manifests[scope],hprf,keys,inputs,reference,test,
                train,training,checks,attack=True)
    dump(output/"attack_rounds.json",attacks);dump(output/"recovery_checks.json",checks)
    with (output/"report.md").open("x") as stream:stream.write(report(config,side,perf,closed,attacks,checks))
    dump(output/"sha256.json",{p.name:sha(p) for p in sorted(output.iterdir()) if p.is_file()})
    print(json.dumps(dict(output=str(output),closed={s:c["rounds_completed"] for s,c in closed.items()},
        recovery_mismatch=sum(x.get("mismatch_count",0) for x in checks),attack_closed_status=attacks["status"])),flush=True)


if __name__=="__main__":main()
