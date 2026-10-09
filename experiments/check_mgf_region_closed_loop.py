"""Small confirmation runs; primary parameter comparison remains frozen.

Preselected benign-max envelopes, same original trainer and selection policy.
Capacity failures/out-of-C inputs STOP; no cap/clipping/threshold change.
"""
import argparse
from fractions import Fraction
import json
from pathlib import Path

import numpy as np

from experiments.audit_mgf_feasible_region import (minimum_period, profile_manifest,
    codec_for,evaluate_selection,check_aggregate,make_vectors)
from experiments.compare_mgf_scope import (advance,dump,sha,model_hash,evaluate_loss_accuracy)
from experiments.diagnose_mgf_fpr import load_inputs,train_updates
from trustlessfl.fmnist import reference_vector,shard
from trustlessfl.source_paper_numeric import recover
from trustlessfl.crypto import ProtocolError


def experiment(base,h,keys,inputs,training,n,C,M,scope,attack=False):
    m=profile_manifest(base,n,C,M,scope);codec=codec_for(m,h)
    reference=reference_vector(inputs/"reference.npz");test=shard(inputs/"test.npz")
    model=np.zeros(base["dimension"]);state={};rows=[];checks=[];failure=None
    for r in range(1,5):
        print(f"confirm closed n={n} {scope} {'MR' if attack else 'benign'} r{r}",flush=True)
        parent=model_hash(model)
        updates=train_updates(base,inputs,training,model,r,attack)
        maximum=float(np.abs(updates).max())
        outside=[i for i,x in enumerate(updates) if Fraction(str(float(np.abs(x).max())))>C]
        if outside:
            failure="input-exceeds-coordinate-bound"
            rows.append(dict(round=r,continuation=False,failure=failure,
                out_of_bound_clients=outside,max_coordinate_abs=maximum,parent_model_hash=parent))
            break
        quanta=[codec.encode(x) for x in updates]
        raw=[h.hprf(k,r,base["dimension"]) for k in keys]
        vectors=[dict(sender=i,masked_vector=codec.mask(u,hs)) for i,(u,hs) in enumerate(zip(quanta,raw,strict=True))]
        scores,ids,pending,failure=evaluate_selection(m,state,codec,vectors,r)
        bad=set(range(4)) if attack and r==4 else set();good=set(range(20))-bad
        row=dict(round=r,scope=scope,selected=ids,selected_count=len(ids),threshold=str(scores["bound"]),
            T=None,continuation=pending is not None,failure=failure,
            benign_acceptance=len(set(ids)&good)/len(good),
            TPR=1-len(set(ids)&bad)/len(bad) if bad else None,
            max_coordinate_abs=maximum,parent_model_hash=parent,update_set_sha256=model_hash(updates))
        if pending is not None:
            U,meta=recover(m,state,codec,h,r,pending,sum(keys[i] for i in ids))
            checks.append(check_aggregate(codec,h,keys,quanta,vectors,ids,r,"closed-confirm-selected"))
            row["T"]=meta["history_term"]
            model+=np.asarray(U,dtype=np.float64)/(codec.scale*len(ids))
            advance(state,meta)
        row["global_model_hash"]=model_hash(model)
        evaluation=evaluate_loss_accuracy(model,reference,test[0][1000:],test[1][1000:])
        row["test_accuracy"]=evaluation["accuracy"];row["test_loss"]=evaluation["loss"]
        rows.append(row)
        if pending is None:break
    return dict(nmax=n,C=str(C),M=M,scope=scope,attack=attack,rounds=rows,
        completed=sum(x["continuation"] for x in rows),stop_reason=failure,
        recovery=checks,interpretation="new local selected-model feedback; not network/VSS execution")


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("artifact",type=Path)
    args=p.parse_args();out=args.artifact;cfg=json.loads((out/"config.json").read_text())
    prev,inputs,manifests,h,_=load_inputs(Path(cfg["previous"]))
    import torch
    torch.set_num_threads(1);torch.manual_seed(prev["training"]["seed"])
    base=manifests["projection"];C=Fraction(cfg["C_candidates"]["2x-benign-max"])
    tasks=[(2,"full-vector"),(10,"projection"),(20,"projection"),(20,"full-vector")]
    results=[]
    for n,scope in tasks:
        M=minimum_period(n,C,cfg["d"],cfg["S"],h.p,h.q)["M_min"]
        result=experiment(base,h,cfg["public_keys"],inputs,prev["training"],n,C,M,scope)
        results.append(result)
        dump(out/f"closed_n{n}_{scope}.json",result)
        # Unchanged MR is outside these envelopes in the frozen fixture.
        # A legitimate client fails its encoder; do not bypass it for a claimed
        # end-to-end attack run. The primary audit still analyzes its scores.
    control=Fraction(cfg["C_candidates"]["2x-MR-max-control"])
    M=minimum_period(20,control,cfg["d"],cfg["S"],h.p,h.q)["M_min"]
    for scope in ("projection","full-vector"):
        benign=experiment(base,h,cfg["public_keys"],inputs,prev["training"],20,control,M,scope)
        results.append(benign);dump(out/f"closed_control_{scope}_benign.json",benign)
        if benign["completed"]==4:
            attacked=experiment(base,h,cfg["public_keys"],inputs,prev["training"],20,control,M,scope,True)
            results.append(attacked);dump(out/f"closed_control_{scope}_MR.json",attacked)
    dump(out/"closed_loop_summary.json",dict(experiments=results,script_sha256=sha(__file__),
        choices="preselected n2-full/n10-projection/n20-both at 2x-benign-max; n20-both at 2x-MR-max control",
        policy_modified=False,clipping=False,parameter_resize=False,
        coordinates=sum(x["coordinates"] for r in results for x in r["recovery"]),
        mismatch=sum(x["mismatch"] for r in results for x in r["recovery"])))


if __name__=="__main__":main()
