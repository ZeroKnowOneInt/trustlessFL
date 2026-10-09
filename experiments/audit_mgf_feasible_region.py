"""Frozen single-Y feasibility audit. No runtime or threshold policy edits.

nmax is SELECTED capacity, not candidates: source bootstrap requires >=20.
Out-of-C MR scores are predicate-only diagnostics, never valid client inputs.
All oracle labels/cutoffs are offline; no cutoff is passed to source selection.
"""

import argparse
import copy
import csv
from datetime import datetime, timezone
from fractions import Fraction
import json
from pathlib import Path
import time

import numpy as np

from experiments.compare_mgf_scope import ROOT, SCOPES, advance, dump, model_hash, norm_text, sha
from experiments.diagnose_mgf_fpr import load_inputs, train_updates, decomposition, summary, spearman, oracle
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.modular_recovery import center_p
from trustlessfl.paper_dmc import round_even
from trustlessfl.source_paper_numeric import (selection_statistics, select_masked, recover,
    MGFSelectionError, descriptor)
from trustlessfl.source_profiles import TransmissionCodec, transmission_error, scale_mask, validate_profile


def minimum_period(n, C, d, S, p, q):
    """Least integer satisfying *both* runtime bounds, not a float estimate.

    E(M) is monotone. Starting at 2*d*n*Bu+1, each step raises the lower
    bound to 2*(d*n*Bu+E(M))+1. No smaller value can satisfy capacity.
    If spacing fails at this lower bound it fails at all larger periods.
    """
    if n < 2 or C <= 0 or min(d, S) < 1:
        raise ValueError("invalid envelope")
    Bu = round_even(S * C)
    M = max(2, 2*d*n*Bu+1)
    for step in range(10000):
        E = transmission_error(n, p, q, M)
        if d <= 2*E:
            return dict(feasible=False, reason="spacing-infeasible", lower_bound=M, E_bar=E, B_u=Bu)
        following = max(2, 2*(d*n*Bu+E)+1)
        if following <= M:
            assert 2*(d*n*Bu+E) < M
            # Strict off-by-one proof at adjacent integer, unless minimum=2.
            if M > 2:
                previous_E = transmission_error(n, p, q, M-1)
                assert 2*(d*n*Bu+previous_E) >= M-1
            return dict(feasible=True, M_min=M, E_bar=E, B_u=Bu, iterations=step+1,
                envelope_margin=str(Fraction(M, 2)-d*n*Bu-E))
        M = following
    raise AssertionError("minimum-period iteration did not converge")


def profile_manifest(base, n, C, M, scope):
    m = copy.deepcopy(base)
    m["source_profile"].update(nmax=n, C=str(C), M=M, mgf_scope=scope)
    m["max_abs"] = str(C)  # Exact rational envelope, not a binary float rewrite.
    return m


def codec_for(m, h):
    o = m["source_profile"]
    return TransmissionCodec(h.p, h.q, o["S"], o["d"], o["M"], o["nmax"],
        Fraction(o["C"]), len(m["clients"]), digest(m))


def stats_abs(a):
    a = np.abs(np.asarray(a, dtype=np.float64))
    return dict(count=a.size, max=float(a.max()), p999=float(np.percentile(a, 99.9)),
        p99=float(np.percentile(a, 99)), p95=float(np.percentile(a, 95)), median=float(np.median(a)))


def update_ranges(a, layers, context):
    rows=[]
    for r, batch in enumerate(a, 1):
        for i, x in enumerate(batch):
            rows.append(dict(context=context, round=r, client=i, **stats_abs(x),
                layers={name:stats_abs(x[start:stop]) for name,start,stop in layers}))
    return dict(context=context, pooled=stats_abs(a), round_client_layer=rows)


def encode_once(a, codec):
    # Same decimal-spelling nearest-even as TransmissionCodec.encode; no clipping.
    return [[codec.encode(x) for x in batch] for batch in a]


def make_vectors(quanta, masks, d):
    # Only used for public offline fixtures; out-of-C status is separately kept.
    return [dict(sender=i, masked_vector=[d*u+m for u,m in zip(row, mask, strict=True)])
        for i,(row,mask) in enumerate(zip(quanta,masks,strict=True))]


def evaluate_selection(manifest, state, codec, vectors, r):
    scores=selection_statistics(manifest,state,codec,vectors,r)
    eligible_count=(max(scores["minimum"],min(scores["maximum"],scores["rank"])) if r<=3
                    else scores["rank"])
    eligible=[scores["names"][i] for i in scores["order"][:eligible_count]]
    try:
        pending=select_masked(manifest,state,codec,vectors,r)
        return scores, eligible, pending, None
    except MGFSelectionError as exc:
        return scores, eligible, None, exc.code
    except ProtocolError as exc:
        # Explicit count infeasibility only. Do NOT cap, fallback or alter b.
        if str(exc)!="selected clients exceed transmission nmax":
            raise
        return scores, eligible, None, "selected-count-exceeds-nmax"


def check_aggregate(codec,hprf,keys,quanta,vectors,ids,r,label):
    total=[sum(vectors[i]["masked_vector"][j] for i in ids) for j in range(len(quanta[0]))]
    truth=[sum(quanta[i][j] for i in ids) for j in range(len(quanta[0]))]
    h=hprf.hprf(sum(keys[i] for i in ids),r,len(truth))
    decoded=codec.recover(total,h,len(ids))
    E=[center_p(y-codec.spacing*u-scale_mask(hj,hprf.p,codec.transmission_period),
                codec.transmission_period) for y,u,hj in zip(total,truth,h,strict=True)]
    mismatch=sum(a!=b for a,b in zip(decoded,truth,strict=True))
    margin=Fraction(codec.transmission_period,2)-max(abs(codec.spacing*u+e)
        for u,e in zip(truth,E,strict=True))
    if mismatch or margin<=0 or max(map(abs,E))>codec.error:
        raise AssertionError("feasible honest aggregate failed exact recovery")
    return dict(label=label,round=r,ids=ids,count=len(ids),coordinates=len(truth),
        mismatch=mismatch,E_max_observed=max(map(abs,E)),capacity_margin=str(margin),
        true_sum_sha256=digest(truth),recovered_sum_sha256=digest(decoded),raw_Y_sha256=digest(total))


def score_diagnostics(quanta,masks,vectors,scope,span,d,S):
    start,stop=(span if scope=="projection" else (0,len(quanta[0])))
    rows=[dict(client=i,**decomposition(u[start:stop],m[start:stop],d,S))
          for i,(u,m) in enumerate(zip(quanta,masks,strict=True))]
    return dict(clients=rows,benign={key:summary([float(x[key]) for x in rows]) for key in
        ("N_update","N_mask","N_total","mask_update_ratio","mask_square_fraction")},
        total_mask_spearman=spearman([Fraction(x["total_square"]) for x in rows],
                                     [Fraction(x["mask_square"]) for x in rows]),
        total_update_spearman=spearman([Fraction(x["total_square"]) for x in rows],
                                     [Fraction(x["update_square"]) for x in rows]))


def run_case(base,h,keys,qben,qmr,raw,n,C,M,cohort_provenance):
    S,d=(base["source_profile"][k] for k in ("S","d"))
    manifests={s:profile_manifest(base,n,C,M,s) for s in SCOPES}
    for m in manifests.values():validate_profile(m,h)
    codec=codec_for(manifests["projection"],h)
    states={s:{} for s in SCOPES};traces={s:[] for s in SCOPES};checks=[]
    stopped={s:False for s in SCOPES};norms={};attack={}
    for r in range(1,5):
        masks=[[scale_mask(x,h.p,M) for x in row] for row in raw[r-1]]
        vectors=make_vectors(qben[r-1],masks,d)
        # A deterministic *local arithmetic* capacity fixture, NOT new protocol
        # selection or silently reduced participants. All 20 scores stay intact.
        checks.append(check_aggregate(codec,h,keys,qben[r-1],vectors,list(range(n)),r,
                                      "honest-capacity-subset-NOT-MGF-selection"))
        if r==4:
            norms={s:score_diagnostics(qben[r-1],masks,vectors,s,
                base["paper_numerics"]["projection"],d,S) for s in SCOPES}
            attacked_quanta=copy.deepcopy(qben[r-1]);attacked_quanta[:4]=qmr
            attacked=make_vectors(attacked_quanta,masks,d)
            for scope in SCOPES:
                start,stop=(base["paper_numerics"]["projection"] if scope=="projection"
                            else (0,base["dimension"]))
                sq={v["sender"]:sum(int(y)**2 for y in v["masked_vector"][start:stop]) for v in attacked}
                oracle_result=oracle(sq,set(range(4)),d*S,Fraction(0))
                # No meaningful CURRENT bound if earlier replay aborted.
                oracle_result.pop("current")
                all_tp=[x["FPR"] for x in oracle_result["rows"] if x["TPR"]==1]
                oracle_result["min_FPR_for_TPR_1"]=min(all_tp) if all_tp else None
                paired=[]
                for i in range(4):
                    malicious=decomposition(qmr[i][start:stop],masks[i][start:stop],d,S)
                    clean=norms[scope]["clients"][i]
                    delta=float(malicious["N_total"])-float(clean["N_total"])
                    paired.append(dict(client=i,delta_L=delta,relative_delta_L=delta/float(clean["N_total"]),
                        update_norm_ratio=float(malicious["N_update"])/float(clean["N_update"]),
                        clean=clean,malicious=malicious))
                attack[scope]=dict(oracle=oracle_result,paired=paired,
                    benign_norms=summary([float(norm_text(sq[i],d*S)) for i in range(4,20)]),
                    malicious_norms=summary([float(norm_text(sq[i],d*S)) for i in range(4)]))
        for scope in SCOPES:
            if stopped[scope]:continue
            manifest=manifests[scope];cc=codec_for(manifest,h);state=states[scope]
            scores,ids,pending,error=evaluate_selection(manifest,state,cc,vectors,r)
            trace=dict(round=r,threshold=str(scores["bound"]),selected=ids,selected_count=len(ids),
                benign_acceptance=len(ids)/20,benign_rejection=1-len(ids)/20,
                continuation=pending is not None,failure=error,T=None,history_ratio=None,
                candidate_count=20,selected_capacity=n)
            if r==4:
                asc,aid,apending,aerror=evaluate_selection(manifest,state,cc,attacked,r)
                out=[i for i,u in enumerate(attacked_quanta) if max(map(abs,u))>cc.max_integer]
                attack[scope]["current_policy"]=dict(threshold=str(asc["bound"]),eligible=aid,
                    benign_FPR=1-len(set(aid)-set(range(4)))/16,
                    TPR=1-len(set(aid)&set(range(4)))/4,
                    continuation_if_wire_accepted=apending is not None,failure=aerror,
                    out_of_bound_clients=out,valid_client_transmissions=not out,
                    meaning="predicate-only if MR outside C; not successful protocol execution")
            if pending is not None:
                recovered,meta=recover(manifest,state,cc,h,r,pending,sum(keys[i] for i in ids))
                expected=[sum(qben[r-1][i][j] for i in ids) for j in range(base["dimension"])]
                assert recovered==expected
                checks.append(check_aggregate(cc,h,keys,qben[r-1],vectors,ids,r,
                                              "source-MGF-selected-honest-aggregate"))
                trace["T"]=meta["history_term"]
                if state.get("paper_terms"):
                    trace["history_ratio"]=str(Fraction(meta["history_term"])/Fraction(state["paper_terms"][-1]))
                advance(state,meta)
            else:stopped[scope]=True
            traces[scope].append(trace)
    return dict(nmax=n,C=str(C),M=M,S=S,d=d,B_u=codec.max_integer,E_bar=codec.error,
        envelope_margin=str(Fraction(M,2)-d*n*codec.max_integer-codec.error),
        model_mask_period=str(Fraction(M,d*S)),alpha=str(Fraction(M,d*S*h.p)),
        candidate_count=20,cohort_provenance=cohort_provenance,norms=norms,attack=attack,
        replay=traces,recovery=checks)


def flat_rows(cases):
    rows=[]
    for case in cases:
        row={k:case[k] for k in ("nmax","C","M","S","d","B_u","E_bar","model_mask_period","envelope_margin")}
        row.update(M_min=case["M_min"],multiplier=case["multiplier"],
            mismatch=sum(x["mismatch"] for x in case["recovery"]))
        for s,label in (("projection","proj"),("full-vector","full")):
            o=case["attack"][s]["oracle"];norm=case["norms"][s]
            last=case["replay"][s][-1]
            current=case["attack"][s].get("current_policy",{})
            row.update({label+"_rho":norm["benign"]["mask_update_ratio"]["median"],
                label+"_mask_ranking":norm["total_mask_spearman"],label+"_AUC":o["AUC_high_norm"],
                label+"_TPR_FPR10":o["best_TPR_at_FPR_budget"]["0.1"]["TPR"],
                label+"_r4_acceptance":last["benign_acceptance"] if last["round"]==4 else None,
                label+"_r4_continuation":last["continuation"] if last["round"]==4 else False,
                label+"_TPR_current":current.get("TPR"),label+"_FPR_current":current.get("benign_FPR"),
                label+"_MR_in_C":current.get("valid_client_transmissions")})
        rows.append(row)
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous",type=Path,default=ROOT/"experiments/results/mgf_scope_comparison_20261009T021637841695Z")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args();cfg,inputs,manifests,h,_=load_inputs(args.previous)
    before={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/"trustlessfl").glob("*.py")}
    base=manifests["projection"];S,d=(base["source_profile"][k] for k in ("S","d"))
    keys=cfg["public_fixture_keys"]
    out=args.output or ROOT/"experiments/results"/("mgf_feasible_region_"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    out.mkdir(parents=True,exist_ok=False)
    with np.load(cfg["frozen_updates_path"],allow_pickle=False) as a:
        frozen=a["updates"].copy();mr=a["malicious"].copy()
    import torch
    from trustlessfl.fmnist import make_model
    torch.set_num_threads(1);torch.manual_seed(cfg["training"]["seed"])
    cursor=0;layers=[]
    for name,v in make_model().named_parameters():
        layers.append((name,cursor,cursor+v.numel()));cursor+=v.numel()
    ranges=[update_ranges(frozen,layers,"shared-frozen-benign"),
            update_ranges(mr[None,:,:],layers,"shared-frozen-MR-r4")]
    # Reproduce previous closed benign updates ONCE to measure the envelope.
    # New parameter cases do not retrain: frozen inputs are identical for all.
    for scope in SCOPES:
        reference=json.loads((args.previous/("projection_rounds.json" if scope=="projection" else "full_vector_rounds.json")).read_text())
        model=np.zeros(base["dimension"]);updates=[]
        for r,row in enumerate(reference["rounds"],1):
            print(f"range replay {scope} r{r}",flush=True)
            assert model_hash(model)==row["parent_model_hash"]
            u=train_updates(base,inputs,cfg["training"],model,r)
            assert model_hash(u)==row["client_update_set_sha256"]
            updates.append(u)
            # Saved recovery ground truth supplies exactly the previous mean.
            checks=json.loads((args.previous/"recovery_checks.json").read_text()) if r==1 else checks
            check=next(x for x in checks if x["context"]=="closed-benign" and x["scope"]==scope and x["round"]==r)
            model+=np.asarray(check["recovered_integer_sum"],dtype=np.float64)/(S*check["selected_count"])
            assert model_hash(model)==row["global_model_hash"]
        ranges.append(update_ranges(np.stack(updates),layers,"previous-closed-benign-"+scope))
    Cmax=max(Fraction(str(x["pooled"]["max"])) for x in ranges if "benign" in x["context"])
    Cs=[("current",Fraction(100)),*((str(k)+"x-benign-max",k*Cmax) for k in (2,5,10))]
    # One explicit attack-inclusive envelope to distinguish conditional from
    # joint correctness for the unchanged MR fixture. No attack modification.
    Cmr=Fraction(str(float(np.abs(mr).max())))
    Cs.append(("2x-MR-max-control",2*Cmr))
    docs=[ROOT/"docs/reproduction"/name for name in ("design-independent-review-2026-10-09.md",
        "source-profile-integration-2026-10-09.md","mgf-scope-comparison-2026-10-09.md","mgf-fpr-diagnosis-2026-10-09.md")]
    config=dict(previous=str(args.previous),input_sha256=cfg["frozen_updates_sha256"],
        previous_sha256=json.loads((args.previous/"sha256.json").read_text()),
        basis_sha256={str(p.relative_to(ROOT)):sha(p) for p in docs},runtime_before=before,
        script_sha256=sha(__file__),p=h.p,q=h.q,S=S,d=d,public_keys=keys,C_benign_max=str(Cmax),
        C_candidates={name:str(c) for name,c in Cs},nmax_values=[2,5,10,20],
        M_multipliers=["1","5/4","3/2","2","4"],
        semantics="20 fixed candidate scores, nmax selected capacity; no cap or client removal",
        MR="unchanged fixture; out-of-C values are offline predicate-only, not protocol-valid",
        replay="frozen history replay, NOT newly trained closed-loop at each parameter",
        bootstrap="source requires at least 20 candidates; unchanged",
        privacy="not established; no HPRF/security changes")
    dump(out/"config.json",config);dump(out/"update_ranges.json",ranges)
    # Precompute quantization/HPRF exactly ONCE, unchanged public keys/input.
    cc=codec_for(base,h);qben=encode_once(frozen,cc);qmr=[cc.encode(x) for x in mr]
    print("raw HPRF frozen cache",flush=True)
    raw=[[h.hprf(k,r,base["dimension"]) for k in keys] for r in range(1,5)]
    cases=[];feasibility=[];start=time.perf_counter()
    for n in (2,5,10,20):
        for name,C in Cs:
            minimum=minimum_period(n,C,d,S,h.p,h.q)
            feasibility.append(dict(nmax=n,C_label=name,C=str(C),**minimum))
            if not minimum["feasible"]:continue
            for multiplier in (Fraction(1),Fraction(5,4),Fraction(3,2),Fraction(2),Fraction(4)):
                M=(minimum["M_min"]*multiplier.numerator+multiplier.denominator-1)//multiplier.denominator
                print(f"case {len(cases)+1}/100 nmax={n} {name} M={M}",flush=True)
                case=run_case(base,h,keys,qben,qmr,raw,n,C,M,name)
                case.update(C_label=name,M_min=minimum["M_min"],multiplier=str(multiplier))
                dump(out/f"case_{len(cases):03d}.json",case);cases.append(case)
    rows=flat_rows(cases)
    with (out/"region.csv").open("x",newline="") as stream:
        w=csv.DictWriter(stream,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    dump(out/"feasibility.json",feasibility);dump(out/"summary.json",rows)
    after={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/"trustlessfl").glob("*.py")}
    assert before==after
    recovery=[x for c in cases for x in c["recovery"]]
    dump(out/"recovery_summary.json",dict(aggregates=len(recovery),
        coordinates=sum(x["coordinates"] for x in recovery),mismatch=sum(x["mismatch"] for x in recovery),
        max_E=max(x["E_max_observed"] for x in recovery),
        min_capacity_margin=str(min(Fraction(x["capacity_margin"]) for x in recovery)),
        runtime_before=before,runtime_after=after,runtime_unchanged=before==after,
        elapsed_seconds=time.perf_counter()-start,
        meaning="capacity subsets and genuine MGF selected HONEST sums; no out-of-C MR guarantee"))
    dump(out/"sha256.json",{p.name:sha(p) for p in out.iterdir() if p.is_file()})
    print(f"COMPLETE {out}",flush=True)


if __name__=="__main__":main()
