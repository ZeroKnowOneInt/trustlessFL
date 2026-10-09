"""Read-only-policy MGF FPR diagnosis on pinned public comparison fixtures.

No runtime/threshold/encoding/security change. Exact integer/Fraction scores
drive the existing predicate. Float64 percentiles/RMS/ROC summaries are ONLY
offline diagnostics; no oracle threshold is passed to the source runtime.
Closed-loop updates are deterministically regenerated and hash-checked against
the previous experiment, not replaced by frozen updates from another model.
"""

import argparse
import copy
from datetime import datetime, timezone
from decimal import Decimal, localcontext
from fractions import Fraction
import json
import math
from pathlib import Path

import numpy as np

from experiments.compare_mgf_scope import (ROOT, SCOPES, advance, decision, dump,
    model_hash, norm_text, recovery_check, sha)
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError, digest
from trustlessfl.paper_dmc import evolve_bound, public_mgf_term
from trustlessfl.source_paper_numeric import paper_codec, mask_integer_wire, scope_span
from trustlessfl.source_profiles import scale_mask, validate_profile


def summary(values):
    a=np.asarray(values,dtype=np.float64)
    if not a.size or not np.isfinite(a).all():
        raise ValueError("diagnostic summary requires nonempty finite values")
    return dict(count=len(a),minimum=float(a.min()),median=float(np.median(a)),
        mean=float(a.mean()),p75=float(np.percentile(a,75)),p90=float(np.percentile(a,90)),
        p95=float(np.percentile(a,95)),maximum=float(a.max()),std=float(a.std()))


def decomposition(u,m,d,S):
    """Exact squares/cross term first; no large-int float multiplication."""
    if len(u)!=len(m) or len(u)==0 or d<=0 or S<=0:
        raise ValueError("invalid diagnostic decomposition inputs")
    u,m=[int(x) for x in u],[int(x) for x in m]
    y=[d*x+h for x,h in zip(u,m,strict=True)]
    update_square=Fraction(sum(x*x for x in u),S*S)
    mask_square=Fraction(sum(h*h for h in m),(d*S)**2)
    cross=Fraction(2*d*sum(x*h for x,h in zip(u,m,strict=True)),(d*S)**2)
    total_square=Fraction(sum(x*x for x in y),(d*S)**2)
    if update_square+mask_square+cross!=total_square:
        raise AssertionError("exact norm identity failed")
    nu=norm_text(sum(x*x for x in u),S)
    nm=norm_text(sum(h*h for h in m),d*S)
    nt=norm_text(sum(x*x for x in y),d*S)
    return dict(dimension=len(u),N_update=nu,N_mask=nm,N_total=nt,
        update_square=str(update_square),mask_square=str(mask_square),total_square=str(total_square),
        interaction=str(cross),cross_equals_twice_inner_product=True,
        mask_update_ratio=float(nm)/max(float(nu),1e-30),epsilon=1e-30,
        mask_square_fraction=float(mask_square/total_square) if total_square else None,
        interaction_fraction=float(cross/total_square) if total_square else None,
        total_RMS=float(nt)/math.sqrt(len(u)),update_RMS=float(nu)/math.sqrt(len(u)),
        mask_RMS=float(nm)/math.sqrt(len(u)))


def coordinates(values):
    """Approximate distribution/contribution diagnostics, NOT predicate scores."""
    a=np.asarray(values,dtype=np.float64)
    square=a*a;total=float(square.sum())
    descending=np.sort(square)[::-1]
    contributions={}
    for label,fraction in (("top_0.1_percent",.001),("top_1_percent",.01),("top_5_percent",.05)):
        count=math.ceil(len(a)*fraction)
        contributions[label]=dict(count=count,actual_fraction=count/len(a),
            squared_norm_fraction=float(descending[:count].sum()/total) if total else None)
    top5=contributions["top_5_percent"]["squared_norm_fraction"]
    return dict(count=len(a),mean=float(a.mean()),std=float(a.std()),median=float(np.median(a)),
        p90_abs=float(np.percentile(np.abs(a),90)),p99_abs=float(np.percentile(np.abs(a),99)),
        max_abs=float(np.abs(a).max()),squared_norm=total,contributions=contributions,
        remaining_95_percent_fraction=1-top5 if top5 is not None else None,
        rounding_note="float64 diagnostics only; top count=ceil(D*fraction)")


def ranks(values):
    order=sorted(range(len(values)),key=lambda i:values[i]);out=[0.]*len(order)
    j=0
    while j<len(order):
        end=j+1
        while end<len(order) and values[order[end]]==values[order[j]]:end+=1
        for pos in range(j,end):out[order[pos]]=(j+end-1)/2
        j=end
    return np.asarray(out)


def spearman(a,b):
    a,b=ranks(a),ranks(b)
    return float(np.corrcoef(a,b)[0,1]) if a.std() and b.std() else None


def oracle(scores,bad,denominator,bound):
    """Sweep exact norm-square cutoffs OFFLINE; never call selection here.

    Direction is fixed: high norm rejects. Equal scores cannot be separated.
    Threshold square 0 is a valid all-reject point if all scores are positive.
    """
    bad=set(bad);good=set(scores)-bad
    if not good or not bad:raise ValueError("oracle requires both labels")
    def point(threshold_sq,threshold_text,label):
        rejected={i for i,s in scores.items() if Fraction(s,denominator**2)>threshold_sq}
        return dict(label=label,threshold_square=str(threshold_sq),threshold=threshold_text,
            TPR=len(rejected&bad)/len(bad),FPR=len(rejected&good)/len(good),
            true_positive=len(rejected&bad),false_positive=len(rejected&good),
            true_negative=len(good-rejected),false_negative=len(bad-rejected))
    cutoffs=sorted({0,*scores.values()})
    rows=[point(Fraction(s,denominator**2),norm_text(s,denominator),"oracle-exact-score-cutoff")
          for s in cutoffs]
    current=point(bound**2,str(bound),"CURRENT-runtime-bound-unmodified")
    auc=Fraction(sum(2*int(scores[b]>scores[g])+int(scores[b]==scores[g]) for b in bad for g in good),
                 2*len(bad)*len(good))
    budgets={}
    for limit in (0,.05,.10,.25,.50):
        feasible=[p for p in rows if p["FPR"]<=limit]
        best=max(feasible,key=lambda x:(x["TPR"],-x["FPR"]))
        budgets[str(limit)]=dict(TPR=best["TPR"],FPR=best["FPR"],
            threshold_square=best["threshold_square"])
    return dict(mode="POST-HOC oracle; not a protocol solution or adopted threshold",
        score_direction="high norm rejects; <= accepts; ties inseparable",rows=rows,
        current=current,AUC_high_norm=float(auc),AUC_exact=str(auc),best_TPR_at_FPR_budget=budgets)


def regions(dimension,projection):
    start,stop=projection
    return {"projection":list(range(start,stop)),"full-vector":list(range(dimension)),
            "outside-J":[*range(0,start),*range(stop,dimension)]}


def margin(norm,bound):
    with localcontext() as ctx:
        ctx.prec=60;n=Fraction(norm);gap=bound-n
        render=lambda v:str(Decimal(v.numerator)/Decimal(v.denominator))
        return render(gap),render(n/bound) if bound else None


class Diagnosis:
    def __init__(self,manifests,hprf,keys,previous_checks):
        self.manifests,self.hprf,self.keys=manifests,hprf,keys
        self.regions=regions(manifests["projection"]["dimension"],
                            manifests["projection"]["paper_numerics"]["projection"])
        self.clients=[];self.norms=[];self.traces=[];self.histories=[];self.coords=[]
        self.representation=[];self.attacks=[];self.oracles=[];self.checks=[]
        self.previous_checks={(x["context"],x["scope"],x["round"]):x for x in previous_checks}
        self.fingerprints={};self.clean_scores={}

    def prepare(self,updates,r,scope):
        codec=paper_codec(self.manifests[scope],self.hprf,r)
        quanta=[codec.encode(row) for row in updates];masks=[];vectors=[]
        for i,u in enumerate(quanta):
            h=self.hprf.hprf(self.keys[i],r,len(u))
            y=mask_integer_wire(codec,u,h)
            m=[a-codec.spacing*b for a,b in zip(y,u,strict=True)]
            if m!=[scale_mask(x,self.hprf.p,codec.transmission_period) for x in h]:
                raise AssertionError("transmission mask changed")
            vectors.append(dict(sender=i,masked_vector=y));masks.append(m)
        return codec,quanta,masks,vectors

    def round(self,context,r,updates,states,expected,scopes=SCOPES,*,bad=(),coordinate_detail=True):
        print(f"diagnose {context} r{r} {'/'.join(scopes)}",flush=True)
        base,quanta,masks,vectors=self.prepare(updates,r,scopes[0]);wire_digest=digest(vectors)
        trajectory="shared-frozen" if len(scopes)>1 else scopes[0]
        if wire_digest!=expected[scopes[0]]["masked_Y_sha256"]:
            raise AssertionError("previous public Y not reproduced")
        component_rows=[]
        for i,(u,m,v) in enumerate(zip(quanta,masks,vectors,strict=True)):
            record=dict(context=context,trajectory_scope=trajectory,round=r,client=i,malicious=i in bad,
                        mask_sha256=digest(m),masked_Y_batch_sha256=wire_digest,regions={})
            for region,indices in self.regions.items():
                uu=[u[j] for j in indices];mm=[m[j] for j in indices]
                record["regions"][region]=decomposition(uu,mm,base.spacing,base.scale)
                if coordinate_detail:
                    arrays={"update":[x/base.scale for x in uu],
                        "mask":[x/base.denominator for x in mm],
                        "masked":[v["masked_vector"][j]/base.denominator for j in indices]}
                    self.coords.append(dict(context=context,trajectory_scope=trajectory,round=r,client=i,region=region,
                        malicious=i in bad,vectors={name:coordinates(a) for name,a in arrays.items()}))
            p,f,o=(record["regions"][s] for s in ("projection","full-vector","outside-J"))
            self.representation.append(dict(context=context,trajectory_scope=trajectory,round=r,client=i,malicious=i in bad,
                norm_full_over_projection=float(f["N_total"])/float(p["N_total"]),
                norm_projection_over_full=float(p["N_total"])/float(f["N_total"]),
                full_over_projection_RMS=f["total_RMS"]/p["total_RMS"],
                projection_RMS={k:p[k+"_RMS"] for k in ("update","mask","total")},
                outside_J_RMS={k:o[k+"_RMS"] for k in ("update","mask","total")},
                full_RMS={k:f[k+"_RMS"] for k in ("update","mask","total")}))
            component_rows.append(record)
        self.norms.extend(component_rows)
        results={}
        for scope in scopes:
            manifest=self.manifests[scope];state=states[scope]
            codec=paper_codec(manifest,self.hprf,r,state.get("paper_next_linf"))
            if (codec.scale,codec.spacing,codec.transmission_period)!=(base.scale,base.spacing,base.transmission_period):
                raise AssertionError("scope changed transmission units")
            before=digest(vectors)
            selected=decision(manifest,state,codec,vectors,r)
            if before!=digest(vectors):raise AssertionError("MGF instrumentation modified raw Y")
            exp=expected[scope];score=selected["scores"];bound=score["bound"]
            if selected["selected"]!=exp["selected"] or bound!=Fraction(exp["bound"]):
                raise AssertionError("diagnosis changed selection or bound")
            current=[]
            for i,record in enumerate(component_rows):
                norm=record["regions"][scope]["N_total"];gap,ratio=margin(norm,bound)
                row=dict(context=context,trajectory_scope=trajectory,scope=scope,round=r,client=i,malicious=i in bad,
                    norm=norm,threshold=str(bound),margin=gap,ratio=ratio,
                    accepted=i in selected["selected"],
                    predicate_pass=Fraction(score["squares"][i],codec.denominator**2)<=bound**2,
                    integer_square_sum=score["squares"][i],masked_Y_batch_sha256=wire_digest)
                current.append(row)
            self.clients.extend(current)
            bootstrap=r<=3
            trace=dict(context=context,scope=scope,round=r,b_r=str(bound),b_r_float=float(bound),
                selected=selected["selected"],selected_count=len(selected["selected"]),
                rejected_count=len(vectors)-len(selected["selected"]),bootstrap=bootstrap,
                minimum=score["minimum"],maximum=score["maximum"],cutoff_zero_based_rank=score["minimum"] if bootstrap else None,
                cutoff_client=score["names"][score["order"][score["minimum"]]] if bootstrap else None,
                rank=score["rank"],predicate_pass_count=sum(x["predicate_pass"] for x in current),
                norm_distribution=summary([float(x["norm"]) for x in current]),
                ratio_distribution=summary([float(x["ratio"]) for x in current]),
                norm_mask_rank_spearman=spearman([x["integer_square_sum"] for x in current],
                    [Fraction(rec["regions"][scope]["mask_square"]) for rec in component_rows]),
                norm_update_rank_spearman=spearman([x["integer_square_sum"] for x in current],
                    [Fraction(rec["regions"][scope]["update_square"]) for rec in component_rows]),
                history_formula_active=not bootstrap)
            self.traces.append(trace)
            recovered,check=recovery_check(manifest,state,codec,self.hprf,self.keys,quanta,selected,r,context)
            if recovered is None:raise AssertionError("previous completed round unexpectedly aborted")
            decoded,meta=recovered
            reference=self.previous_checks.get((context,scope,r))
            if reference and (check["plaintext_integer_sum"]!=reference["plaintext_integer_sum"] or
                    check["recovered_integer_sum"]!=reference["recovered_integer_sum"] or
                    check["realized_residual"]!=reference["realized_residual"] or
                    check["raw_Y_sum_sha256"]!=reference["raw_Y_sum_sha256"]):
                raise AssertionError("recovery changed from previous artifact")
            check["previous_recovery_arrays_verified"]=reference is not None
            self.checks.append(check)
            if Fraction(meta["history_term"])!=Fraction(exp["history_term"]):
                raise AssertionError("history changed from previous comparison")
            start,stop=scope_span(manifest)
            B=[y-codec.spacing*u for y,u in zip(selected["pending"]["total"],decoded,strict=True)]
            direct_B=[sum(masks[i][j] for i in selected["selected"]) for j in range(manifest["dimension"])]
            if B!=direct_B:raise AssertionError("raw Y mask sum was not preserved")
            hu=public_mgf_term([Fraction(x,codec.scale) for x in decoded[start:stop]],
                              [0]*(stop-start),codec)
            hm=Fraction(max(B[start:stop]),codec.denominator)
            total=hu+hm
            if total!=Fraction(meta["history_term"]):raise AssertionError("history decomposition differs")
            previous_T=Fraction(state["paper_terms"][-1]) if state.get("paper_terms") else None
            nominal=evolve_bound(bound,older_term=previous_T,newer_term=total) if previous_T else None
            self.histories.append(dict(context=context,scope=scope,round=r,selected=selected["selected"],
                H_update=str(hu),H_mask=str(hm),T_r=str(total),H_update_float=float(hu),H_mask_float=float(hm),
                T_r_float=float(total),H_mask_over_T=float(hm/total),H_update_over_T=float(hu/total),
                T_r_over_T_previous=str(total/previous_T) if previous_T else None,
                b_r=str(bound),history_formula_b_next=str(nominal) if nominal is not None else None,
                next_round_history_formula_active=r+1>3,actual_b_next=None,
                raw_Y_sum_sha256=digest(selected["pending"]["total"]),actual_B_verified=True))
            if bad:
                self.attack_analysis(context,r,scope,current,component_rows,codec,bound,bad)
            else:
                self.clean_scores[(context,scope,r)]={row["client"]:row for row in current}
                self.fingerprints[(context,r)]=wire_digest
            advance(state,meta)
            results[scope]=dict(decoded=decoded,meta=meta,check=check)
        return results

    def attack_analysis(self,context,r,scope,clients,components,codec,bound,bad):
        good=[x for x in clients if not x["malicious"]];evil=[x for x in clients if x["malicious"]]
        benign=[float(x["norm"]) for x in good];malicious=[float(x["norm"]) for x in evil]
        lo,hi=min(benign),max(benign);ml,mh=min(malicious),max(malicious)
        clean_context="frozen-benign" if context=="frozen-MR" else "closed-benign"
        clean=self.clean_scores[(clean_context,scope,r)]
        shifts=[]
        for row in evil:
            before=clean[row["client"]]
            shifts.append(dict(client=row["client"],clean_norm=before["norm"],attack_norm=row["norm"],
                delta_norm=float(row["norm"])-float(before["norm"]),
                relative_change=(float(row["norm"])-float(before["norm"]))/float(before["norm"]),
                clean_accepted=before["accepted"],attack_accepted=row["accepted"],
                clean_predicate_pass=before["predicate_pass"],attack_predicate_pass=row["predicate_pass"]))
        self.attacks.append(dict(context=context,scope=scope,round=r,benign=summary(benign),
            malicious=summary(malicious),malicious_inside_benign_range=sum(lo<=x<=hi for x in malicious),
            benign_inside_malicious_range=sum(ml<=x<=mh for x in benign),
            overlap_definition="number in the OTHER group's inclusive min/max interval; not density overlap",
            threshold=str(bound),threshold_position=dict(below_benign_min=float(bound)<lo,
                inside_benign_range=lo<=float(bound)<=hi,between_groups=(hi<float(bound)<ml) or (mh<float(bound)<lo)),
            attacker_paired_norm_changes=shifts,
            attacker_update_norms=[c["regions"][scope]["N_update"] for c in components if c["malicious"]]))
        self.oracles.append(dict(context=context,scope=scope,round=r,
            **oracle({row["client"]:row["integer_square_sum"] for row in clients},bad,codec.denominator,bound)))

    def finalize(self):
        for context in ("frozen-benign","closed-benign","closed-MR"):
            for scope in SCOPES:
                ts=[x for x in self.traces if x["context"]==context and x["scope"]==scope]
                hs=[x for x in self.histories if x["context"]==context and x["scope"]==scope]
                for idx,(t,h) in enumerate(zip(ts,hs,strict=True)):
                    if idx:
                        t["threshold_ratio"]=str(Fraction(t["b_r"])/Fraction(ts[idx-1]["b_r"]))
                    else:t["threshold_ratio"]=None
                    t["history_ratio"]=str(Fraction(hs[idx-1]["T_r"])/Fraction(hs[idx-2]["T_r"])) if idx>=2 else None
                    if idx+1<len(ts):
                        h["actual_b_next"]=ts[idx+1]["b_r"]
                        if h["next_round_history_formula_active"] and Fraction(h["history_formula_b_next"])!=Fraction(h["actual_b_next"]):
                            raise AssertionError("active history formula mismatch")


def expected_frozen(row,scope,attack=False):
    data=row["attack_scopes" if attack else "scopes"][scope]
    # Attack history is independently derived, not saved in old side_by_side.
    return dict(selected=data["selected"],bound=data["threshold"],
        masked_Y_sha256=row["attack_masked_Y_sha256" if attack else "masked_Y_sha256"],
        history_term=data.get("history_term"))


def expected_closed(row):
    return dict(selected=row["selected"],bound=row["b_r"],history_term=row["T_r"],masked_Y_sha256=row["masked_Y_sha256"])


def load_inputs(previous):
    cfg=json.loads((previous/"config.json").read_text())
    sha_map=json.loads((previous/"sha256.json").read_text())
    if any(sha(previous/name)!=value for name,value in sha_map.items()):
        raise AssertionError("previous artifact changed")
    if sha(Path(cfg["source_manifest"]))!=cfg["source_manifest_sha256"]:
        raise AssertionError("previous manifest changed")
    if sha(Path(cfg["frozen_updates_path"]))!=cfg["frozen_updates_sha256"]:
        raise AssertionError("frozen fixture changed")
    if any(sha(ROOT/name)!=value for name,value in cfg["implementation_sha256"].items()):
        raise AssertionError("comparison/source implementation changed since baseline")
    inputs=Path(cfg["training"]["input_root"])
    for name,value in {**cfg["input_sha256"],**cfg["extra_input_sha256"]}.items():
        if sha(inputs/name)!=value:raise AssertionError("training data changed")
    manifest=json.loads(Path(cfg["source_manifest"]).read_text())
    from trustlessfl.aion_source_asr import source_inventory
    if source_inventory(manifest["source-root"])!=manifest["source-sha256"]:
        raise AssertionError("author source snapshot changed")
    hprf=OriginalAionHPRF.from_directory(Path(manifest["source-root"])/"agent/Aion/HPRF")
    manifests={}
    for scope in SCOPES:
        m=copy.deepcopy(manifest);m["source_profile"]=cfg["profiles"][scope]
        m["key_profile"].update(minimum=0,maximum=hprf.q-1,modulus=hprf.q)
        m["max_abs"]=float(Fraction(cfg["profiles"][scope]["C"]))
        validate_profile(m,hprf);manifests[scope]=m
    checks=json.loads((previous/"recovery_checks.json").read_text())
    if len(checks)!=24 or any(x["status"]!="recovered" or x["mismatch_count"] or
            x["plaintext_integer_sum"]!=x["recovered_integer_sum"] for x in checks):
        raise AssertionError("baseline exact recovery evidence changed")
    return cfg,inputs,manifests,hprf,checks


def train_updates(manifest,inputs,training,model,r,attack=False):
    from trustlessfl.fmnist import FmnistTrainer
    attack_config=dict(rounds=[4],clean_path=str(inputs/"attack-clean.npz"),
        poison_path=str(inputs/"attack-poison.npz"),steps=training["attack_steps"],
        boost=training["attack_boost"],poison_batch=training["poison_batch"])
    return np.stack([FmnistTrainer(inputs/f"client-{i}.npz",inputs/"reference.npz",
        seed=training["seed"],epochs=training["epochs"],batch_size=64,sampling_policy="author-loader",
        attack=attack_config if attack and i<4 else None)(model,i,manifest["learning_rate"],r)
        for i in manifest["clients"]])


def markdown_report(cfg,diagnosis,projection_layers):
    def select(rows,context,scope,r=None):
        return [x for x in rows if x["context"]==context and x.get("scope")==scope and (r is None or x["round"]==r)]
    lines=["# Full-vector MGF benign FPR diagnosis", "", "## 1. Scope", "",
        "Pinned public fixture replay only: no predicate/threshold/parameter/key/recovery edits. "
        "Frozen same-Y analysis is separated from independently trained closed-loop trajectories. "
        "All selection and sqrt precision conventions remain the source implementation's.", "",
        "## 2. Previous result", "",
        "R4 benign rejection projection=25%, full=90%; MR rejection=25%,100%. "
        "Previous predicate medians 12.42/650.84ms, MR clean accuracies 10.08/87.96%. "
        "These are previous measurements, not new performance benchmarks.", "",
        "## 3. Norm scaling", "",
        f"D_proj=840, D_full=61706; sqrt ratio={math.sqrt(61706/840):.12g}. Diagnostic ONLY, never a threshold.", "",
        "| Context / round | mean full/proj norm | median full/proj RMS |", "|---|---:|---:|"]
    for context,trajectory in (("frozen-benign","shared-frozen"),("closed-benign","projection"),("closed-benign","full-vector")):
        for r in range(1,5):
            rs=[x for x in diagnosis.representation if x["context"]==context and x["trajectory_scope"]==trajectory and x["round"]==r]
            lines.append(f"| {context} ({trajectory}) / {r} | {np.mean([x['norm_full_over_projection'] for x in rs]):.9g} | {np.median([x['full_over_projection_RMS'] for x in rs]):.9g} |")
    lines += ["", "## 4. Norm decomposition", "",
        "Exact squares: N_total^2=N_update^2+N_mask^2+2<u/S,m/(dS)>. "
        "Python integers and Fraction verify the identity; component sqrt uses 60-digit Decimal. "
        "Coordinate percentiles/RMS are float64 diagnostics, not predicate inputs.", "",
        "| Context r4 | Scope | median update norm | median mask norm | median mask/update | median mask square fraction |", "|---|---|---:|---:|---:|---:|"]
    for context in ("frozen-benign","closed-benign"):
        for scope in SCOPES:
            rows=[x["regions"][scope] for x in diagnosis.norms if x["context"]==context and x["round"]==4
                  and x["trajectory_scope"]==("shared-frozen" if context=="frozen-benign" else scope)]
            lines.append(f"| {context} | {scope} | {np.median([float(x['N_update']) for x in rows]):.9g} | {np.median([float(x['N_mask']) for x in rows]):.9g} | {np.median([x['mask_update_ratio'] for x in rows]):.9g} | {np.median([x['mask_square_fraction'] for x in rows]):.12g} |")
    lines += ["", "## 5. Threshold trajectory", "",
        "Source bootstrap r1-3: min=floor(N/10)=2, max=floor(4N/5)=16; zero-based rank 2 "
        "(third-smallest squared norm) supplies b. Rank counts STRICTLY smaller scores, then "
        "selection count=max(min,min(max,rank)). With distinct scores this selects exactly 2/20. "
        "The inclusive bound is active only from r4; <2 survivors abort. Bootstrap selected and "
        "predicate-pass flags are separately recorded (including Decimal cutoff rounding).", "",
        "| Context | Scope | Round | b | norm median | norm min/max | selected | b/b_prev |", "|---|---|---:|---:|---:|---|---|---:|"]
    for context in ("frozen-benign","closed-benign"):
        for scope in SCOPES:
            for t in select(diagnosis.traces,context,scope):
                n=t["norm_distribution"];br=float(Fraction(t["threshold_ratio"])) if t["threshold_ratio"] else None
                lines.append(f"| {context} | {scope} | {t['round']} | {t['b_r_float']:.9g} | {n['median']:.9g} | {n['minimum']:.9g} / {n['maximum']:.9g} | {t['selected']} | {br} |")
    for context in ("frozen-benign","closed-benign"):
        for scope in SCOPES:
            lines += ["", f"### {context}, {scope}, r4 — all 20 benign clients", "",
                "| Client | Norm | Threshold | Ratio | Margin | Accepted |", "|---|---:|---:|---:|---:|---|"]
            for c in select(diagnosis.clients,context,scope,4):
                lines.append(f"| {c['client']} | {float(c['norm']):.12g} | {float(Fraction(c['threshold'])):.12g} | {float(c['ratio']):.12g} | {float(c['margin']):.12g} | {c['accepted']} |")
    lines += ["", "## 6. History decomposition", "",
        "B=sum(raw Y)-dU is checked against the direct client mask sum. "
        "T=||U_region/S||2+max(B_region)/(dS) uses the SELECTED sum, not mean. "
        "b4=b3*T3/T2. Nominal ratio updates in r2/r3 are diagnostic only: bootstrap overrides them.", "",
        "| Context | Scope | Round | H_update | H_mask | mask/T | T/T_prev | actual b_next |", "|---|---|---:|---:|---:|---:|---:|---:|"]
    for context in ("frozen-benign","closed-benign"):
        for scope in SCOPES:
            for h in select(diagnosis.histories,context,scope):
                ratio=float(Fraction(h["T_r_over_T_previous"])) if h["T_r_over_T_previous"] else None
                nxt=float(Fraction(h["actual_b_next"])) if h["actual_b_next"] else None
                lines.append(f"| {context} | {scope} | {h['round']} | {h['H_update_float']:.9g} | {h['H_mask_float']:.9g} | {h['H_mask_over_T']:.12g} | {ratio} | {nxt} |")
    lines += ["", "## 7. Projection representativeness", "",
        "J maps to these existing parameter spans (not changed): "+json.dumps(projection_layers),
        "Coordinate mean/std/median/p90abs/p99abs/max and top 0.1%/1%/5% squared contributions "
        "are in coordinate_statistics.json for update/mask/masked, J/full/outside-J, each client. "
        "projection_vs_full.json includes client RMS and projection/full norm ratios. "
        "Mask distribution observations do NOT prove independent/uniform cryptographic outputs.", "",
        "## 8. Attack separation", "",
        "Same round/key/mask paired clean vs MR changes are retained. Overlap is defined by the "
        "other group's inclusive min/max interval, not a fitted probability density.", "",
        "| Context | Scope | benign median/p90 | malicious median/min/max | malicious in benign range |", "|---|---|---|---|---:|"]
    for a in diagnosis.attacks:
        b,m=a["benign"],a["malicious"]
        lines.append(f"| {a['context']} | {a['scope']} | {b['median']:.12g}/{b['p90']:.12g} | {m['median']:.12g}/{m['minimum']:.12g}/{m['maximum']:.12g} | {a['malicious_inside_benign_range']} / 4 |")
    lines += ["", "## 9. Oracle threshold diagnostic", "",
        "All exact score cutoffs are swept OFFLINE using known fixture labels. This is NOT a "
        "protocol solution, threshold recommendation, or deployed tuning. High norm is the fixed reject direction.", "",
        "| Context | Scope | AUC | best TPR at FPR<=0 | <=0.1 | <=0.25 |", "|---|---|---:|---:|---:|---:|"]
    for o in diagnosis.oracles:
        b=o["best_TPR_at_FPR_budget"]
        lines.append(f"| {o['context']} | {o['scope']} | {o['AUC_high_norm']} | {b['0']['TPR']} | {b['0.1']['TPR']} | {b['0.25']['TPR']} |")
    full4=select(diagnosis.traces,"closed-benign","full-vector",4)[0]
    full3=select(diagnosis.traces,"closed-benign","full-vector",3)[0]
    ratio=float(Fraction(full4["threshold_ratio"]))
    rows=[x["regions"]["full-vector"] for x in diagnosis.norms if x["context"]=="closed-benign" and x["round"]==4
          and x["trajectory_scope"]=="full-vector"]
    mr=[x for x in diagnosis.oracles if x["context"]=="closed-MR" and x["scope"]=="full-vector"][0]
    lines += ["", "## 10. Root cause classification", "",
        "The labels below describe THIS pinned fixture, not every parameter/HPRF/attack.", "",
        "| Hypothesis | Decision | Evidence |", "|---|---|---|",
        "| Dimension calibration failure | not supported | Raw norms scale near sqrt(D); source independently bootstraps the FULL norm, rather than reusing the projection b. Dimension explains absolute magnitude, not an omitted dimension multiplier. |",
        f"| Mask domination | supported | Full r4 median mask/update={np.median([x['mask_update_ratio'] for x in rows]):.9g}; client and selected-history masks dominate. |",
        f"| History instability | not supported | Full b4/b3={ratio:.12g}, change={(ratio-1)*100:.12g}%; no sudden collapse/explosion. |",
        "Persistent low-tail bootstrap calibration is an additional supported cause: selecting 2/20 in r1-3 "
        "sets b3 at the third-smallest masked norm; the nearly unchanged, mask-dominated full history "
        "keeps that cutoff near the same lower tail in r4. This is not a missing sqrt(D) correction.", "",
        "### Answers to the seven questions", "",
        "1. The 90% FPR inherits a low-tail bootstrap cutoff, with norms/history dominated by fixed-scale masks. "
        "Large masks make benign updates almost irrelevant to the score.",
        "2. Dimension explains the absolute full/projection norm ratio, but NOT the FPR by itself: the full "
        "bootstrap already uses its own full norm. A sqrt(D) multiplier is not justified as a fix.",
        "3. Yes: see the exact decomposition and selected-history mask fractions.",
        f"4. No: full b3={full3['b_r_float']:.12g}, b4={full4['b_r_float']:.12g}; ratio={ratio:.12g}.",
        f"5. This scalar norm is not shown to separate the MR fixture: full closed-MR AUC={mr['AUC_high_norm']}; "
        "oracle low-FPR TPR remains poor. Higher current rejection is not discrimination.",
        "6. J's mask RMS is broadly representative, but J is classifier weights and update RMS can differ. "
        "Its r4 acceptance is also affected by mask-tail/history variation; lower FPR is not evidence of "
        "a generally representative or stronger poisoning detector.",
        "7. Review mask scaling/period policy first. Bootstrap-only acceptance tuning cannot create separation "
        "when the current score is mask-dominated and oracle separation is poor.", "",
        "## 11. Recovery regression", "",
        f"Fresh comparisons={len(diagnosis.checks)}, coordinates={sum(len(x['plaintext_integer_sum']) for x in diagnosis.checks)}, "
        f"mismatch={sum(x['mismatch_count'] for x in diagnosis.checks)}. "
        "All 24 baseline recovery arrays/residuals/raw sums are compared again; the additional two frozen-MR "
        "r4 recoveries are NEW checks, not previous baseline claims. `%M -> center -> RoundEven` is unchanged.", "",
        "## 12. Limitations", "",
        "Oracle thresholds are not protocol solutions. actual-mask-sum != paper-hprf. Scalar HPRF privacy, "
        "raw-output inversion, r+block overlap, aggregate-key leakage, share-mask consistency remain unresolved. "
        "Weighted FedAvg unsupported; production security not established. One seed/4 rounds/4 MR attackers; "
        "no general robustness or independence claim. Public fixture plaintext/keys are not new runtime inputs.", "",
        "## 13. Recommended next experiment", "",
        "ONE element: mask scaling/period-policy feasibility audit. Keep S,d,nmax,C and the decoder fixed, "
        "and compare the feasible M interval with M/(dS) required for norm separability on the same frozen "
        "updates. Current centered envelope requires M/(dS)>2*nmax*C+2*E/(dS), approximately 4000. "
        "Do not silently lower M below capacity or alter C/clipping/threshold. This audit may conclude that "
        "no usable mask scale exists under the unchanged envelope, before proposing any policy redesign.", ""]
    return "\n".join(lines)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous",type=Path,default=ROOT/"experiments/results/mgf_scope_comparison_20261009T021637841695Z")
    parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    cfg,inputs,manifests,hprf,baseline_checks=load_inputs(args.previous)
    runtime_before={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/"trustlessfl").glob("*.py")}
    docs=[ROOT/"docs/reproduction"/name for name in ("design-independent-review-2026-10-09.md",
        "source-profile-integration-2026-10-09.md","mgf-scope-comparison-2026-10-09.md")]
    from trustlessfl.fmnist import make_model
    import torch
    torch.set_num_threads(1);torch.manual_seed(cfg["training"]["seed"])
    cursor=0;layers=[]
    for name,param in make_model().named_parameters():
        stop=cursor+param.numel();start_J,stop_J=cfg["projection"]
        if max(cursor,start_J)<min(stop,stop_J):
            layers.append(dict(name=name,parameter_span=[cursor,stop],shape=list(param.shape),
                overlap_count=min(stop,stop_J)-max(cursor,start_J)))
        cursor=stop
    output=args.output or ROOT/"experiments/results"/("mgf_fpr_diagnosis_"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"))
    output.mkdir(parents=True,exist_ok=False)
    config=dict(previous=str(args.previous),previous_sha256=json.loads((args.previous/"sha256.json").read_text()),
        profiles=cfg["profiles"],unchanged_parameters=True,threshold_tuning=False,recovery_modified=False,
        training=cfg["training"],fixture_key_policy="same public keys; no resampling",public_fixture_keys=cfg["public_fixture_keys"],
        projection=cfg["projection"],dimension=manifests["projection"]["dimension"],layer_mapping=layers,
        hprf_parameters=dict(p=hprf.p,q=hprf.q),
        author_source_sha256=json.loads(Path(cfg["source_manifest"]).read_text())["source-sha256"],
        input_sha256={**cfg["input_sha256"],**cfg["extra_input_sha256"]},
        basis_document_sha256={str(p.relative_to(ROOT)):sha(p) for p in docs},
        runtime_sha256_before=runtime_before,diagnostic_script_sha256=sha(Path(__file__)),
        diagnostic_precision="exact integer/Fraction identities and scores; source Decimal60 sqrt; float64 summaries ONLY",
        closed_replay="regenerate each benign update at previous model; hash check; MR r1-3 reuse identical benign updates; MR r4 regenerate")
    dump(output/"config.json",config);print(f"artifact {output}",flush=True)
    diagnosis=Diagnosis(manifests,hprf,cfg["public_fixture_keys"],baseline_checks)
    side=json.loads((args.previous/"side_by_side.json").read_text())
    with np.load(cfg["frozen_updates_path"],allow_pickle=False) as f:
        frozen=f["updates"].copy();malicious=f["malicious"].copy()
    states={s:{} for s in SCOPES}
    for r,update in enumerate(frozen,1):
        expected={s:expected_frozen(side["rounds"][r-1],s) for s in SCOPES}
        if r==4:
            # Attack has the SAME pre-r4 history, not the benign r4 committed term.
            attack_states=copy.deepcopy(states)
        diagnosis.round("frozen-benign",r,update,states,expected)
    attacked=frozen[3].copy();attacked[:len(malicious)]=malicious
    # Old artifact does not save this counterfactual's history; compute once using
    # unchanged recover, then the diagnostic replay verifies exactly that value.
    _,quanta,_,vectors=diagnosis.prepare(attacked,4,"projection")
    attack_expected={}
    for scope in SCOPES:
        codec=paper_codec(manifests[scope],hprf,4)
        dec=decision(manifests[scope],attack_states[scope],codec,vectors,4)
        recovered,_=recovery_check(manifests[scope],attack_states[scope],codec,hprf,
            cfg["public_fixture_keys"],quanta,dec,4,"counterfactual-history-reference-only")
        row=expected_frozen(side["rounds"][3],scope,True)
        row["history_term"]=recovered[1]["history_term"];attack_expected[scope]=row
    diagnosis.round("frozen-MR",4,attacked,attack_states,attack_expected,bad=tuple(range(4)))
    closed={s:json.loads((args.previous/("projection_rounds.json" if s=="projection" else "full_vector_rounds.json")).read_text()) for s in SCOPES}
    attack_closed=json.loads((args.previous/"attack_rounds.json").read_text())["experiments"]
    for scope in SCOPES:
        model=np.zeros(manifests[scope]["dimension"]);states={scope:{}};cache=[]
        for r,row in enumerate(closed[scope]["rounds"],1):
            if model_hash(model)!=row["parent_model_hash"]:raise AssertionError("closed parent model changed")
            update=train_updates(manifests[scope],inputs,cfg["training"],model,r)
            if model_hash(update)!=row["client_update_set_sha256"]:raise AssertionError("closed update regeneration differs")
            if r<4:cache.append(update)
            result=diagnosis.round("closed-benign",r,update,states,{scope:expected_closed(row)},(scope,))[scope]
            model+=np.asarray(result["decoded"],dtype=np.float64)/(cfg["profiles"][scope]["S"]*len(row["selected"]))
            if model_hash(model)!=row["global_model_hash"]:raise AssertionError("closed model changed")
        model=np.zeros(manifests[scope]["dimension"]);states={scope:{}}
        for r,row in enumerate(attack_closed[scope]["rounds"],1):
            if model_hash(model)!=row["parent_model_hash"]:raise AssertionError("MR parent changed")
            update=cache[r-1] if r<4 else train_updates(manifests[scope],inputs,cfg["training"],model,r,True)
            if model_hash(update)!=row["client_update_set_sha256"]:raise AssertionError("MR update regeneration differs")
            result=diagnosis.round("closed-MR",r,update,states,{scope:expected_closed(row)},(scope,),
                bad=tuple(range(4)) if r==4 else (),coordinate_detail=r==4)[scope]
            model+=np.asarray(result["decoded"],dtype=np.float64)/(cfg["profiles"][scope]["S"]*len(row["selected"]))
            if model_hash(model)!=row["global_model_hash"]:raise AssertionError("MR model changed")
    diagnosis.finalize()
    runtime_after={str(p.relative_to(ROOT)):sha(p) for p in (ROOT/"trustlessfl").glob("*.py")}
    if runtime_after!=runtime_before:raise AssertionError("runtime changed during analysis")
    artifacts={"client_norms.json":diagnosis.clients,"norm_decomposition.json":diagnosis.norms,
        "threshold_trace.json":diagnosis.traces,"history_decomposition.json":diagnosis.histories,
        "coordinate_statistics.json":diagnosis.coords,
        "projection_vs_full.json":dict(dimension_reference=math.sqrt(61706/840),layer_mapping=layers,clients=diagnosis.representation),
        "attack_separation.json":diagnosis.attacks,"oracle_threshold.json":diagnosis.oracles,
        "recovery_regression.json":dict(runtime_unchanged=True,runtime_sha256_after=runtime_after,
            baseline_coordinates_verified=sum(len(x["plaintext_integer_sum"]) for x in baseline_checks),
            fresh_coordinates=sum(len(x["plaintext_integer_sum"]) for x in diagnosis.checks),
            checks=diagnosis.checks)}
    for name,value in artifacts.items():dump(output/name,value)
    with (output/"report.md").open("x") as f:f.write(markdown_report(cfg,diagnosis,layers))
    dump(output/"sha256.json",{p.name:sha(p) for p in sorted(output.iterdir()) if p.is_file()})
    print(json.dumps(dict(output=str(output),recovery_mismatch=sum(x["mismatch_count"] for x in diagnosis.checks),
        fresh_coordinates=sum(len(x["plaintext_integer_sum"]) for x in diagnosis.checks),runtime_unchanged=True)),flush=True)


if __name__=="__main__":main()
