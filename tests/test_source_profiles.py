"""Profile separation, audited counterexamples, and source/Flower replay."""

import copy
from fractions import Fraction
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.crypto import ProtocolError, canonical, digest
from trustlessfl.modular_recovery import center_p
from trustlessfl.paper_dmc import PaperDMC
from trustlessfl import source_profiles as profiles
from trustlessfl.source_paper_numeric import (SUM_SCALE_SOURCE, FILTER_RULE, descriptor,
    paper_codec, mask_integer_wire, select_masked, recover)

P = 14760426300877770769
Q = 5 * P


def options(**changes):
    return {**dict(recovery=profiles.CENTERED, key_domain="author-small",
        period_policy="fixed-integer", history="actual-mask-sum", S=10000, d=21,
        M=8421, nmax=20, C="0.001", aggregation="unweighted", rounding="nearest-even"), **changes}


def manifest_for(opts=None):
    opts = options() if opts is None else dict(opts)
    key_policy = dict(kind="author-scalar", minimum=1, maximum=100000, production_privacy=False)
    if opts["key_domain"] == "author-full-q":
        key_policy.update(minimum=0, maximum=Q-1, modulus=Q)
    return dict(source_profile=opts, key_profile=key_policy, **{"research-only": True},
        task="public-profile-fixture", workload="synthetic", clients=list(range(20)),
        dimension=8, decimals=6, max_abs=float(opts.get("C", "0.001")),
        paper_numerics=dict(initial_linf="0.012347", beta="0.2", projection=[0,8],
            scale_source=SUM_SCALE_SOURCE, filter_rule=FILTER_RULE))


def toy_codec(period=101):
    return profiles.TransmissionCodec(101, 505, 1, 9, period, 4, Fraction(1), 20)


@pytest.mark.parametrize("u", [[1,1,0,0], [-1,-1,0,0], [1,-1,0,0]])
def test_toy_positive_negative_and_multiple_carry(u):
    hprf=OriginalAionHPRF(1,4,101,505,[[1,2,3,4]])
    codec=toy_codec()
    keys=[400,350,400,350]
    hs=[hprf.hprf(k,1,4) for k in keys]
    wires=[codec.mask([z,-z,z,0],h) for z,h in zip(u,hs)]
    total=[sum(row[j] for row in wires) for j in range(4)]
    plain=[sum(u),-sum(u),sum(u),0]
    assert sum(h[0] for h in hs)>2*codec.transmission_period
    assert codec.recover(total,hprf.hprf(sum(keys),1,4),4)==plain
    assert any(y<0 for row in wires for y in row) or sum(u)>=0


@pytest.mark.parametrize("m", [5,6,21,22,101,102])
def test_odd_even_midpoint_convention(m):
    assert center_p(m//2,m)==m//2
    assert center_p(m//2+1,m)==m//2+1-m
    assert center_p(m-1,m)==-1
    if m%2==0:
        assert center_p(-m//2,m)==m//2


@pytest.mark.parametrize("d", [21,22,32,50,100])
def test_audited_worst_case_residual_is_corrected_when_spacing_allows_it(d):
    from experiments.transmission_numeric import worst_case_fixture
    # Same controlled internal-q extremum as the review; not a new PRF.
    f=worst_case_fixture(p=P,period=32000)
    codec=profiles.TransmissionCodec(P,Q,1,d,32000,20,Fraction(1),20)
    assert f["transmission_error"]==10==codec.error
    total=d*3+sum(profiles.scale_mask(h,P,32000) for h in f["hs"])
    assert codec.recover([total],[f["aggregate"]],20)==[3]


def test_spacing_boundary_d20_is_rejected_before_recovery():
    with pytest.raises(ProtocolError,match="spacing infeasible"):
        profiles.TransmissionCodec(P,Q,10000,20,8421,20,Fraction("0.001"),20)


@pytest.mark.parametrize("m", [8419,8420])
def test_centered_capacity_strict_boundary_rejected(m):
    with pytest.raises(ProtocolError,match="centered capacity infeasible"):
        profiles.TransmissionCodec(P,Q,10000,21,m,20,Fraction("0.001"),20)


def test_report_u700_fixture_is_infeasible_not_a_successful_sum60():
    with pytest.raises(ProtocolError,match="capacity infeasible"):
        profiles.TransmissionCodec(P,Q,10**6,100,32000,2,Fraction("0.00035"),20)


def test_non_integer_adaptive_period_is_rejected_without_rounding_or_resize():
    opts=options();opts.pop("M");opts["period_policy"]="adaptive-rational"
    opts.update(S=10**6,d=100)
    m=manifest_for(opts)
    m["paper_numerics"]["initial_linf"]="9894833/16777216"
    before=copy.deepcopy(m)
    with pytest.raises(ProtocolError,match="non-integer"):
        paper_codec(m,SimpleNamespace(p=P,q=Q),1)
    assert m==before


def test_integer_adaptive_period32000_keeps_its_infeasible_capacity():
    opts=options();opts.pop("M");opts.update(period_policy="adaptive-rational",
        S=10**6,d=100,C="0.00035",nmax=2)
    m=manifest_for(opts)
    m["paper_numerics"]["initial_linf"]="1/625"
    with pytest.raises(ProtocolError,match="capacity infeasible"):
        paper_codec(m,SimpleNamespace(p=P,q=Q),4)


def test_feasible_adaptive_setup_is_revalidated_each_round_without_fallback():
    opts=options();opts.pop("M");opts.update(period_policy="adaptive-rational")
    m=manifest_for(opts)
    m["paper_numerics"]["initial_linf"]="1"
    codec=paper_codec(m,SimpleNamespace(p=P,q=Q),1)
    assert codec.transmission_period==42000
    with pytest.raises(ProtocolError,match="capacity infeasible"):
        paper_codec(m,SimpleNamespace(p=P,q=Q),2,"0.01")


@pytest.mark.parametrize("field,value", [("S",0),("S",True),("d",0),("d",1.5),
    ("M",0),("M",2.5),("M",True),("nmax",0),("nmax",True),("C","-1"),
    ("C","nan"),("rounding","half-up"),("aggregation","sample-weighted"),
    ("recovery","unknown"),("history","unknown"),("key_domain","unknown"),
    ("period_policy","unknown")])
def test_invalid_or_weighted_profile_is_explicitly_rejected(field,value):
    opts=options();opts[field]=value
    with pytest.raises(ProtocolError):
        profiles.profile(dict(source_profile=opts))


def test_paper_hprf_history_is_recognized_but_not_mapped_to_actual_sum():
    opts=options();opts["history"]="paper-hprf"
    with pytest.raises(ProtocolError,match="explicitly unsupported"):
        profiles.profile(dict(source_profile=opts))


def test_actual_history_keeps_raw_sum_and_matches_review_counterexample():
    opts=options();opts.update(S=1,d=3,M=21,nmax=2,C="1")
    m=manifest_for(opts);m["dimension"]=1;m["paper_numerics"]["projection"]=[0,1]
    hprf=OriginalAionHPRF(1,2,101,505,[[1,2]])
    codec=paper_codec(m,hprf,1)
    wires=[mask_integer_wire(codec,[u],hprf.hprf(k,1,1)) for k,u in [(400,1),(350,0)]]
    raw=sum(w[0] for w in wires)
    pending=dict(selected=[0,1],total=[raw],paper_scale=descriptor(codec),bound_decimal="100")
    saved=copy.deepcopy(pending)
    decoded,meta=recover(m,{},codec,hprf,1,pending,750)
    assert decoded==[1] and raw==35 and raw%21!=raw
    assert pending==saved
    assert Fraction(meta["mask_linf"])==Fraction(32,3)
    assert Fraction(meta["history_term"])==Fraction(35,3)!=Fraction(444,101)
    assert meta["source_profile"]["history"]=="actual-mask-sum"


def test_missing_profile_preserves_legacy_codec_wire_and_descriptor():
    m=manifest_for();del m["source_profile"];m["max_abs"]=100.0
    legacy=paper_codec(m,SimpleNamespace(p=P),1)
    expected=PaperDMC(20,6,P).with_mgf("0.012347",beta="0.2",hmax_domain="normalized")
    assert type(legacy) is PaperDMC and legacy==expected
    assert descriptor(legacy)==dict(coefficient=str(expected.coefficient),denominator=10**8,
                                   model_decimals=6,candidates=20)
    assert profiles.profile(m)==profiles.DEFAULTS
    assert profiles.key_bounds(m)==(1,100000)


@pytest.mark.parametrize("domain",["author-small","author-full-q"])
def test_explicit_legacy_keeps_wire_arithmetic_and_separates_key_profile(domain):
    opts=dict(profiles.DEFAULTS,key_domain=domain)
    m=manifest_for(opts)
    codec=paper_codec(m,SimpleNamespace(p=P,q=Q),1)
    old=PaperDMC(20,6,P).with_mgf("0.012347",beta="0.2",hmax_domain="normalized")
    assert codec.coefficient==old.coefficient and codec.denominator==old.denominator
    assert mask_integer_wire(codec,[1,-1],[P,P//2])==mask_integer_wire(old,[1,-1],[P,P//2])
    assert descriptor(codec)["profile_digest"]==profiles.profile_tag(m)
    assert profiles.key_bounds(m,SimpleNamespace(p=P,q=Q))==(
        (1,100000) if domain=="author-small" else (0,Q-1))


def test_non_grid_aligned_bound_uses_round_even_not_legacy_floor():
    codec=profiles.TransmissionCodec(P,Q,10000,21,16821,20,Fraction("0.00015"),20)
    assert codec.max_integer==2
    assert codec.encode([0.00015,-0.00015])==[2,-2]


@pytest.mark.parametrize("h", [0,1,P-1,P,P+1,-1,-P])
def test_scaling_endpoint_and_translation(h):
    assert profiles.scale_mask(h+P,P,8421)==profiles.scale_mask(h,P,8421)+8421
    assert profiles.scale_mask(h,P,8421)==round(Fraction(8421*h,P))


def test_full_q_sampler_uses_whole_domain_and_key_sum_bound_is_shared(monkeypatch):
    opts=options();opts["key_domain"]="author-full-q"
    m=manifest_for(opts)
    observed=[]
    monkeypatch.setattr(profiles,"secrets",SimpleNamespace(randbelow=lambda q:observed.append(q) or q-1))
    assert profiles.sample_key(m,SimpleNamespace(q=Q))==Q-1 and observed==[Q]
    assert profiles.key_sum_valid(m,0,2)
    assert profiles.key_sum_valid(m,2*(Q-1),2)
    assert not profiles.key_sum_valid(m,2*(Q-1)+1,2)
    assert not profiles.key_sum_valid(m,True,2)
    m["key_profile"]["maximum"]=100000
    with pytest.raises(ProtocolError,match="disagree"):
        profiles.key_bounds(m,SimpleNamespace(q=Q))


@pytest.mark.parametrize("change", ["M","history","remove"])
def test_profile_change_cannot_reuse_state_or_replies(change):
    m=manifest_for();state={}
    profiles.pin_profile(m,state)
    if change=="remove":del m["source_profile"]
    else:m["source_profile"][change]="changed"
    with pytest.raises(ProtocolError,match="changed after initialization"):
        profiles.pin_profile(m,state)


def author_root():
    root=Path(__file__).resolve().parents[2]/"Aion"
    if not (root/"agent/Aion/HPRF/matrix").exists():pytest.skip("author setup required")
    pytest.importorskip("gmpy2");pytest.importorskip("Cryptodome")
    return root


@pytest.fixture(params=["author-small","author-full-q"])
def source_case(tmp_path,make_source_commit,request):
    from trustlessfl.aion_source_asr import source_request
    from trustlessfl.aion_source_server import provision_source
    from trustlessfl.aion_source_roster import statement
    # Existing runtime C=100, exact minimum M=2*(21*20*Round(1e4*100)+10)+1.
    # Tests here exercise routing/replay; they make no MGF usability claim.
    opts=options();opts.update(key_domain=request.param,C="100",M=840000021)
    path,nodes=provision_source(tmp_path/"run",author_root(),clients=20,committee=4,
        committee_members=[0,1,2,3],dimension=8,rounds=2,workload="synthetic",max_abs=100,
        source_profile=opts,paper_numerics=dict(initial_linf="0.012347",beta="0.2",projection=[0,8]))
    m=json.loads(path.read_text());states={i:{} for i in range(21)}
    proof=make_source_commit(m,states)
    def call(actor,action,r=1,**kwargs):
        return source_request(nodes[actor+1],states[actor],dict(action=action,task=m["task"],round=r,**kwargs))
    previous=dict(round=0,model=[0.0]*8,commit=proof(1,digest(dict(
        msg="VALID_CLIENTS",iteration=0,valid_clients=m["clients"]))))
    for i in m["clients"]:
        for event in call(i,"enroll")["outbox"]:
            call(event["recipient"],"deliver-share",body=event["body"])
    vectors=[call(i,"mask",model=previous)["outbox"][0]["body"] for i in m["clients"]]
    selected=call(20,"select",vectors=vectors)["selected"]
    auth=[call(i,"authorize-selection",vectors=vectors,model=previous,members=selected) for i in m["committee"]]
    tag=digest(vectors)
    commit=proof(2,digest(statement(m,1,selected,vectors_digest=tag)))
    shares=[dict(sender=i,**call(i,"sum-shares",members=selected,selection_commit=commit)) for i in m["committee"]]
    final=call(20,"reconstruct",shares=shares)
    return dict(m=m,path=path,nodes=nodes,states=states,proof=proof,call=call,previous=previous,
        vectors=vectors,selected=selected,tag=tag,commit=commit,auth=auth,final=final)


def test_client_selection_asr_and_committee_use_one_profile(source_case):
    c=source_case;m=c["m"];selected=c["selected"]
    from trustlessfl.task import local_delta
    from trustlessfl.aion_source_asr import load_source
    hprf=load_source(m["source-root"],json.dumps(m["source-sha256"],sort_keys=True))[3]
    codec=paper_codec(m,hprf,1)
    plain=[codec.encode(local_delta(np.zeros(8),i,m["learning_rate"])) for i in selected]
    summed=[sum(row[j] for row in plain) for j in range(8)]
    body=c["final"]["outbox"][0]["body"]
    assert c["final"]["result"]==[u/(10000*len(selected)) for u in summed]
    raw=[sum(v["masked_vector"][j] for v in c["vectors"] if v["sender"] in selected) for j in range(8)]
    assert c["states"][20]["pending"]["total"]==raw
    expected_masks=[raw[j]-21*summed[j] for j in range(8)]
    assert Fraction(body["paper_numeric"]["mask_linf"])==Fraction(max(expected_masks),21*10000)
    for i in m["committee"]:
        assert c["states"][i]["source-selection"]["pending"]["total"]==raw
        assert c["call"](i,"validate-aggregate",body=body,opening=c["final"]["aggregate_opening"])["verified"]
    if m["source_profile"]["key_domain"]=="author-full-q":
        assert c["final"]["aggregate_opening"]["key"]>100000*len(selected)


@pytest.mark.parametrize("tamper", ["scale","source_profile","result"])
def test_committee_rejects_aggregator_profile_or_model_tampering(source_case,tamper):
    c=source_case;body=copy.deepcopy(c["final"]["outbox"][0]["body"])
    if tamper=="scale":body["paper_numeric"]["scale"]["S"]+=1
    elif tamper=="source_profile":body["paper_numeric"]["source_profile"]["M"]+=1
    else:body["final_sum"][0]+=.01
    with pytest.raises(ProtocolError,match="differs from local replay"):
        c["call"](0,"validate-aggregate",body=body,opening=c["final"]["aggregate_opening"])


def test_bft_binds_selected_vectors_and_profile_before_key_release(source_case):
    from trustlessfl.aion_source_roster import statement
    c=source_case;m=c["m"]
    right=statement(m,1,c["selected"],vectors_digest=c["tag"])
    wrong=statement(m,1,c["selected"],vectors_digest="0"*64)
    assert right["profile_digest"]==profiles.profile_tag(m) and digest(right)!=digest(wrong)
    with pytest.raises(ProtocolError,match="context mismatch"):
        c["call"](0,"sum-shares",members=c["selected"],selection_commit=c["proof"](2,digest(wrong)))
    changed=copy.deepcopy(m);changed["source_profile"]["M"]+=2
    c["path"].write_bytes(canonical(changed))
    before=copy.deepcopy(c["states"][0])
    with pytest.raises(ProtocolError,match="changed after initialization"):
        c["call"](0,"sum-shares",members=c["selected"],selection_commit=c["commit"])
    assert c["states"][0]==before


def test_second_round_replays_committed_history_with_same_units(source_case):
    c=source_case;m=c["m"];body=c["final"]["outbox"][0]["body"]
    for i in m["committee"]:
        c["call"](i,"validate-aggregate",body=body,opening=c["final"]["aggregate_opening"])
    previous=dict(round=1,model=body["model"],body=body,commit=c["proof"](3,digest(body)))
    vectors=[c["call"](i,"mask",2,model=previous)["outbox"][0]["body"] for i in m["clients"]]
    selected=c["call"](20,"select",2,vectors=vectors)["selected"]
    for i in m["committee"]:
        reply=c["call"](i,"authorize-selection",2,vectors=vectors,model=previous,members=selected)
        assert reply["vectors_digest"]==digest(vectors)
    assert all(v["paper_scale"]["S"]==10000 and v["paper_scale"]["M"]==840000021 for v in vectors)


def test_flower_workflow_and_offline_verifier_full_q_unweighted(tmp_path):
    from trustlessfl.aion_source_server import provision_source,AuthorASRWorkflow
    from trustlessfl.local_grid import PooledProcessGrid
    from experiments.verify_source_learning import verify_learning
    opts=options();opts.update(key_domain="author-full-q",C="100",M=840000021)
    path,nodes=provision_source(tmp_path/"run",author_root(),clients=20,committee=4,
        dimension=8,rounds=2,workload="synthetic",max_abs=100,source_profile=opts,
        paper_numerics=dict(initial_linf="0.012347",beta="0.2",projection=[0,8]))
    m=json.loads(path.read_text())
    with PooledProcessGrid(nodes,2) as grid:
        result=AuthorASRWorkflow(m).run(grid)
    (path.parent/"results.json").write_bytes(canonical(result))
    replay=verify_learning(path.parent)
    assert replay["model_max_abs_error"]<1e-12 and replay["mask_share_deliveries"]==0
    assert result["aggregate_validated_rounds"]==2
    assert result["key_share_deliveries"]==80
    assert all(v["paper_numeric"]["removal"]==profiles.CENTERED for v in result["history"])


def test_actual_synthetic_updates_exceeding_c001_are_rejected_not_clipped():
    from trustlessfl.task import local_delta
    codec=profiles.TransmissionCodec(P,Q,10000,21,84021,20,Fraction("0.01"),20)
    updates=[local_delta(np.zeros(8),i,.001) for i in range(20)]
    over=[row for row in updates if np.max(np.abs(row))>.01]
    assert over
    for row in over:
        with pytest.raises(ProtocolError,match="coordinate bound"):
            codec.encode(row)


def test_client_keeps_endpoint_and_out_of_period_wire_before_mgf():
    codec=profiles.TransmissionCodec(101,505,1,3,21,2,Fraction(1),20)
    assert codec.mask([1],[101])==[24]  # Endpoint M plus d, NOT 24 % 21.
    assert codec.mask([-1],[0])==[-3]
    assert codec.recover([24-3],[101],2)==[0]


def test_generalized_runtime_error_bound_matches_independent_review():
    assert profiles.transmission_error(20,11,55,7)==14
    assert profiles.transmission_error(1,11,55,7)==0
    assert profiles.transmission_error(20,P,Q,8421)==10


def test_recovery_rejects_residual_or_sum_outside_declared_bounds():
    codec=profiles.TransmissionCodec(101,505,1,11,101,4,Fraction(1),20)
    assert codec.error==4  # Generalized bound, not the sharper raw E_H=2.
    with pytest.raises(ProtocolError,match="residual or decoded sum"):
        codec.recover([5],[0],2)  # Residual 5 exceeds the general bound 4.
    with pytest.raises(ProtocolError,match="residual or decoded sum"):
        codec.recover([33],[0],2)  # Decoded 3 exceeds two clients' bound 2.


def test_selection_over_nmax_is_rejected_not_silently_capped():
    m=manifest_for(options(nmax=2))
    codec=paper_codec(m,SimpleNamespace(p=P,q=Q),4)
    state=dict(paper_bound="1",paper_terms=["1","1"])
    vectors=[dict(sender=i,masked_vector=[0]*8) for i in range(20)]
    with pytest.raises(ProtocolError,match="exceed transmission nmax"):
        select_masked(m,state,codec,vectors,4)


@pytest.mark.parametrize("code",sorted(profiles.SourceProfileError.CODES))
@pytest.mark.parametrize("official",[False,True])
def test_profile_failures_have_closed_codes_in_flower_entrypoints(monkeypatch,code,official):
    pytest.importorskip("flwr")
    pytest.importorskip("gmpy2");pytest.importorskip("Cryptodome")
    from flwr.app import Context,Message,RecordDict
    from trustlessfl.client_app import handle_source_asr,records
    from trustlessfl.aion_source_official import handle
    def fail(*args):
        raise profiles.SourceProfileError(code,"private-fixture-coordinates")
    if official:
        monkeypatch.setattr("trustlessfl.aion_source_official.actor_config",lambda _: {})
        monkeypatch.setattr("trustlessfl.aion_source_official.flower_source_request",fail)
    else:
        monkeypatch.setattr("trustlessfl.aion_source_asr.flower_source_request",fail)
    ctx=Context(run_id=1,node_id=1,node_config={},state=RecordDict(),run_config={})
    message=Message(records(dict(action="select")),dst_node_id=1,message_type="query.aion_source_asr")
    reply=(handle if official else handle_source_asr)(message,ctx)
    assert reply.error.reason=="Author ASR profile failure: "+code


@pytest.mark.parametrize("change",["bound","nmax","history","spacing","capacity"])
def test_invalid_setup_is_rejected_before_task_creation(tmp_path,change):
    from trustlessfl.aion_source_server import provision_source
    opts=options()
    if change=="bound":opts["C"]="0.01"
    elif change=="nmax":opts["nmax"]=21
    elif change=="history":opts["history"]="paper-hprf"
    elif change=="spacing":opts["d"]=20
    else:opts["M"]=8420
    path=tmp_path/"invalid"
    with pytest.raises(ProtocolError):
        provision_source(path,author_root(),clients=20,dimension=8,rounds=1,
            workload="synthetic",max_abs=.001,source_profile=opts,
            paper_numerics=dict(initial_linf=".012347",beta=".2",projection=[0,8]))
    assert not path.exists()


def test_official_staging_preserves_opt_in_profile(tmp_path):
    pytest.importorskip("tomli_w")
    from trustlessfl.aion_source_server import provision_source
    from experiments.run_source_asr_official import stage
    opts=options(C="100",M=840000021,key_domain="author-full-q")
    path,_=provision_source(tmp_path/"prepared",author_root(),clients=20,dimension=8,
        workload="synthetic",max_abs=100,source_profile=opts,
        paper_numerics=dict(initial_linf=".012347",beta=".2",projection=[0,8]))
    staged=stage(path.parent,tmp_path/"stage",rounds=2,workers=2)
    copied=json.loads((staged/"manifest.json").read_text())
    assert copied["source_profile"]==opts and copied["key_profile"]["maximum"]==Q-1
    assert (staged/"app/trustlessfl/source_profiles.py").exists()
