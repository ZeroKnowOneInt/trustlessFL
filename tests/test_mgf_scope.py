"""Masked norm scope is independent of the transmission recovery arithmetic."""

import copy
from fractions import Fraction
import json
from pathlib import Path

import numpy as np
import pytest

from trustlessfl.crypto import ProtocolError, canonical
from trustlessfl.paper_dmc import PaperDMC
from trustlessfl.source_paper_numeric import (mgf_scope, scope_span, integer_square_sum,
    selection_statistics, select_masked, history_statistics, recover, paper_codec,
    descriptor, mask_integer_wire, MGFSelectionError, FILTER_RULE)
from trustlessfl import source_profiles as profiles
from trustlessfl.aion_original_hprf import OriginalAionHPRF
from test_source_profiles import options, manifest_for, author_root


def fixture(scope=None):
    opts=options(S=1,d=5,M=101,nmax=2,C="1")  # E_bar(2,101)=2, so d>=5.
    if scope is not None:opts["mgf_scope"]=scope
    m=manifest_for(opts);m["dimension"]=3;m["paper_numerics"]["projection"]=[0,1]
    hprf=OriginalAionHPRF(1,3,101,505,[[1,2,3]])
    codec=paper_codec(m,hprf,1)
    return m,hprf,codec


@pytest.mark.parametrize("scope,indices",[("projection",[0]),("full-vector",[0,1,2])])
def test_scope_scores_use_declared_coordinates(scope,indices):
    m,_,codec=fixture(scope)
    row=[-3,4,5]
    vectors=[dict(sender=i,masked_vector=row) for i in range(20)]
    scores=selection_statistics(m,{},codec,vectors,1)
    assert scores["squares"]==[sum(row[j]**2 for j in indices)]*20


def test_outside_j_counterexample_is_measured_not_a_signed_protocol_attack():
    # Independent review §14: predicate-only; intentionally outside wire bounds.
    result={}
    for scope in ("projection","full-vector"):
        m,_,_=fixture(scope)
        codec=PaperDMC(20,6,101)
        state=dict(paper_bound="1",paper_terms=["1","1"],paper_mgf_scope=scope)
        vectors=[dict(sender=i,masked_vector=[0,10**50,0]) for i in range(20)]
        info=selection_statistics(m,state,codec,vectors,4)
        result[scope]=info["squares"]
        try:selected=select_masked(m,state,codec,vectors,4)["selected"]
        except MGFSelectionError:selected=[]
        assert len(selected)==sum(Fraction(s,codec.denominator**2)<=info["bound"]**2
                                  for s in info["squares"])
    assert result["projection"]==[0]*20
    assert result["full-vector"]==[10**100]*20


@pytest.mark.parametrize("scope",["projection","full-vector"])
def test_history_uses_matching_u_and_actual_mask_sum(scope):
    m,_,codec=fixture(scope)
    values=list(map(Fraction,[3,4,0]));mask=[1,2,9]
    linf,mask_norm,_,term=history_statistics(m,codec,values,mask,[0,0,0],2)
    assert linf==(3 if scope=="projection" else 4)
    assert mask_norm==Fraction(1 if scope=="projection" else 9,5)
    assert term==(Fraction(3)+Fraction(1,5) if scope=="projection" else Fraction(34,5))


def test_same_y_stays_masked_and_recovery_does_not_depend_on_norm_scope():
    wires=[];results=[]
    for scope in ("projection","full-vector"):
        m,h,codec=fixture(scope)
        rows=[mask_integer_wire(codec,u,h.hprf(k,1,3))
              for k,u in [(4,[1,-1,0]),(16,[-1,0,1])]]
        raw=[sum(row[j] for row in rows) for j in range(3)]
        pending=dict(total=raw,selected=[0,1],bound_decimal="100",paper_scale=descriptor(codec),mgf_scope=scope)
        decoded,meta=recover(m,{},codec,h,1,pending,20)
        assert decoded==[0,-1,1]
        unmasked=[[codec.spacing*u for u in row] for row in [[1,-1,0],[-1,0,1]]]
        assert rows!=unmasked  # MGF input still contains the masks.
        assert meta["mgf_scope"]==scope
        wires.append(rows);results.append(decoded)
    assert wires[0]==wires[1] and results[0]==results[1]


def test_scope_history_cannot_be_mixed_or_silently_inherited():
    m,_,codec=fixture("full-vector")
    vectors=[dict(sender=i,masked_vector=[0,0,0]) for i in range(20)]
    for tag in (None,"projection"):
        state=dict(paper_bound="10",paper_terms=["1","2"])
        if tag is not None:state["paper_mgf_scope"]=tag
        with pytest.raises(ProtocolError,match="history scope mismatch"):
            select_masked(m,state,codec,vectors,4)
    a=dict(paper_bound="10",paper_terms=["1","2"],paper_mgf_scope="projection")
    b=dict(paper_bound="30",paper_terms=["4","3"],paper_mgf_scope="full-vector")
    proj,_,pc=fixture("projection")
    assert selection_statistics(proj,a,pc,vectors,4)["bound"]==20
    assert selection_statistics(m,b,codec,vectors,4)["bound"]==Fraction(45,2)


def test_missing_scope_keeps_projection_pending_and_legacy_recovery():
    m,h,_=fixture();m.pop("source_profile")
    from test_source_profiles import P,Q
    h=OriginalAionHPRF(1,3,P,Q,[[1,2,3]])
    old=paper_codec(m,h,1)
    assert mgf_scope(m)=="projection" and scope_span(m)==(0,1)
    rows=[mask_integer_wire(old,[1,0,1],h.hprf(k,1,3)) for k in [4,16]]
    pending=dict(total=[sum(row[j] for row in rows) for j in range(3)],selected=[0,1],bound_decimal="100")
    decoded,meta=recover(m,{},old,h,1,pending,20)
    explicit=copy.deepcopy(m);explicit["source_profile"]={**profiles.DEFAULTS,"mgf_scope":"projection"}
    # Scalar arithmetic unchanged; pin the explicit codec separately.
    codec=paper_codec(explicit,h,1)
    other,info=recover(explicit,{},codec,h,1,{**pending,"mgf_scope":"projection"},20)
    assert decoded==other and meta["history_term"]==info["history_term"]
    assert "mgf_scope" not in meta and "source_profile" not in meta


def test_explicit_profile_without_scope_has_unchanged_schema_and_projection():
    m,_,_=fixture()
    assert profiles.profile(m)==m["source_profile"] and mgf_scope(m)=="projection"
    m["source_profile"]["mgf_scope"]="unknown"
    with pytest.raises(ProtocolError):profiles.profile(m)


@pytest.mark.parametrize("kind",[list,lambda x:np.array(x,dtype=np.int64),lambda x:np.array(x,dtype=object)])
def test_large_signed_integer_squares_do_not_overflow(kind):
    values=kind([2**62,-2**62])
    assert integer_square_sum(values)==2**125


@pytest.mark.parametrize("scope",["projection","full-vector"])
def test_flower_committee_and_offline_replay_scope(tmp_path,scope):
    from trustlessfl.aion_source_server import provision_source,AuthorASRWorkflow
    from trustlessfl.local_grid import PooledProcessGrid
    from experiments.verify_source_learning import verify_learning
    opts=options(C="100",M=840000021,key_domain="author-full-q",mgf_scope=scope)
    path,nodes=provision_source(tmp_path/"run",author_root(),clients=20,committee=4,dimension=8,
        rounds=2,workload="synthetic",max_abs=100,source_profile=opts,
        paper_numerics=dict(initial_linf=".012347",beta=".2",projection=[1,3]))
    manifest=json.loads(path.read_text())
    with PooledProcessGrid(nodes,2) as grid:result=AuthorASRWorkflow(manifest).run(grid)
    (path.parent/"results.json").write_bytes(canonical(result))
    assert result["aggregate_validated_rounds"]==2 and result["mask_share_deliveries"]==0
    assert all(row["paper_numeric"]["mgf_scope"]==scope for row in result["history"])
    assert verify_learning(path.parent)["model_max_abs_error"]<1e-12
