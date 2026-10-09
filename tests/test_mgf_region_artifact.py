"""Optional final public feasibility ledger checks; no threshold expectations."""
from fractions import Fraction
import json
import os
from pathlib import Path

import pytest

from experiments.compare_mgf_scope import ROOT,sha
from experiments.diagnose_mgf_fpr import oracle
from trustlessfl.source_profiles import transmission_error


@pytest.fixture(scope="module")
def ledger():
    path=Path(os.environ.get("MGF_REGION_ARTIFACT",ROOT/
        "experiments/results/mgf_feasible_region_20261009T063122844117Z"))
    if not (path/"summary.json").exists():pytest.skip("completed feasibility audit unavailable")
    return path


def read(path,name):return json.loads((path/name).read_text())


def cases(path):return [read(path,f"case_{i:03d}.json") for i in range(100)]


def test_all_ledger_hashes_and_runtime_unchanged(ledger):
    for name,value in read(ledger,"sha256.json").items():assert sha(ledger/name)==value
    if (ledger/"final_sha256.json").exists():
        final=read(ledger,"final_sha256.json")
        for name,value in final["artifact_sha256"].items():assert sha(ledger/name)==value
        for name,value in final["repository_sha256"].items():assert sha(ROOT/name)==value
    cfg=read(ledger,"config.json");rec=read(ledger,"recovery_summary.json")
    assert cfg["runtime_before"]==rec["runtime_after"]
    assert rec["runtime_unchanged"]
    for name,value in cfg["runtime_before"].items():assert sha(ROOT/name)==value
    for name,value in cfg["basis_sha256"].items():assert sha(ROOT/name)==value
    assert sha(ROOT/"experiments/audit_mgf_feasible_region.py")==cfg["script_sha256"]


def test_exact_feasibility_and_adjacent_minimum(ledger):
    cfg=read(ledger,"config.json")
    for c in cases(ledger):
        E=transmission_error(c["nmax"],cfg["p"],cfg["q"],c["M"])
        assert c["d"]>2*E and E==c["E_bar"]
        assert 2*(c["d"]*c["nmax"]*c["B_u"]+E)<c["M"]
        previous=c["M_min"]-1;Ep=transmission_error(c["nmax"],cfg["p"],cfg["q"],previous)
        assert 2*(c["d"]*c["nmax"]*c["B_u"]+Ep)>=previous
        assert c["candidate_count"]==20


def test_components_and_paired_masks_remain_identical(ledger):
    for c in cases(ledger):
        for scope,value in c["norms"].items():
            for v in value["clients"]:
                assert Fraction(v["update_square"])+Fraction(v["mask_square"])+Fraction(
                    v["interaction"])==Fraction(v["total_square"])
            for pair in c["attack"][scope]["paired"]:
                assert pair["clean"]["mask_square"]==pair["malicious"]["mask_square"]


def test_oracle_is_freshly_recomputed_not_expected_result(ledger):
    for c in cases(ledger):
        for scope,value in c["norms"].items():
            denominator=c["d"]*c["S"]
            scores={v["client"]:int(Fraction(v["total_square"])*denominator**2)
                    for v in value["clients"]}
            for pair in c["attack"][scope]["paired"]:
                scores[pair["client"]]=int(Fraction(pair["malicious"]["total_square"])*denominator**2)
            result=oracle(scores,range(4),denominator,Fraction(0))
            saved=c["attack"][scope]["oracle"]
            assert result["AUC_exact"]==saved["AUC_exact"]
            assert result["best_TPR_at_FPR_budget"]==saved["best_TPR_at_FPR_budget"]


def test_capacity_failures_not_silently_capped_or_committed(ledger):
    for c in cases(ledger):
        for traces in c["replay"].values():
            for row in traces:
                if row["selected_count"]>c["nmax"]:
                    assert row["failure"]=="selected-count-exceeds-nmax"
                    assert not row["continuation"] and row["T"] is None
                if row["selected_count"]<2:
                    assert row["failure"]=="insufficient-valid"
                    assert not row["continuation"]


def test_recovery_equality_hashes_and_residual_bounds(ledger):
    checks=[x for c in cases(ledger) for x in c["recovery"]]
    r=read(ledger,"recovery_summary.json")
    assert r["aggregates"]==len(checks)
    assert r["coordinates"]==sum(x["coordinates"] for x in checks)
    for c in cases(ledger):
        for x in c["recovery"]:
            assert x["mismatch"]==0 and x["true_sum_sha256"]==x["recovered_sum_sha256"]
            assert x["E_max_observed"]<=c["E_bar"] and Fraction(x["capacity_margin"])>0


def test_attack_outside_envelope_is_not_claimed_correct(ledger):
    a=read(ledger,"attack_recovery.json")
    assert a["mismatch"]==0 and a["skipped"]
    for c in cases(ledger):
        for v in c["attack"].values():
            current=v.get("current_policy")
            if current and current["out_of_bound_clients"]:
                assert not current["valid_client_transmissions"]
    for r in a["records"]:
        for x in r["checks"]:assert x["true_sum_sha256"]==x["recovered_sum_sha256"]


def test_confirmations_keep_same_policy_and_explicit_stops(ledger):
    c=read(ledger,"closed_loop_summary.json")
    assert not c["policy_modified"] and not c["clipping"] and not c["parameter_resize"]
    assert c["mismatch"]==0
    for e in c["experiments"]:
        assert e["completed"]==sum(x["continuation"] for x in e["rounds"])
        if e["stop_reason"]:assert not e["rounds"][-1]["continuation"]
