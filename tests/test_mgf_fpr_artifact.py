"""Optional pinned public FPR ledger checks; no dataset re-training in pytest."""

from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path

import pytest

from experiments.diagnose_mgf_fpr import oracle

ROOT=Path(__file__).resolve().parents[1]
DEFAULT=ROOT/"experiments/results/mgf_fpr_diagnosis_20261009T025455220443Z"


@pytest.fixture(scope="module")
def ledger():
    path=Path(os.environ.get("MGF_FPR_ARTIFACT",DEFAULT))
    if not (path/"sha256.json").exists():
        pytest.skip("completed public diagnosis artifact not available; run diagnose_mgf_fpr.py")
    return path


def read(path,name):return json.loads((path/name).read_text())


def test_ledger_hashes_and_runtime_unchanged(ledger):
    def sha(path):
        with path.open("rb") as f:return hashlib.file_digest(f,"sha256").hexdigest()
    for name,expected in read(ledger,"sha256.json").items():assert sha(ledger/name)==expected
    cfg=read(ledger,"config.json");rec=read(ledger,"recovery_regression.json")
    assert cfg["runtime_sha256_before"]==rec["runtime_sha256_after"]
    for name,expected in cfg["runtime_sha256_before"].items():assert sha(ROOT/name)==expected
    assert sha(ROOT/"experiments/diagnose_mgf_fpr.py")==cfg["diagnostic_script_sha256"]
    assert cfg["threshold_tuning"] is False and cfg["recovery_modified"] is False


def test_every_component_identity_and_raw_norm_score(ledger):
    components=read(ledger,"norm_decomposition.json")
    lookup={}
    for row in components:
        for scope,value in row["regions"].items():
            assert Fraction(value["total_square"])==Fraction(value["update_square"])+Fraction(
                value["mask_square"])+Fraction(value["interaction"])
            lookup[(row["context"],row["trajectory_scope"],row["round"],row["client"],scope)]=value
    assert len(lookup)==sum(len(row["regions"]) for row in components)
    cfg=read(ledger,"config.json");p=cfg["profiles"]["projection"];den=p["d"]*p["S"]
    for row in read(ledger,"client_norms.json"):
        square=Fraction(row["integer_square_sum"],den**2)
        assert square==Fraction(lookup[(row["context"],row["trajectory_scope"],row["round"],row["client"],row["scope"])]["total_square"])
        assert row["predicate_pass"]==(square<=Fraction(row["threshold"])**2)
        if row["round"]==4:assert row["accepted"]==row["predicate_pass"]


def test_history_sum_ratios_and_actual_bootstrap_transition(ledger):
    histories=read(ledger,"history_decomposition.json")
    traces=read(ledger,"threshold_trace.json")
    lookup={(x["context"],x["scope"],x["round"]):x for x in histories}
    for h in histories:
        assert Fraction(h["T_r"])==Fraction(h["H_update"])+Fraction(h["H_mask"])
        assert h["actual_B_verified"]
        if h["round"]==3:
            assert Fraction(h["actual_b_next"])==Fraction(h["history_formula_b_next"])
        if h["round"]==2:assert not h["next_round_history_formula_active"]
    for t in traces:
        if t["round"]==4 and t["context"]!="frozen-MR":
            h3=lookup[(t["context"],t["scope"],3)];h2=lookup[(t["context"],t["scope"],2)]
            assert Fraction(t["threshold_ratio"])==Fraction(t["history_ratio"])==Fraction(h3["T_r"])/Fraction(h2["T_r"])


def test_recovery_replays_baseline_arrays_and_not_only_old_success_count(ledger):
    rec=read(ledger,"recovery_regression.json")
    assert rec["runtime_unchanged"]
    assert len(rec["checks"])==26
    assert sum(x["previous_recovery_arrays_verified"] for x in rec["checks"])==24
    assert rec["baseline_coordinates_verified"]==1480944
    assert rec["fresh_coordinates"]==1604356
    for row in rec["checks"]:
        assert row["plaintext_integer_sum"]==row["recovered_integer_sum"]
        assert row["mismatch_count"]==0 and row["max_absolute_difference"]==0
        assert row["residual_max_abs"]<=row["residual_bound"] and Fraction(row["capacity_margin"])>0
        assert row["raw_Y_sum_preserved"]


def test_oracle_counts_are_recomputed_from_exact_fixture_scores(ledger):
    clients=read(ledger,"client_norms.json");cfg=read(ledger,"config.json")
    for stored in read(ledger,"oracle_threshold.json"):
        group=[x for x in clients if (x["context"],x["scope"],x["round"])==(
            stored["context"],stored["scope"],stored["round"])]
        scores={x["client"]:x["integer_square_sum"] for x in group}
        bad={x["client"] for x in group if x["malicious"]}
        p=cfg["profiles"][stored["scope"]]
        actual=oracle(scores,bad,p["d"]*p["S"],Fraction(group[0]["threshold"]))
        assert actual["rows"]==stored["rows"] and actual["current"]==stored["current"]
        assert actual["AUC_exact"]==stored["AUC_exact"]
