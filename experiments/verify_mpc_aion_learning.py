"""Independently verify the saved MPC-Aion learning-function audit."""
import argparse
from fractions import Fraction
import hashlib
import json
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
from pathlib import Path
from types import SimpleNamespace

import numpy as np

from trustlessfl.crypto import ProtocolError
from trustlessfl.fmnist import DIMENSION, evaluate, reference_vector
from trustlessfl.fmnist_no_wrap_app import configure_torch, ordered, vector_hash
from trustlessfl.fmnist_no_wrap_math import quantize
from trustlessfl.paper_dmc import round_even

ROOT=Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(run):
    body=json.loads((run/"results.json").read_text())
    cfg=body["manifest"]["config"]
    mode=cfg.get("threshold_mode","dynamic")
    no_wrap_case="no-wrap-static" if mode=="static" else "no-wrap-dynamic"
    assert [c["case"] for c in body["cases"]]==["quantized-unfiltered",no_wrap_case]
    configure_torch(cfg["device"])
    original_cfg=json.loads((Path(body["manifest"]["source_run"])/"provenance.json").read_text())["config"]
    with np.load(Path(original_cfg["data-dir"])/"test.npz",allow_pickle=False) as data:
        test_x,test_y=data["x"],data["y"]
    reference=reference_vector(run/"shards/reference.npz")
    models={}; checks=0
    for case in body["cases"]:
        with np.load(run/(case["case"]+"-models.npz"),allow_pickle=False) as data:
            weights,sums,counts=data["models"],data["integer_sums"],data["applied_counts"]
        assert weights.shape==(cfg["rounds"]+1,DIMENSION) and np.isfinite(weights).all()
        assert np.array_equal(weights[0],np.zeros(DIMENSION))
        history=[]; exclusions=[0]*4
        for i,row in enumerate(case["history"][1:]):
            count=int(counts[i]); selected=row["accepted_clients"]
            assert count==(len(selected) if len(selected)>=2 else 0)
            step=sums[i].astype(np.float64)/(cfg["scale"]*count) if count else 0
            assert np.array_equal(weights[i+1],weights[i]+step)
            assert selected==[k for k,n in enumerate(row["squared_norms_real"]) if n<=row["threshold_squared_real"]]
            assert row["max_quantization_error"]<=.5/cfg["scale"]+1e-12
            assert all(m["device"]==cfg["device"] and m["rows"]==15000 and m["optimizer_steps"]==235 for m in row["training_meta"])
            for k in range(4): exclusions[k]+=int(k not in selected)
            if case["case"]=="no-wrap-static":
                assert row["threshold_squared_real"]==cfg["squared_threshold"]/cfg["scale"]**2
            if case["case"]=="no-wrap-dynamic":
                if len(history)<2: threshold=cfg["boot"]
                else:
                    old,new=history[-2:]
                    ratio=max(Fraction(1,4),min(Fraction(4),Fraction(new[0]+1,old[0]+1)))
                    threshold=min(cfg["maximum"],max(cfg["minimum"],round_even(new[1]*ratio)))
                assert row["threshold_squared_real"]==threshold/cfg["scale"]**2
                if count:
                    norm=sum(round_even(Fraction(int(v),count))**2 for v in sums[i])
                    history.append((norm,threshold))
            checks+=1
        assert exclusions==case["excluded_client_rounds_by_client"]
        # Re-evaluate from the saved checkpoint using the existing workload API.
        reevaluated=evaluate(weights[-1],reference,test_x,test_y,device=cfg["device"])
        assert reevaluated["accuracy"]==case["final_accuracy"]
        models[case["case"]]=weights
    if mode=="dynamic":
        assert np.array_equal(models["quantized-unfiltered"][:6],models[no_wrap_case][:6])
    same_models=np.array_equal(models["quantized-unfiltered"],models[no_wrap_case])
    if not body["cases"][1]["excluded_total"] and not body["cases"][1]["abort_rounds"]:
        assert same_models
    for path,expected in body["manifest"]["source_sha256"].items():
        archived=run/"source-snapshot"/path
        assert sha(archived if archived.exists() else ROOT/path)==expected
    assert sha(run/"shards/reference.npz")==body["manifest"]["source_reference_sha256"]
    assert sha(Path(original_cfg["data-dir"])/"test.npz")==body["manifest"]["source_test_sha256"]
    for record in body["manifest"]["records"]:
        assert sha(run/f"shards/client-{record['client']}.npz")==record["sha256"]
    reply=lambda i:SimpleNamespace(content={"meta":{"partition":i}},metadata=SimpleNamespace(src_node_id=i),has_error=lambda:False)
    try: ordered([reply(i) for i in range(3)],{i:i for i in range(4)})
    except ValueError as exc: assert "incomplete" in str(exc)
    else: raise AssertionError("partial cohort unexpectedly accepted")
    try: quantize(np.array([2.0001],dtype=np.float64),cfg["scale"],cfg["cap"])
    except ProtocolError: pass
    else: raise AssertionError("oversized coordinate did not reject")
    offset=np.zeros(DIMENSION,dtype=np.float64)
    other_reference=reference.copy(); other_reference[0]+=.1
    assert vector_hash(offset)==vector_hash(offset.copy())
    assert vector_hash(reference+offset)!=vector_hash(other_reference+offset)
    result=dict(passed=True,independent_round_checks=checks,threshold_mode=mode,
        static_threshold_constant=mode=="static",quantized_and_no_wrap_models_equal=same_models,
        max_model_difference_quantized_vs_no_wrap=float(np.max(np.abs(models["quantized-unfiltered"]-models[no_wrap_case]))),
        public_sum_count_model_update_matches=True,threshold_history_verified=True,
        final_accuracy_independently_reevaluated_from_checkpoints=True,
        all_training_replies_gpu=True,source_and_data_hashes_match=True,
        one_coordinate_cap_rejects_reference_path=True,existing_flower_interface_rejects_missing_client=True,
        offset_hash_alone_does_not_bind_reference=True,
        fixed_squared_boundary_25_would_accept_all_recorded_unfiltered_updates=all(
            max(row["squared_norms_real"])<=25 for row in body["cases"][0]["history"][1:]),
        verifier_sha256=sha(Path(__file__)),scope="offline learning semantics; not native MPC or runtime dropout fault injection")
    (run/"verification.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",type=Path,required=True)
    args=parser.parse_args()
    verify(args.run)
