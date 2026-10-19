"""Actual FMNIST local training with the proposed MPC functionality in plaintext.

This isolates learning semantics, not MPC/Flower transport. Four equal-sized,
label-sorted non-IID shards; fresh honest training in every round. No attackers.
"""
import argparse
import os
os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import time

import numpy as np

from trustlessfl.aion_original_hprf import OriginalAionHPRF
from trustlessfl.fmnist import (DIMENSION, FmnistTrainer, load_vector, make_model,
                              reference_vector, tensor_images)
from trustlessfl.fmnist_no_wrap_app import configure_torch
from trustlessfl.fmnist_no_wrap_math import quantize
from trustlessfl.private_bound import ReferenceSubmission, aggregate, scale_canonical_mask
from trustlessfl.static_bound import static_learning_policy

ROOT=Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_model(weights, reference, images, labels, device):
    import torch
    model=make_model().to(device)
    load_vector(model, reference+weights)
    model.eval()
    hits=np.zeros(10,dtype=np.int64)
    with torch.no_grad():
        for start in range(0,len(images),256):
            y=labels[start:start+256]
            predicted=model(tensor_images(images[start:start+256],device)).argmax(1).cpu().numpy()
            hits+=np.bincount(y[predicted==y],minlength=10)
    counts=np.bincount(labels,minlength=10)
    return dict(accuracy=float(hits.sum()/len(labels)), per_class_accuracy=(hits/counts).tolist())


def run(source, output, *, rounds=10, device="cuda:0", seed=42, squared_threshold=None):
    configure_torch(device)
    cfg=json.loads((source/"provenance.json").read_text())["config"]
    source_data=Path(cfg["data-dir"])
    # Reuse exactly the previous public dataset and initial checkpoint.
    arrays=[]
    for i in range(4):
        with np.load(source_data/f"client-{i}.npz",allow_pickle=False) as row:
            arrays.append((row["x"],row["y"]))
    x=np.concatenate([a[0] for a in arrays]); y=np.concatenate([a[1] for a in arrays])
    if len(y)!=60000 or not np.array_equal(np.bincount(y,minlength=10),[6000]*10):
        raise ValueError("expected the complete balanced FMNIST training set")
    output.mkdir(parents=True,exist_ok=False)
    shards=output/"shards"; shards.mkdir()
    partitions=np.array_split(np.argsort(y,kind="stable"),4)
    records=[]
    for i,indices in enumerate(partitions):
        path=shards/f"client-{i}.npz"
        np.savez_compressed(path,x=x[indices],y=y[indices])
        records.append(dict(client=i,rows=len(indices),class_counts=np.bincount(y[indices],minlength=10).tolist(),sha256=sha(path)))
    reference_path=shards/"reference.npz"
    shutil.copyfile(source_data/"reference.npz",reference_path)
    reference=reference_vector(reference_path)
    with np.load(source_data/"test.npz",allow_pickle=False) as data:
        test_x,test_y=data["x"],data["y"]
    S,B=cfg["scale"],cfg["coordinate-cap"]
    threshold=25*S*S if squared_threshold is None else squared_threshold
    base=static_learning_policy({"threshold-mode":"static", "squared-threshold":threshold,
        "scale":S,"coordinate-cap":B},dimension=DIMENSION,clients=4)
    hprf=OriginalAionHPRF(1,2,14760426300877770769,5*14760426300877770769,[[1,2]])
    manifest=dict(scope="honest actual training, plaintext execution of MPC output functionality; no native MPC or new Flower run",
        source_run=str(source),source_reference_sha256=sha(reference_path),source_test_sha256=sha(source_data/"test.npz"),
        config=dict(seed=seed,rounds=rounds,device=device,dimension=DIMENSION,scale=S,cap=B,local_epochs=1,
                    batch_size=64,learning_rate=cfg["learning-rate"],momentum=.9,weight_decay=.0005,
                    threshold_mode="static",squared_threshold=base.squared_bound),
        partition="four equal-sized sorted-label shards; all 60000 samples",records=records,
        source_sha256={name:sha(ROOT/name) for name in ("experiments/audit_mpc_aion_learning.py",
            "trustlessfl/fmnist.py","trustlessfl/private_bound.py","trustlessfl/fmnist_no_wrap_math.py",
            "trustlessfl/static_bound.py","trustlessfl/fmnist_no_wrap_app.py")},
        private_diagnostics="per-client norm and pass IDs are offline public-data diagnostics, never authorized live MPC outputs")
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n")
    for relative,expected in manifest["source_sha256"].items():
        data=(ROOT/relative).read_bytes()
        assert hashlib.sha256(data).hexdigest()==expected
        archived=output/"source-snapshot"/relative
        archived.parent.mkdir(parents=True,exist_ok=True); archived.write_bytes(data)
    all_cases=[]; first_hashes=[]
    started=time.perf_counter()
    for case in ("quantized-unfiltered","no-wrap-static"):
        weights=np.zeros(DIMENSION,dtype=np.float64)
        history=[dict(round=0,**test_model(weights,reference,test_x,test_y,device))]
        models=[weights.copy()]; sums=[]; counts=[]
        for r in range(1,rounds+1):
            p=base if case=="no-wrap-static" else replace(base,squared_bound=base.norm_cap)
            deltas=[]; integers=[]; meta=[]
            for i in range(4):
                trainer=FmnistTrainer(shards/f"client-{i}.npz",reference_path,seed=seed,
                    epochs=1,batch_size=64,device=device)
                delta=trainer(weights,i,cfg["learning-rate"],r)
                deltas.append(delta); integers.append(quantize(delta,S,B)); meta.append(trainer.meta)
            if r==1:
                first_hashes.append([hashlib.sha256(delta.tobytes()).hexdigest() for delta in deltas])
            norms=[sum(v*v for v in u) for u in integers]
            selected=[i for i,norm in enumerate(norms) if norm<=p.squared_bound]
            expected=(dict(status="ok",count=len(selected),sum=tuple(sum(integers[i][j] for i in selected)
                for j in range(DIMENSION))) if len(selected)>=p.minimum_accepted else dict(status="abort"))
            submissions=[]
            for i,u in enumerate(integers):
                h=hprf.hprf(i+1,r,DIMENSION)
                masks=tuple(scale_canonical_mask(v%hprf.p,hprf.p,p.mask_max) for v in h)
                submissions.append(ReferenceSubmission(p.encode(u,masks),masks))
            result=aggregate(p,submissions,mode="plaintext-reference")
            if result!=expected:
                raise AssertionError("offset/mask recovery differs from independent selected-sum oracle")
            before=weights.copy()
            if result["status"]=="ok":
                integer_sum=result["sum"]; count=result["count"]
                weights+=np.asarray(integer_sum,dtype=np.float64)/(S*count)
            else:
                integer_sum=(0,)*DIMENSION; count=0
            sums.append(np.asarray(integer_sum,dtype=np.int64)); counts.append(count); models.append(weights.copy())
            row=dict(round=r,status=result["status"],accepted_clients=selected,applied_count=count,
                threshold_squared_real=p.squared_bound/S**2,
                squared_norms_real=[n/S**2 for n in norms],
                max_abs_coordinate_real=[float(np.max(np.abs(d))) for d in deltas],
                max_quantization_error=max(float(np.max(np.abs(d-np.asarray(u)/S)))
                    for d,u in zip(deltas,integers)),
                applied_step_l2=float(np.linalg.norm(weights-before)),training_meta=meta,
                integer_oracle_matches=True,**test_model(weights,reference,test_x,test_y,device))
            history.append(row)
            print(json.dumps(dict(case=case,round=r,accuracy=row["accuracy"],accepted=selected,
                threshold=row["threshold_squared_real"],norms=row["squared_norms_real"])),flush=True)
        np.savez_compressed(output/f"{case}-models.npz",models=np.stack(models),
            integer_sums=np.stack(sums),applied_counts=np.asarray(counts))
        exclusions=[sum(i not in row["accepted_clients"] for row in history[1:]) for i in range(4)]
        all_cases.append(dict(case=case,history=history,excluded_client_rounds_by_client=exclusions,
            excluded_total=sum(exclusions),abort_rounds=[row["round"] for row in history[1:] if row["status"]=="abort"],
            final_accuracy=history[-1]["accuracy"]))
    if first_hashes[0]!=first_hashes[1]:
        raise AssertionError("same initial model did not produce identical honest first-round updates")
    result=dict(manifest=manifest,cases=all_cases,first_round_update_hashes_match=True,
        elapsed_seconds=time.perf_counter()-started,completed=True,native_mpc_run=False,
        malicious_clients=0,training_replies=8*rounds)
    (output/"results.json").write_text(json.dumps(result,indent=2,allow_nan=False)+"\n")
    print(json.dumps(dict(completed=True,output=str(output),seconds=result["elapsed_seconds"],
        cases=[{k:c[k] for k in ("case","final_accuracy","excluded_total","abort_rounds")} for c in all_cases])),flush=True)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run",type=Path,default=ROOT/".cache/fmnist-no-wrap/clean-4c-5r-20261010-v2")
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--rounds",type=int,default=10)
    parser.add_argument("--device",choices=("cuda:0","cpu"),default="cuda:0")
    parser.add_argument("--squared-threshold",type=int,help="frozen squared threshold in integer units; default 25*S*S")
    args=parser.parse_args()
    if not 1<=args.rounds<=100:
        raise ValueError("invalid rounds")
    run(args.source_run,args.output,rounds=args.rounds,device=args.device,squared_threshold=args.squared_threshold)


if __name__=="__main__":
    main()
