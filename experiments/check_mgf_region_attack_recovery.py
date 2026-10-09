"""Additional exact recovery ONLY for attack-inclusive design envelopes."""
import argparse
from fractions import Fraction
import json
from pathlib import Path
import time

import numpy as np

from experiments.audit_mgf_feasible_region import (codec_for, profile_manifest, make_vectors,
    check_aggregate,flat_rows)
from experiments.compare_mgf_scope import ROOT, dump, sha
from experiments.diagnose_mgf_fpr import load_inputs
from trustlessfl.source_profiles import scale_mask


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("artifact",type=Path)
    p.add_argument("--stream",action="store_true",help="read case checkpoints as the unchanged audit completes")
    args=p.parse_args();out=args.artifact
    cfg=json.loads((out/"config.json").read_text())
    prev,_,manifests,h,_=load_inputs(Path(cfg["previous"]))
    base=manifests["projection"];old=codec_for(base,h)
    with np.load(prev["frozen_updates_path"],allow_pickle=False) as a:
        clean=a["updates"][3].copy();malicious=a["malicious"].copy()
    mixed=clean.copy();mixed[:4]=malicious
    mixed_max=Fraction(str(float(np.abs(mixed).max())))
    quanta=[old.encode(x) for x in mixed]
    keys=cfg["public_keys"];raw=[h.hprf(k,4,base["dimension"]) for k in keys]
    def cases():
        for i in range(100):
            casefile=out/f"case_{i:03d}.json"
            deadline=time.monotonic()+3600
            while True:
                try:
                    yield json.loads(casefile.read_text())
                    break
                except (FileNotFoundError,json.JSONDecodeError):
                    if not args.stream or time.monotonic()>deadline:raise
                    time.sleep(.5)
    records=[];skipped=[];wire_audit=[]
    for case in cases():
        row=flat_rows([case])[0]
        n,C,M=row["nmax"],Fraction(row["C"]),row["M"]
        m=profile_manifest(base,n,C,M,"projection");codec=codec_for(m,h)
        masks=[[scale_mask(x,h.p,M) for x in hs] for hs in raw]
        offline_vectors=make_vectors(quanta,masks,codec.spacing)
        limit=codec.spacing*codec.max_integer;upper=limit+M+1
        violations={i:sum(not -limit<=y<=upper for y in offline_vectors[i]["masked_vector"])
                    for i in range(4)}
        wire_audit.append(dict(nmax=n,C=str(C),M=M,numeric_wire_limit=limit,
            numeric_wire_upper=upper,MR_clients_violating_wire=[i for i,count in violations.items() if count],
            coordinate_violations=violations,real_MR_in_C=mixed_max<=C,
            meaning="numeric subcheck of source check_vectors only; no signature/end-to-end claim"))
        if mixed_max>C:
            skipped.append(dict(nmax=n,C=str(C),M=M,reason="MR-outside-envelope; no correctness assertion"))
            continue
        # Same validated one-Y generator, not a new representation.
        vectors=[dict(sender=i,masked_vector=codec.mask(u,hs)) for i,(u,hs) in enumerate(zip(quanta,raw,strict=True))]
        assert vectors==offline_vectors
        checks=[check_aggregate(codec,h,keys,quanta,vectors,list(range(n)),4,
                                "MR-inclusive-capacity-fixture-NOT-MGF-selection")]
        # Actual eligible lists have already been independently computed by the
        # unchanged source selection; use only valid continuation results.
        for scope,v in case["attack"].items():
            current=v.get("current_policy",{})
            if current.get("continuation_if_wire_accepted"):
                assert current["valid_client_transmissions"]
                checks.append(check_aggregate(codec,h,keys,quanta,vectors,current["eligible"],4,
                                              "MR-inclusive-source-eligible-"+scope))
        records.append(dict(nmax=n,C=str(C),M=M,checks=checks))
        print(f"valid-MR envelope n={n} M={M}",flush=True)
    checks=[x for r in records for x in r["checks"]]
    dump(out/"MR_wire_bounds.json",wire_audit)
    dump(out/"attack_recovery.json",dict(records=records,skipped=skipped,
        aggregates=len(checks),coordinates=sum(x["coordinates"] for x in checks),
        mismatch=sum(x["mismatch"] for x in checks),
        max_E=max(x["E_max_observed"] for x in checks),
        min_capacity_margin=str(min(Fraction(x["capacity_margin"]) for x in checks)),
        generator="unchanged TransmissionCodec.mask; no out-of-C MR included",
        verifier_script_sha256=sha(__file__)))


if __name__=="__main__":main()
