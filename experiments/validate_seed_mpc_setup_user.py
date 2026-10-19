"""Trusted standalone oracle for an installed wheel in a clean Linux container.

The runtime does not import this script. It reads only this test's synthetic data.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import numpy as np

from trustlessfl.crypto import canonical
from trustlessfl.seed_mpc_user import prepare,run
from trustlessfl.seed_mpc_session import load_deployment
from trustlessfl.seed_mpc_model import train_custom,evaluate_custom
from trustlessfl.seed_mpc_training import quantize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--installation',type=Path,required=True)
    parser.add_argument('--example-script',type=Path,required=True)
    parser.add_argument('--clients',type=int,default=8)
    args=parser.parse_args()
    root=args.output.resolve();root.mkdir(parents=True,exist_ok=False,mode=0o700)
    # PATH contains the image's official Flower CLI and CPU dependency runtime.
    subprocess.run([sys.executable,str(args.example_script),'--output',str(root/'data'),
                    '--clients',str(args.clients)],check=True)
    session=root/'session'
    prepare(session,args.installation,root/'data/model.json',clients=args.clients,rounds=2,
            collection_window_ms=30000,component_input='holder-checked-direct-v1',communication_meter=True)
    spawned=[]
    original_popen=subprocess.Popen
    def tracked_popen(*args,**kwargs):
        process=original_popen(*args,**kwargs);spawned.append(process);return process
    subprocess.Popen=tracked_popen
    try:
        summary=run(session)
    except Exception:
        print('Owned process exit codes:',[(p.pid,p.returncode) for p in spawned],flush=True)
        raise
    finally:subprocess.Popen=original_popen
    deployment,committee=load_deployment(session/'deployment.json')
    result=json.loads(next((session/'runtime-results').glob('run-*/results.json')).read_text())
    model=np.asarray(deployment['initial_model'],dtype=np.float64)
    checks=[]
    for r,record in enumerate(result['records'],1):
        rows=[]
        for slot in range(args.clients):
            with np.load(session/f'clients/C{slot}/train.npz',allow_pickle=False) as data:
                delta,_=train_custom(deployment['model_adapter'],model,data['x'],data['y'],slot=slot,
                    round_id=r,training=deployment['training'])
            row=quantize(delta,committee.policy)
            if all(abs(v)<=committee.policy.coordinate_cap for v in row) and sum(v*v for v in row)<=committee.policy.squared_threshold:rows.append(row)
        expected={'status':'ok','count':args.clients,'sum':[sum(row[j] for row in rows) for j in range(committee.policy.dimension)]}
        assert len(rows)==args.clients
        assert record['result_certificate']['body']['result']==expected
        assert record['manifest']['presence']==[1]*args.clients
        model=np.asarray(committee.next_model(model.tolist(),expected),dtype=np.float64)
        assert np.array_equal(model,np.asarray(result['models'][r],dtype=np.float64))
        with np.load(deployment['test_data'],allow_pickle=False) as data:
            metric=evaluate_custom(deployment['model_adapter'],model,data['x'],data['y'])
        assert metric==result['metrics'][r]
        checks.append({'round':r,'accepted':args.clients,'integer_sum_exact':True,'model_exact':True,'evaluation_exact':True})
    assert not list(session.glob('clients/*/audit/round-*.json'))
    assert summary['independent_retraining_verified'] is False
    report={'passed':True,'clients':args.clients,'aggregators':4,'dimension':committee.policy.dimension,
        'rounds':checks,'raw_audit_files':0,'native_source_build_manifest_sha256':deployment['backend_pin']['source_build_sha256'],
        'runtime_module':__import__('trustlessfl.seed_mpc_user',fromlist=['']).__file__,
        'compilation':deployment['compilation'],'communication':result['communication']['native'],
        'scope':'trusted synthetic oracle in one clean Ubuntu container; not operator isolation'}
    (root/'verification.json').write_bytes(canonical(report))
    print(json.dumps({'passed':True,'clients':args.clients,'rounds':2,'report':str(root/'verification.json')}),flush=True)


if __name__=='__main__':main()
