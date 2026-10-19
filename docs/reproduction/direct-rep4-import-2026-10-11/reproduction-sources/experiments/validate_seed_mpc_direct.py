"""Sequential post-fault validation: one full learning round and small regressions."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--resume',action='store_true')
    options=parser.parse_args()
    matrix=json.loads((ROOT/'.cache/direct-security-matrix-v1/verification.json').read_text())
    if not matrix['passed'] or len(matrix['cases'])!=9:raise RuntimeError('complete native fault checks first')
    install='.cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1'
    common=['--mp-spdz-dir',install,'--snapshot-version','2','--communication-meter',
            '--chunk-blocks','64','--collection-window-ms','600000','--timeout','600']
    cases=[('direct-import-lenet-v1','experiments.run_seed_mpc_flower',
            [*common,'--component-input','holder-checked-direct-v1','--mode','fmnist-lenet5','--rounds','1']),
           ('direct-stock-d1024-v1','experiments.run_seed_mpc_flower',
            [*common,'--component-input','stock-private-v1','--mode','scale-fixture','--dimension','1024','--rounds','3']),
           ('direct-import-dropout-v2','experiments.run_seed_mpc_flower',
            [*[v if v!='600000' else '5000' for v in common],'--component-input','holder-checked-direct-v1','--mode','dropout-fixture','--dimension','65','--rounds','10']),
           ('direct-import-isolated-v1','experiments.run_seed_mpc_isolated',
            ['--mp-spdz-dir',install,'--component-input','holder-checked-direct-v1','--chunk-blocks','64'])]
    env={**os.environ,'PATH':str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin',
         'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1'}
    for name,module,args in cases:
        completed=ROOT/f'.cache/{name}/verification.json'
        if options.resume and completed.exists():
            if not json.loads(completed.read_text()).get('passed'):raise RuntimeError('failed completed verification')
            print('REUSE completed '+name,flush=True);continue
        print('START '+name,flush=True)
        with (ROOT/f'.cache/{name}-run.log').open('x') as log:
            subprocess.run([sys.executable,'-m',module,'--output',f'.cache/{name}',*args],
                cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        if module.endswith('isolated'):
            subprocess.run([sys.executable,'-m','experiments.verify_seed_mpc_isolated_fixture',
                '--output',f'.cache/{name}'],cwd=ROOT,env=env,check=True)
        print('PASS '+name,flush=True)
if __name__=='__main__':main()
