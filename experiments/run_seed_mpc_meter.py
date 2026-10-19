"""Reproduce exact communication accounting on fresh local native sessions.

Use a fresh --output. Public export is an explicit whitelist; client directories,
seed inputs, private signing/TLS keys, and raw-update audits are never copied.
"""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from experiments.run_seed_mpc_flower import stage,run,verify_run,sha
from trustlessfl.crypto import canonical


def reproduce(output):
    output=output.resolve(); output.mkdir(parents=True,exist_ok=False,mode=0o700)
    os.environ['PATH']=str(ROOT/'.venv/bin')+os.pathsep+os.environ['PATH']
    profiles=[('normal','fixture',3,2,60000,True),
              ('dropout','dropout-fixture',10,2,1000,True),
              ('tiny-fmnist','tiny-fmnist',3,2,60000,True),
              ('legacy-v1','fixture',3,1,60000,False)]
    runs={}
    for name,mode,rounds,version,window,meter in profiles:
        directory=output/name
        installation=ROOT/'.cache/private-bound-mpc'/('mp-spdz-0.4.3-telemetry' if meter else 'mp-spdz-0.4.3')
        stage(directory,installation,mode=mode,dimension=65,rounds=rounds,snapshot_version=version,
              collection_window_ms=window,communication_meter=meter)
        print('STAGED '+name,flush=True); run(directory)
        with contextlib.redirect_stdout(io.StringIO()): result=verify_run(directory)
        runs[name]=result
        public=output/'public'/name; public.mkdir(parents=True)
        for filename in ('verification.json','deployment.json','provenance.json','runtime-wall.json'):
            source=directory/filename
            if source.exists(): shutil.copyfile(source,public/filename)
        shutil.copyfile(next((directory/'runtime-results').glob('run-*/results.json')),public/'results.json')
        shutil.copytree(directory/'sources',public/'sources')
        shutil.copytree(directory/'mpc/Programs/Source',public/'mpc-source')
        if meter:
            for i in range(4):
                lines=(directory/f'mpc/P{i}/native.log').read_text().splitlines()
                checkpoints=[line for line in lines if line.startswith(('SEED_MPC_COMM ','SEED_MPC_COMM_FINAL ',
                    'SEED_MPC_COMM_GLOBAL ','SEED_MPC_REG_CHECKED','SEED_MPC_CHECKED '))]
                (public/f'native-checkpoints-P{i}.txt').write_text('\n'.join(checkpoints)+'\n')
            shutil.copyfile(installation/'telemetry-build.json',public/'telemetry-build.json')
        for p in directory.glob('attempt-*/run-status.json'):
            shutil.copyfile(p,public/'flower-run-status.json')
        print(json.dumps({'profile':name,'passed':result['passed'],
                          'total_native_sent_bytes':result.get('communication',{}).get('native',{}).get('total_sent_bytes')}),flush=True)
    summary={'scope':'local single-UID functional verification; application counters exclude unmeasured transport overhead',
             'runs':{name:{k:v for k,v in result.items() if k in ('passed','mode','dimension','snapshot_version','rounds',
                 'compile_seconds','wall_seconds','metrics','communication','round_checks','dropout_and_catchup_exact',
                 'verified_receipt_certificates','client_ack_required','seed_inputs_per_client')} for name,result in runs.items()},
             'runner_sha256':sha(Path(__file__))}
    (output/'public/summary.json').write_bytes(canonical(summary))
    public=output/'public'
    manifest={str(p.relative_to(public)):sha(p) for p in sorted(public.rglob('*')) if p.is_file()}
    (public/'sha256-manifest.json').write_bytes(canonical(manifest))
    print('PUBLIC_EXPORT '+str(public),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    reproduce(parser.parse_args().output)
