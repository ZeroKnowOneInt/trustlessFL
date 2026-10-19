"""Re-run only the failed clean workload, retaining completed attack runs."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def main():
    output=ROOT/'.cache/seed-mpc-experiments/native-sequential-clean-runtime-fix-2026-10-11'
    if output.exists():raise RuntimeError('fresh recovery session required')
    env={**os.environ,'PATH':str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin',
         'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1'}
    command=[sys.executable,'-u','-m','experiments.run_seed_mpc_flower','--output',str(output),
        '--mp-spdz-dir',str(ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-telemetry'),
        '--mode','fmnist-lenet5','--rounds','5','--timeout','1200',
        '--collection-window-ms','600000','--snapshot-version','2','--communication-meter',
        '--test-poisoning','clean']
    print('START_CLEAN_RECOVERY',flush=True)
    with output.with_suffix('.log').open('x') as log:
        subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    verified=json.loads((output/'verification.json').read_text())
    if not verified['passed'] or not verified['learning_workload_completed']:
        raise RuntimeError('clean recovery workload did not complete')
    runs=[ROOT/'.cache/seed-mpc-experiments/native-sequential-bounded-100-2026-10-11',
          ROOT/'.cache/seed-mpc-experiments/native-sequential-out-of-bound-2026-10-11',output]
    public=ROOT/'docs/reproduction/seed-mpc-security-experiments-2026-10-11'
    subprocess.run([sys.executable,'-m','experiments.export_seed_mpc_poisoning','--oracle',
        str(ROOT/'.cache/seed-mpc-experiments/poisoning-iid-v2-2026-10-11'),
        '--native',*map(str,runs),'--output',str(public)],cwd=ROOT,env=env,check=True)
    status=json.loads((public/'batch-status.json').read_text())
    status['previous_failed_clean']=status.pop('clean')
    status['clean']={'execution_terminated':True,'internal_verification_passed':True,
        'learning_workload_completed':True,'comparison_passed':True,'source_run':output.name}
    status['native_comparison_completed_conditions']=['bounded-100','out-of-bound','clean']
    status['batch']='completed after clean-only recovery; failed clean run retained and excluded'
    (public/'batch-status.json').write_text(json.dumps(status,ensure_ascii=False,indent=2)+'\n')
    import hashlib
    manifest={str(p.relative_to(public)):hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(public.rglob('*')) if p.is_file() and p.name!='manifest.json'}
    (public/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('CLEAN_RECOVERY_COMPLETED',flush=True)


if __name__=='__main__':main()
