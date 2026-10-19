"""Sequential full-model experiments; keeps one Flower/Rep4 workload active."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wait-for',type=Path,required=True)
    parser.add_argument('--wait-pid',type=int,required=True)
    args=parser.parse_args()
    first=args.wait_for.resolve();deadline=time.monotonic()+7200
    while not (first/'verification.json').exists():
        if time.monotonic()>deadline:raise RuntimeError('first native experiment timed out')
        proc=Path('/proc')/str(args.wait_pid)
        try:argv=(proc/'cmdline').read_bytes().split(b'\0')
        except OSError:raise RuntimeError('first native experiment exited without verification')
        if b'experiments.run_seed_mpc_flower' not in argv:raise RuntimeError('first native experiment PID changed')
        time.sleep(1)
    while True:
        try:body=json.loads((first/'verification.json').read_text());break
        except json.JSONDecodeError:time.sleep(.1)
    assert body['passed']
    # The post-run verifier writes verification just before returning. Reap
    # the original harness before starting the next full workload.
    while (Path('/proc')/str(args.wait_pid)).exists():time.sleep(.1)
    runs=[first]
    env={**os.environ,'PATH':str(ROOT/'.venv/bin')+':/usr/local/bin:/usr/bin:/bin',
         'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1'}
    def archive():
        subprocess.run([sys.executable,'-m','experiments.export_seed_mpc_poisoning','--oracle',
            str(ROOT/'.cache/seed-mpc-experiments/poisoning-iid-v2-2026-10-11'),'--native',*map(str,runs),
            '--output',str(ROOT/'docs/reproduction/seed-mpc-security-experiments-2026-10-11')],
            cwd=ROOT,env=env,check=True)
    archive()
    for case in ('out-of-bound','clean'):
        output=ROOT/f'.cache/seed-mpc-experiments/native-sequential-{case}-2026-10-11'
        if output.exists():raise RuntimeError('fresh native session directory required')
        command=[sys.executable,'-u','-m','experiments.run_seed_mpc_flower','--output',str(output),
            '--mp-spdz-dir',str(ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-telemetry'),
            '--mode','fmnist-lenet5','--rounds','5','--timeout','1200','--collection-window-ms','600000',
            '--snapshot-version','2','--communication-meter','--test-poisoning',case]
        print('START_NATIVE_CASE',case,flush=True)
        with output.with_suffix('.log').open('x') as log:
            subprocess.run(command,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        assert json.loads((output/'verification.json').read_text())['passed']
        runs.append(output);print('VERIFIED_NATIVE_CASE',case,flush=True)
        archive()
    print('NATIVE_BATCH_COMPLETED',flush=True)


if __name__=='__main__':main()
