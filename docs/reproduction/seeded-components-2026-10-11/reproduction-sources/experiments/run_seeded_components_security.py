"""Explicit local fault injection: no deployment bypass or production flags."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
from experiments.run_seed_mpc_flower import stage, run
from trustlessfl.crypto import ProtocolError, canonical, digest

ROOT=Path(__file__).resolve().parents[1]


def probe(output,installation,fault):
    stage(output,installation,mode='fixture',dimension=65,rounds=3,snapshot_version=2)
    if fault=='seed-equivocation':
        # A protocol-violating client signs a different seed replica for P0.
        # No private values are printed or included in the public report.
        from trustlessfl.crypto import Identity
        from trustlessfl.seed_mpc_prss import seed_packet
        directory=output/'clients/C0'
        private=json.loads((directory/'client.json').read_text())
        public=json.loads((directory/'public-registration.json').read_text())
        deployment=json.loads((output/'deployment.json').read_text())
        seeds=[bytes.fromhex(s) for s in private['component_seeds']]
        changed=bytearray(seeds[1]); changed[0] ^= 1; seeds[1]=bytes(changed)
        packet=seed_packet(Identity.from_private(private['identity']),seeds,public['envelope']['body'],0,
                           deployment['committee']['registry']['A0'])
        path=output/'mpc/P0/seed-packets/C0.json'
        path.write_bytes(canonical(packet)); path.chmod(0o600)
    original=subprocess.Popen
    injected=False
    def start(command,*args,**kwargs):
        nonlocal injected
        if (fault=='component-equivocation' and isinstance(command,list)
                and 'trustlessfl.seed_mpc_service' in command and command[-1]=='0'):
            # The malicious holder changes one component input; stock active input
            # still authenticates its chosen value. The circuit must detect that
            # this value differs from the other two holders' copies.
            body="from trustlessfl import seed_mpc_service as s; orig=s.private_round_words\ndef bad(*a,**k):\n for j,v in enumerate(orig(*a,**k)):\n  yield (v ^ 1) if j==0 else v\ns.private_round_words=bad; s.main()"
            index=command.index('trustlessfl.seed_mpc_service')
            command=[command[0],'-c',body,*command[index+1:]]
            injected=True
        return original(command,*args,**kwargs)
    failure=None
    try:
        with patch('subprocess.Popen',side_effect=start): run(output)
    except (ProtocolError,RuntimeError,subprocess.CalledProcessError) as exc:
        failure=type(exc).__name__
    if failure is None or fault=='component-equivocation' and not injected:
        raise ProtocolError('fault was not injected/rejected')
    expected=('inconsistent component seed registration' if fault=='seed-equivocation'
              else 'inconsistent local mask components')
    logs=[(output/f'mpc/P{i}/native.log').read_text() for i in range(4)]
    if not any(expected in log for log in logs):
        raise ProtocolError('expected native rejection not observed')
    if any('SEED_MPC_PUBLIC ' in log or 'SEED_MPC_CHECKED ' in log for log in logs):
        raise ProtocolError('fault produced pending aggregate output')
    import sqlite3
    for i in range(4):
        connection=sqlite3.connect(output/f'mpc/P{i}/rounds.sqlite')
        try:
            if connection.execute('SELECT round FROM head WHERE id=1').fetchone()[0]!=0:
                raise ProtocolError('fault advanced certified model')
            if connection.execute("SELECT COUNT(*) FROM rounds WHERE result_body IS NOT NULL OR result_vote IS NOT NULL OR certificate IS NOT NULL").fetchone()[0]:
                raise ProtocolError('fault produced a result vote/certificate')
        finally: connection.close()
    report={'passed':True,'fault':fault,'rejected_at':expected,'aggregate_outputs':0,
            'result_checkpoints':0,'mask_mode':'rep4-seeded-components-v1',
            'scope':'local input fault injection; no complete malicious-protocol/composition proof'}
    (output/'security-verification.json').write_bytes(canonical(report))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mp-spdz-dir',type=Path,default=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-telemetry')
    parser.add_argument('--fault',choices=['seed-equivocation','component-equivocation'],required=True)
    args=parser.parse_args()
    print(json.dumps(probe(args.output.resolve(),args.mp_spdz_dir.resolve(),args.fault),indent=2))


if __name__=='__main__': main()
