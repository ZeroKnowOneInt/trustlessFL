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


def probe(output,installation,fault,chunk_blocks=None):
    stage(output,installation,mode='fixture',dimension=65,rounds=3,snapshot_version=2,chunk_blocks=chunk_blocks)
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
    if fault=='registration-bind':
        path=output/'clients/C0/seed-input.json'
        private=json.loads(path.read_text())
        private['registration_digest']=('ff' if private['registration_digest'][:2]!='ff' else '00')+private['registration_digest'][2:]
        path.write_bytes(canonical(private))
    public_faults={
        'public-wire-lowbit':(10,1), 'public-wire-highbit':(10,1<<63),
        'public-tag-highbit':(2,1<<63), 'public-presence-highbit':(6,1<<32)}
    common_faults={'public-noncanonical-wire':(10,65536),'public-nonzero-padding':(75,1)}
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
        elif (isinstance(command,list) and 'trustlessfl.seed_mpc_service' in command
              and (fault in common_faults or fault in public_faults and command[-1]=='0')):
            offset,value=(common_faults if fault in common_faults else public_faults)[fault]
            operation='=' if fault in common_faults else '^='
            body=("from trustlessfl import seed_mpc_service as s; from trustlessfl.seed_mpc_committee import SeedCommittee; "
                  "orig=SeedCommittee.runtime_round\ndef bad(self,*a,**k):\n values=orig(self,*a,**k)\n "
                  f"values[{offset}]{operation}{value}\n return values\nSeedCommittee.runtime_round=bad; s.main()")
            index=command.index('trustlessfl.seed_mpc_service')
            command=[command[0],'-c',body,*command[index+1:]]
            injected=True
        return original(command,*args,**kwargs)
    failure=None
    try:
        with patch('subprocess.Popen',side_effect=start): run(output)
    except (ProtocolError,RuntimeError,subprocess.CalledProcessError) as exc:
        failure=type(exc).__name__
    if failure is None or fault in ('component-equivocation',*public_faults,*common_faults) and not injected:
        raise ProtocolError('fault was not injected/rejected')
    expected={
        'seed-equivocation':'inconsistent component seed registration',
        'component-equivocation':'inconsistent local mask components',
        'registration-bind':'registration handle binding differs',
        'public-noncanonical-wire':'noncanonical public wire',
        'public-nonzero-padding':'nonzero public padding',
        **{f:'inconsistent public chunk' for f in public_faults}}[fault]
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
            'public_agreement':'checked-open-v1',
            'chunk_blocks':json.loads((output/'mpc/policy.json').read_text())['chunk_blocks'],
            'scope':'local input fault injection; no complete malicious-protocol/composition proof'}
    (output/'security-verification.json').write_bytes(canonical(report))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mp-spdz-dir',type=Path,default=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-telemetry')
    parser.add_argument('--fault',choices=['seed-equivocation','component-equivocation','registration-bind','public-wire-lowbit',
        'public-wire-highbit','public-tag-highbit','public-presence-highbit','public-noncanonical-wire','public-nonzero-padding'],required=True)
    parser.add_argument('--chunk-blocks',type=int)
    args=parser.parse_args()
    print(json.dumps(probe(args.output.resolve(),args.mp_spdz_dir.resolve(),args.fault,args.chunk_blocks),indent=2))


if __name__=='__main__': main()
