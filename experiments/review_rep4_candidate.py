"""Sequential local native validation matrix; no full-model speed claim."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from experiments.run_seed_mpc_probe import run_probe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--output-directory',type=Path,required=True)
    parser.add_argument('--suite',choices=['all','functional','security'],default='all')
    args = parser.parse_args()
    args.output_directory.mkdir(parents=True,exist_ok=False)
    specs = [
        ('aes-known-answer', {'case':'aes'}),
        ('edges-16', {'case':'edge-cases'}),
        ('edges-32', {'case':'edge-cases','word_bits':32}),
        ('dimension-64', {'dimension':64}),
        ('nonboolean-2', {'case':'nonboolean','seed_encoding':'bits'}),
        ('nonboolean-high', {'case':'nonboolean-high','seed_encoding':'bits'}),
        ('equivocated-response', {'case':'equivocate'}),
        ('tampered-triple-frame', {'case':'tamper-triple'}),
    ]
    if args.suite == 'functional': specs = specs[:4]
    elif args.suite == 'security': specs = specs[4:]
    summary = {'scope':'synthetic local native Rep4, f=1 assumption; no Flower/BFT or formal composition proof',
               'runs':{},'log_sha256':{}}
    for name,options in specs:
        print('START '+name,flush=True)
        result = run_probe(args.mp_spdz_dir,backend='rep4',coordinate_circuit='binary',
                           communication_stats=True,**options)
        dest = args.output_directory/name
        dest.mkdir()
        (dest/'result.json').write_text(json.dumps(result,indent=2))
        workspace = Path(result['workspace'])
        paths = [('compile.log',workspace/'compile.log')]+[
            (f'P{i}.log',workspace/f'P{i}'/'native.log') for i in range(4)]+[
            (f'C{i}.log',workspace/f'C{i}'/'client.log') for i in range(4)]
        for target,source in paths:
            shutil.copyfile(source,dest/target)
            summary['log_sha256'][str(dest/target)] = hashlib.sha256(source.read_bytes()).hexdigest()
        summary['runs'][name] = {'passed':result['passed'],'output':result['output'],
                                'global_mb':result['global_data_sent_mb'],
                                'native_seconds':result['native_seconds'],
                                'compile_seconds':result['compile_seconds'],
                                'result':str(dest/'result.json')}
        (args.output_directory/'summary.json').write_text(json.dumps(summary,indent=2))
        print('PASS '+name+' '+json.dumps(summary['runs'][name]),flush=True)


if __name__=='__main__': main()
