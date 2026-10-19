"""Native chunk/compile-reuse checks with safe public result/log archives."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from experiments.run_seed_mpc_probe import run_probe


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--output-directory',type=Path,required=True)
    args=parser.parse_args()
    args.output_directory.mkdir(parents=True,exist_ok=False)
    summary={'scope':'local synthetic Rep4 chunks, public-file input; no Flower/BFT/composition proof',
             'runs':{},'log_sha256':{}}
    cached=None
    specs=[('partial-65','cross-chunk',65,16),
           ('changed-input-same-bytecode','alternate',65,16),
           ('public-disagreement','public-equivocate',65,16),
           ('public-highbit','public-highbit',65,16),
           ('noncanonical-wire','noncanonical-wire',65,16),
           ('nonzero-padding','nonzero-padding',65,16),
           ('replayed-round','replayed-round',65,16),
           ('dimension-1024','cross-chunk',1024,16),
           ('edges-32','edge-cases',65,32)]
    for name,case,dimension,word_bits in specs:
        print('START '+name,flush=True)
        result=run_probe(args.mp_spdz_dir,case=case,dimension=dimension,word_bits=word_bits,
                         backend='rep4',coordinate_circuit='chunked',communication_stats=True,
                         compiled_workspace=cached if dimension==65 and word_bits==16 else None)
        if cached is None: cached=result['workspace']
        dest=args.output_directory/name; dest.mkdir()
        (dest/'result.json').write_text(json.dumps(result,indent=2))
        workspace=Path(result['workspace'])
        for target,source in [('compile.log',workspace/'compile.log')]+[
                (f'P{i}.log',workspace/f'P{i}'/'native.log') for i in range(4)]+[
                (f'C{i}.log',workspace/f'C{i}'/'client.log') for i in range(4)]:
            shutil.copyfile(source,dest/target)
            summary['log_sha256'][str(dest/target)]=hashlib.sha256(source.read_bytes()).hexdigest()
        summary['runs'][name]={k:result[k] for k in ['passed','dimension','word_bits'] if k in result}
        summary['runs'][name].update({k:result[k] for k in
            ['global_data_sent_mb','compile_seconds','native_seconds','compile_invocations','compiled_artifact_hash']})
        summary['runs'][name]['result']=str(dest/'result.json')
        (args.output_directory/'summary.json').write_text(json.dumps(summary,indent=2))
        print('PASS '+name+' '+json.dumps(summary['runs'][name]),flush=True)


if __name__=='__main__': main()
