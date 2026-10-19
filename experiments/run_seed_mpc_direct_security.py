"""Sequential local direct-import fault matrix; no production security bypass."""
import argparse
import contextlib
import json
from pathlib import Path
from experiments.run_seeded_components_security import probe
from trustlessfl.seed_mpc_backend import sha
ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--resume',action='store_true')
    args=parser.parse_args();output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=args.resume)
    install=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1'
    matrix=[('component-equivocation',party) for party in range(4)]+[
        (fault,0) for fault in ('component-noncanonical','seed-equivocation',
          'native-digest-equivocation','native-status-equivocation','native-postcheck-share')]
    results=[]
    if args.resume:
        saved=json.loads((output/'verification.json').read_text())
        results=saved['cases']
        if len(results)>=len(matrix) or any(not r['passed'] for r in results):
            raise ValueError('invalid resume progress')
        for result,(fault,party) in zip(results,matrix):
            if result['fault']!=fault or result['fault_party']!=party:
                raise ValueError('resume matrix differs')
    for index,(fault,party) in enumerate(matrix):
        if index<len(results):continue
        label=f'{fault}-P{party}'
        if (output/label).exists():label+='-retry1'
        print(f'START {index+1}/{len(matrix)} {label}',flush=True)
        with (output/f'{label}-run.log').open('x') as log:
            with contextlib.redirect_stdout(log),contextlib.redirect_stderr(log):
                result=probe(output/label,install,fault,64,'holder-checked-direct-v1',party)
        results.append(result)
        print(f'PASS {label}',flush=True)
        record={'passed':len(results)==len(matrix),'cases':results,
            'source_sha256':sha(Path(__file__)),
            'native_initial_build':json.loads((output/'native-first-build.json').read_text()) if (output/'native-first-build.json').exists() else None,
            'native_final_build':json.loads((ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-direct-adversary-test/adversary-build.json').read_text()),
            'scope':'local bounded fault coverage including three native attacks; not a complete composition proof'}
        (output/'verification.json').write_text(json.dumps(record,indent=2)+'\n')

if __name__=='__main__':main()
