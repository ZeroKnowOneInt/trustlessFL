"""Export only public verification, circuit metadata and source snapshots; never client audits/seeds/data."""
import hashlib
import json
from pathlib import Path
import shutil
from trustlessfl.crypto import ProtocolError, canonical
from experiments.run_seed_mpc_flower import ROOT


def export(output):
    output=Path(output); output.mkdir(parents=True,exist_ok=False)
    validation=ROOT/'.cache/custom-model-validation-v2'
    summary=json.loads((validation/'verification.json').read_text())
    if not summary['passed']: raise ProtocolError('model validation incomplete')
    def copy(source,relative):
        target=output/relative; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(source,target)
    copy(validation/'verification.json','model-validation.json')
    directories=[(row['case'],validation/row['case']) for row in summary['cases']]
    directories += [('legacy-fixture',ROOT/'.cache/custom-legacy-fixture-regression-v1'),
                    ('tiny-fmnist',ROOT/'.cache/custom-tiny-fmnist-regression-v1')]
    comparison=[]
    for name,directory in directories:
        result=json.loads((directory/'verification.json').read_text())
        if not result['passed']: raise ProtocolError('regression incomplete')
        for filename in ('verification.json','provenance.json'):
            copy(directory/filename,Path(name)/filename)
        for filename in ('policy.json','compile-resource.txt'):
            copy(directory/'mpc'/filename,Path(name)/filename)
        native=result['communication']['native']
        comparison.append({'case':name,'dimension':result['dimension'],'rounds':result['rounds'],
            'passed':result['passed'],'compilation':result['compilation'],
            'round_checks':result['round_checks'],'metrics':result['metrics'],
            'native':{k:native[k] for k in ('definition','excluded','setup_sent_bytes','rounds','total_sent_bytes','reconciled')}})
    source=directories[0][1]
    provenance=json.loads((source/'provenance.json').read_text())
    for relative,expected in provenance['source_sha256'].items():
        saved=source/'sources'/relative
        if hashlib.sha256(saved.read_bytes()).hexdigest()!=expected: raise ProtocolError('archived source changed')
        copy(saved,Path('sources')/relative)
    for relative,expected in provenance['mpc_source_sha256'].items():
        saved=source/'mpc/Programs/Source'/relative
        if hashlib.sha256(saved.read_bytes()).hexdigest()!=expected: raise ProtocolError('archived MPC source changed')
        copy(saved,Path('mpc-source')/relative)
    deployment=json.loads((source/'deployment.json').read_text())
    plugin=Path(deployment['model_adapter']['plugin'])
    if hashlib.sha256(plugin.read_bytes()).hexdigest()!=deployment['model_adapter']['plugin_sha256']:
        raise ProtocolError('public model plugin changed')
    copy(plugin,'example/classifier.py')
    copy(ROOT/'experiments/prepare_seed_mpc_custom_example.py','example/prepare_seed_mpc_custom_example.py')
    copy(ROOT/'experiments/validate_seed_mpc_models.py','example/validate_seed_mpc_models.py')
    copy(ROOT/'.cache/custom-model-final-tests-v1.log','pytest.log')
    (output/'comparison.json').write_bytes(canonical({'passed':True,'cases':comparison,
        'scope':'public artifacts only; local trusted test oracle; no raw private updates, seeds, client data or private runtime state'}))
    manifest={p.relative_to(output).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(output.rglob('*')) if p.is_file()}
    (output/'manifest.json').write_bytes(canonical({'sha256':manifest,'files':len(manifest)}))
    return output


if __name__=='__main__':
    print(export(ROOT/'docs/reproduction/user-models-2026-10-11'))
