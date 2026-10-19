"""Export public optimization evidence; exclude seed packets and raw update audits."""
import argparse
import json
from pathlib import Path
import shutil
from trustlessfl.crypto import ProtocolError
from experiments.export_seeded_components import ROOT, FIELDS, sha, write

RUNS={
    'wire-open-lenet':('public-open-lenet-v1','verification.json'),
    'packed-lenet':('public-packed-lenet-c64-v1','verification.json'),
    'isolated-packed':('public-packed-isolated-v1','public-fixture-verification.json'),
    **{f'packed-fault-{f}':(f'public-packed-fault-{f}-v1','security-verification.json') for f in (
        'public-wire-highbit','public-nonzero-padding','component-equivocation')},
    **{f'packing-{b}':(f'public-packed-d1024-c{b}-v1','verification.json') for b in (4,16,64)},
    **{f'fault-{f}':(f'public-open-fault-{f}-v1','security-verification.json') for f in (
        'public-wire-lowbit','public-wire-highbit','public-tag-highbit','public-presence-highbit',
        'public-noncanonical-wire','public-nonzero-padding','registration-bind','seed-equivocation','component-equivocation')},
}


def export(output):
    checked={}
    for label,(name,filename) in RUNS.items():
        source=ROOT/'.cache'/name; path=source/filename
        if not path.exists(): raise ProtocolError(f'missing completed result: {label}')
        result=json.loads(path.read_text())
        if not result.get('passed'): raise ProtocolError(f'failed result: {label}')
        if label.endswith('lenet') and not result.get('learning_workload_completed'):
            raise ProtocolError('incomplete all-present learning')
        checked[label]=(source,path,result)
    # Same mathematical/training contract and exact metric equality are required.
    previous_path=ROOT/'.cache/seeded-components-lenet-final-v1/verification.json'
    previous=json.loads(previous_path.read_text())
    if not previous.get('passed'): raise ProtocolError('previous learning baseline failed')
    versions=[previous,checked['wire-open-lenet'][2],checked['packed-lenet'][2]]
    if any(v['metrics']!=previous['metrics'] or v['round_checks'][0]['presence']!=[1]*4 for v in versions):
        raise ProtocolError('full-model learning comparison differs')
    baseline_deployment=json.loads((previous_path.parent/'deployment.json').read_text())
    for label in ('wire-open-lenet','packed-lenet'):
        d=json.loads((checked[label][0]/'deployment.json').read_text())
        for field in ('training','initial_model','backend_pin'):
            if d[field]!=baseline_deployment[field]: raise ProtocolError('baseline training/backend differs')
        if d['committee']['policy']!=baseline_deployment['committee']['policy']:
            raise ProtocolError('baseline policy differs')
    output.mkdir(parents=True,exist_ok=False)
    for label,(source,path,result) in checked.items():
        summary={k:result[k] for k in (*FIELDS,'public_agreement') if k in result}
        summary['original_verification_sha256']=sha(path)
        if 'isolation' in result:
            summary['isolation']={k:result['isolation'][k] for k in
                ('roles','cross_role_denials','own_file_readable','host_parent_pid_hidden','runtime')}
        if 'communication' in result:
            c=result['communication']
            summary['communication']={k:c[k] for k in ('native','component_seed_provisioning','rpc_endpoint_counts_exact') if k in c}
        provenance=source/'provenance.json'
        if provenance.exists():
            original=json.loads(provenance.read_text())
            summary.update({k:original[k] for k in ('source_sha256','mpc_source_sha256','versions','scope')})
        deployment=source/'deployment.json'
        if deployment.exists():
            d=json.loads(deployment.read_text());summary['execution_hash']=d['committee']['execution_hash']
            summary['policy']=d['committee']['policy']
            config=json.loads((source/'mpc/policy.json').read_text())
            summary['native_settings']={k:config[k] for k in ('chunk_blocks','public_agreement','mask_mode','round_slots')}
        write(output/label/'summary.json',summary)
        for i in range(4):
            log=source/f'mpc/P{i}/native.log'
            if log.exists():
                prefixes=('SEED_MPC_COMM ','SEED_MPC_COMM_FINAL ','SEED_MPC_COMM_GLOBAL ',
                          'SEED_MPC_CHECKED ','SEED_MPC_REG_CHECKED','Time =','Time7 =','Time8 =',
                          'Data sent =','Global data sent =','Starting timer','Stopped timer')
                lines=[l for l in log.read_text().splitlines() if l.startswith(prefixes)]
                target=output/label/f'P{i}-counters.log';target.write_text('\n'.join(lines)+'\n')
        if label.endswith('lenet'):
            for relative in ('mpc/Programs/Source','sources/trustlessfl','sources/experiments'):
                for f in (source/relative).glob('*'):
                    if f.suffix in ('.mpc','.py'):
                        target=output/label/relative/f.name;target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(f,target)
            for relative in ('mpc/policy.json','provenance.json'):
                target=output/label/relative;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source/relative,target)
    first=[v['communication']['native']['rounds'][0]['sent_bytes'] for v in versions]
    comparison={
        'dimension':61706,'clients':4,'rounds':1,'presence':[1]*4,'metrics_identical':True,
        'baseline_verification_sha256':sha(previous_path),
        'versions':[{ 'name':name,'round_sent_bytes':first[i],
            'setup_sent_bytes':v['communication']['native']['setup_sent_bytes']}
            for i,(name,v) in enumerate(zip(('seeded-components','checked-public','checked-public-packed'),versions))],
        'public_comparison_reduction_percent':100*(1-first[1]/first[0]),
        'additional_packing_reduction_percent':100*(1-first[2]/first[1]),
        'combined_reduction_percent':100*(1-first[2]/first[0]),
        'definition':'native tracked Player sent payload sum over four aggregators, including live preprocessing; setup separated; excludes application, native framing and TLS/TCP/IP',
        'scope':'same D/N/Q/B/T/S/model/data/training/seed/round slots/backend; independent fresh sessions; chunk packing differs as stated; no generic performance/security proof'}
    write(output/'comparison.json',comparison)
    for relative in ('experiments/export_seed_mpc_public_packing.py','experiments/run_seeded_components_security.py',
                     'tests/test_seed_mpc_prss.py','tests/test_seed_mpc_flower.py'):
        target=output/'reproduction-sources'/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/relative,target)
    manifest={str(f.relative_to(output)):sha(f) for f in sorted(output.rglob('*')) if f.is_file() and f.name!='manifest.json'}
    write(output/'manifest.json',manifest)
    return {'exported_files':len(manifest),'comparison':comparison}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'docs/reproduction/public-packed-2026-10-11')
    args=parser.parse_args();print(json.dumps(export(args.output.resolve()),ensure_ascii=False,indent=2))
