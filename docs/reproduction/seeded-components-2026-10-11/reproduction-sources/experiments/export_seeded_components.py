"""Export public counters, summaries and source snapshots; no client private files."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from trustlessfl.crypto import ProtocolError

ROOT=Path(__file__).resolve().parents[1]
RUNS={
    'full-shape-3r':('seeded-components-d61706-v1','verification.json'),
    'tiny-fmnist-final':('seeded-components-tiny-fmnist-v3','verification.json'),
    'lenet-final':('seeded-components-lenet-final-v1','verification.json'),
    'seed-fault-final':('seeded-components-final-seed-equivocation','security-verification.json'),
    'component-fault-final':('seeded-components-final-component-equivocation','security-verification.json'),
    'isolated-final':('seeded-components-isolated-final-v1','public-fixture-verification.json'),
}
FIELDS=('passed','protocol_correctness_passed','learning_workload_completed','runtime','mode','mask_mode',
        'dimension','rounds','round_checks','rows','metrics','compile_invocations','compile_seconds',
        'seed_inputs_per_client','internal_mb','native_resources','compile_resources','wall_seconds',
        'runtime_guard','fault','rejected_at','aggregate_outputs','result_checkpoints','raw_audits',
        'receipt_certificates','verified_receipt_certificates','scope')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def export(output):
    checked={}
    # Preflight every required result before creating a public artifact.
    for label,(name,filename) in RUNS.items():
        source=ROOT/'.cache'/name
        path=source/filename
        if not path.exists():raise ProtocolError(f'missing completed result: {label}')
        result=json.loads(path.read_text())
        if not result.get('passed'):raise ProtocolError(f'failed result: {label}')
        if label=='lenet-final' and not result.get('learning_workload_completed'):
            raise ProtocolError('full learning workload incomplete')
        checked[label]=(source,path,result)
    output.mkdir(parents=True,exist_ok=True)
    for label,(source,path,result) in checked.items():
        summary={k:result[k] for k in FIELDS if k in result}
        summary['original_verification_sha256']=sha(path)
        if 'communication' in result:
            communication=result['communication']
            summary['communication']={k:communication[k] for k in
                ('native','component_seed_provisioning','rpc_endpoint_counts_exact') if k in communication}
            external=communication.get('external_seed_input',{})
            summary['native_client_registration']={k:external[k] for k in
                ('definition','sent_bytes','received_bytes','seed_inputs_per_client') if k in external}
        if 'isolation' in result:
            summary['isolation']={k:result['isolation'][k] for k in
                ('roles','cross_role_denials','own_file_readable','host_parent_pid_hidden','runtime')}
        provenance=source/'provenance.json'
        if provenance.exists():
            original=json.loads(provenance.read_text())
            summary['source_sha256']=original['source_sha256']
            summary['mpc_source_sha256']=original['mpc_source_sha256']
            summary['versions']=original['versions']
            summary['scope']=original['scope']
        deployment=source/'deployment.json'
        if deployment.exists():
            d=json.loads(deployment.read_text())
            summary['execution_hash']=d['committee']['execution_hash']
            summary['mask_source_sha256']=d.get('mask_source_sha256')
            summary['policy']=d['committee']['policy']
        write(output/label/'summary.json',summary)
        for i in range(4):
            native=source/f'mpc/P{i}/native.log'
            if native.exists():
                prefixes=('SEED_MPC_COMM ','SEED_MPC_COMM_FINAL ','SEED_MPC_COMM_GLOBAL ',
                          'SEED_MPC_CHECKED ','SEED_MPC_REG_CHECKED','Time =','Time7 =','Time8 =',
                          'Data sent =','Global data sent =','Starting timer','Stopped timer')
                lines=[l for l in native.read_text().splitlines() if l.startswith(prefixes)]
                target=output/label/f'P{i}-counters.log';target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text('\n'.join(lines)+'\n')
        if label in ('full-shape-3r','lenet-final'):
            for directory,relative in ((source/'sources/trustlessfl','sources/trustlessfl'),
                                       (source/'mpc/Programs/Source','mpc-source')):
                for f in directory.glob('*.py'):
                    target=output/label/relative/f.name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,target)
                for f in directory.glob('*.mpc'):
                    target=output/label/relative/f.name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,target)
            for relative in ('mpc/policy.json','provenance.json'):
                f=source/relative
                if f.exists():
                    target=output/label/Path(relative).name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,target)
    baseline=ROOT/'docs/reproduction/seed-mpc-scale-2026-10-11/batched-61706/verification.json'
    old=json.loads(baseline.read_text())
    current=checked['full-shape-3r'][2]['communication']['native']
    comparison={'baseline_source':str(baseline.relative_to(ROOT)),
        'baseline_verification_sha256':sha(baseline),'baseline_dimension':old['dimension'],
        'baseline_rounds':old['rounds'],'baseline_global_mb':old['internal_mb'],
        'new_dimension':61706,'new_rounds':3,'new_global_sent_bytes':current['total_sent_bytes'],
        'new_setup_sent_bytes':current['setup_sent_bytes'],'new_rounds_sent_bytes':[r['sent_bytes'] for r in current['rounds']],
        'total_reduction_percent':100*(1-current['total_sent_bytes']/(old['internal_mb']*1e6)),
        'scope':'native MPC only, including live preprocessing; baseline total rounded; new v2 snapshot; third new fixture snapshot has one absent rejected slot; bootstrap payload counted separately',
        'benchmark_variant':'three-round shape benchmark precedes final registration-channel consolidation and local-source binding; final full LeNet one-round result verifies final implementation'}
    full_baseline=ROOT/'docs/reproduction/seed-mpc-security-experiments-2026-10-11/native/native-sequential-clean-runtime-fix-2026-10-11/verification.json'
    previous=json.loads(full_baseline.read_text())
    latest=checked['lenet-final'][2]
    previous_first=previous['communication']['native']['rounds'][0]['sent_bytes']
    latest_first=latest['communication']['native']['rounds'][0]['sent_bytes']
    if previous['metrics'][1]!=latest['metrics'][1]:
        raise ProtocolError('first-round full-model metrics differ from previous clean baseline')
    comparison['final_lenet_first_round']={'previous_source':str(full_baseline.relative_to(ROOT)),
        'previous_verification_sha256':sha(full_baseline),'previous_sent_bytes':previous_first,
        'new_sent_bytes':latest_first,'reduction_percent':100*(1-latest_first/previous_first),
        'previous_setup_sent_bytes':previous['communication']['native']['setup_sent_bytes'],
        'new_setup_sent_bytes':latest['communication']['native']['setup_sent_bytes'],
        'first_round_metrics_identical':True,'previous_compiled_round_slots':5,'new_compiled_round_slots':1,
        'presence':[1,1,1,1],'dimension':61706,'clients':4,'chunk_blocks':4,
        'scope':'first-round native counters incl. live preprocessing; identical public policy/model/data/seed/training; compilation loop budgets differ; excludes bootstrap ciphertext and application transport'}
    write(output/'comparison.json',comparison)
    for relative in ('experiments/run_seeded_components_security.py','experiments/export_seeded_components.py','tests/test_seed_mpc_prss.py'):
        target=output/'reproduction-sources'/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,target)
    manifest={str(f.relative_to(output)):sha(f) for f in sorted(output.rglob('*')) if f.is_file() and f.name!='manifest.json'}
    write(output/'manifest.json',manifest)
    return {'exported_files':len(manifest),'comparison':comparison}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'docs/reproduction/seeded-components-2026-10-11')
    args=parser.parse_args();print(json.dumps(export(args.output.resolve()),ensure_ascii=False,indent=2))
