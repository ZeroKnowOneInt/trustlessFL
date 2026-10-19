"""Export checked public direct-import evidence; never private seed/update files."""
import argparse
import json
from pathlib import Path
import shutil
from experiments.export_seeded_components import ROOT,FIELDS,sha,write
from trustlessfl.crypto import ProtocolError

RUNS={'d65':('direct-import-d65-v1','verification.json'),
      'd1024':('direct-import-d1024-v1','verification.json'),
      'stock-d1024':('direct-stock-d1024-v1','verification.json'),
      'lenet':('direct-import-lenet-v1','verification.json'),
      'dropout':('direct-import-dropout-v2','verification.json'),
      'isolated':('direct-import-isolated-v1','public-fixture-verification.json')}


def export(output):
    checked={}
    for label,(name,filename) in RUNS.items():
        source=ROOT/'.cache'/name;path=source/filename
        value=json.loads(path.read_text())
        if not value.get('passed'):raise ProtocolError('failed required direct-import evidence')
        checked[label]=(source,path,value)
    matrix=ROOT/'.cache/direct-security-matrix-v1/verification.json'
    faults=json.loads(matrix.read_text())
    if not faults['passed'] or len(faults['cases'])!=9:raise ProtocolError('native fault matrix incomplete')
    current=checked['lenet'][2];baseline_path=ROOT/'.cache/public-packed-lenet-c64-v1/verification.json'
    baseline=json.loads(baseline_path.read_text())
    if (not baseline['passed'] or not current['learning_workload_completed']
            or baseline['metrics']!=current['metrics']
            or any(v['round_checks'][0]['presence']!=[1]*4 for v in (baseline,current))):
        raise ProtocolError('full-model learning comparison differs')
    original=json.loads((baseline_path.parent/'deployment.json').read_text())
    new=json.loads((checked['lenet'][0]/'deployment.json').read_text())
    for field in ('training','initial_model'):
        if original[field]!=new[field]:raise ProtocolError('learning contract differs')
    if original['committee']['policy']!=new['committee']['policy']:raise ProtocolError('policy differs')
    old_config=json.loads((baseline_path.parent/'mpc/policy.json').read_text())
    new_config=json.loads((checked['lenet'][0]/'mpc/policy.json').read_text())
    for field in ('chunk_blocks','public_agreement','mask_mode','round_slots','ring_bits','rep4_input_mode'):
        if old_config[field]!=new_config[field]:raise ProtocolError('arithmetic/packing contract differs')
    stock=checked['stock-d1024'];direct=checked['d1024']
    for field in ('backend_pin','training','initial_model'):
        left=json.loads((stock[0]/'deployment.json').read_text())[field]
        right=json.loads((direct[0]/'deployment.json').read_text())[field]
        if left!=right:raise ProtocolError('same-build comparison differs')
    old_rounds=[r['sent_bytes'] for r in stock[2]['communication']['native']['rounds']]
    direct_rounds=[r['sent_bytes'] for r in direct[2]['communication']['native']['rounds']]
    first=[v['communication']['native']['rounds'][0]['sent_bytes'] for v in (baseline,current)]
    comparison={'dimension':61706,'clients':4,'rounds':1,'metrics_identical':True,
        'versions':[{'name':name,'round_sent_bytes':first[i],
            'setup_sent_bytes':v['communication']['native']['setup_sent_bytes']}
            for i,(name,v) in enumerate(zip(('stock-packed','holder-checked-direct'),(baseline,current)))],
        'round_reduction_percent':100*(1-first[1]/first[0]),
        'stock_baseline_verification_sha256':sha(baseline_path),
        'same_build_d1024':{'stock_rounds':old_rounds,'direct_rounds':direct_rounds},
        'definition':'native Player sent payload sum across four aggregators, including live preprocessing; setup separated; excludes application/native framing/TLS/TCP/IP',
        'scope':'same full-model policy/data/training/packing; separate fresh sessions; native importer build differs; same-build stock/direct control at D1024; one learning round, not five-round completion or complete security proof'}
    output.mkdir(parents=True,exist_ok=False)
    for label,(source,path,result) in checked.items():
        summary={k:result[k] for k in FIELDS if k in result}
        summary['original_verification_sha256']=sha(path)
        if 'communication' in result:
            summary['communication']={k:result['communication'][k] for k in
                ('native','component_seed_provisioning','rpc_endpoint_counts_exact') if k in result['communication']}
        if 'isolation' in result:summary['isolation']={k:result['isolation'][k] for k in
            ('roles','cross_role_denials','own_file_readable','host_parent_pid_hidden','runtime')}
        if 'dropout_and_catchup_exact' in result:
            summary['dropout_and_catchup_exact']=result['dropout_and_catchup_exact']
            summary['all_client_ack_absence_progress']=result['all_client_ack_absence_progress']
        original_provenance=json.loads((source/'provenance.json').read_text())
        summary.update({k:original_provenance[k] for k in ('source_sha256','mpc_source_sha256','versions','scope')})
        config=json.loads((source/'mpc/policy.json').read_text())
        summary['native_settings']={k:config[k] for k in ('component_input','mask_mode','public_agreement','chunk_blocks','round_slots')}
        write(output/label/'summary.json',summary)
        for i in range(4):
            prefixes=('SEED_MPC_COMM ','SEED_MPC_COMM_FINAL ','SEED_MPC_COMM_GLOBAL ','SEED_MPC_CHECKED ',
                'SEED_MPC_REG_CHECKED','Time =','Time7 =','Time8 =','Data sent =','Global data sent =')
            lines=[line for line in (source/f'mpc/P{i}/native.log').read_text().splitlines() if line.startswith(prefixes)]
            (output/label/f'P{i}-counters.log').write_text('\n'.join(lines)+'\n')
    write(output/'faults/summary.json',faults)
    write(output/'comparison.json',comparison)
    install=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-direct-rep4-v1'
    write(output/'native-build.json',json.loads((install/'direct-build.json').read_text()))
    for relative in ('GC/Rep4Secret.cpp','GC/Rep4Secret.h','Processor/BaseMachine.cpp'):
        target=output/'native-source'/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(install/relative,target)
    for relative in ('mpc/Programs/Source','sources/trustlessfl','sources/experiments'):
        for f in (checked['lenet'][0]/relative).glob('*'):
            if f.suffix in ('.mpc','.py'):
                target=output/'lenet'/relative/f.name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(f,target)
    for relative in ('mpc/policy.json','provenance.json'):
        target=output/'lenet'/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(checked['lenet'][0]/relative,target)
    for relative in ('experiments/export_seed_mpc_direct.py','experiments/build_seed_mpc_direct.py',
        'experiments/build_seed_mpc_direct_adversary.py','experiments/run_seed_mpc_direct_security.py',
        'experiments/run_seeded_components_security.py','experiments/validate_seed_mpc_direct.py','tests/test_seed_mpc_backend.py'):
        target=output/'reproduction-sources'/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/relative,target)
    manifest={str(f.relative_to(output)):sha(f) for f in sorted(output.rglob('*')) if f.is_file()}
    write(output/'manifest.json',manifest)
    return {'exported_files':len(manifest),'comparison':comparison}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'docs/reproduction/direct-rep4-import-2026-10-11')
    args=parser.parse_args();print(json.dumps(export(args.output.resolve()),ensure_ascii=False,indent=2))
