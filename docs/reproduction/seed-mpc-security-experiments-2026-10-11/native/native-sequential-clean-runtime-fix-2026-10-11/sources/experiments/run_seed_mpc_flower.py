"""Local official Flower + four separately owned Rep4 services.

Bootstrap and post-run oracle are trusted test harnesses; ServerApp never
receives seeds, signing keys or raw updates. No Hub/deployment publishing.
"""
import argparse
from dataclasses import asdict
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import tomllib
import uuid

import numpy as np
import tomli_w

from experiments.prepare_fashion_mnist import prepare
from experiments.run_fmnist_flower import read_dataset
from experiments.run_endpoint_flower import run as flower_run
from experiments.run_private_bound_mpc import configure_tls,free_port_base,write_private
from experiments.run_seed_mpc_probe import circuit_bytes,CIRCUIT_SHA256
from trustlessfl.crypto import Identity,ProtocolError,canonical,digest
from trustlessfl.seed_mpc_committee import CoordinatorState
from trustlessfl.seed_mpc_policy import SeedMPCPolicy
from trustlessfl.seed_mpc_session import load_deployment,rpc
from trustlessfl.seed_mpc_training import DIMENSION,LENET_DIMENSION,initial_lenet,train,quantize,evaluate,evaluate_lenet,fixture_update,scale_fixture_update,dropout_fixture_update,dropout_test_schedule
from trustlessfl.seed_mpc_resources import read_resources
from trustlessfl.seed_mpc_backend import pin_backend
from trustlessfl.seed_mpc_meter import native_partition,global_partition
from trustlessfl.seed_mpc_isolation import RoleSandbox
from trustlessfl.seed_mpc_flower_runtime import learning_workload_completed

ROOT=Path(__file__).resolve().parents[1]


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path,value):
    with Path(path).open('xb') as stream: stream.write(canonical(value))


def stage(output,installation,*,mode='tiny-fmnist',dimension=65,rounds=3,rows=256,seed=42,fault=None,timeout=180,
          snapshot_version=1,collection_window_ms=60000,communication_meter=False,
          test_audit=True,role_isolation=False,test_poisoning=None):
    if type(test_audit) is not bool or type(role_isolation) is not bool: raise ProtocolError('invalid isolation/audit mode')
    if test_poisoning not in (None,'clean','out-of-bound','sign-flip','bounded-50','bounded-100','label-flip'):
        raise ProtocolError('invalid test poisoning condition')
    if test_poisoning and mode!='fmnist-lenet5': raise ProtocolError('poisoning test requires full LeNet5')
    if type(communication_meter) is not bool: raise ProtocolError('invalid communication meter')
    if type(snapshot_version) is not int or snapshot_version not in (1,2): raise ProtocolError('invalid snapshot version')
    if type(collection_window_ms) is not int or not 1<=collection_window_ms<=3600000: raise ProtocolError('invalid collection window')
    if mode not in ('fixture','scale-fixture','dropout-fixture','tiny-fmnist','fmnist-lenet5') or not 1<=rounds<=20 or rows<32: raise ProtocolError('invalid workload')
    if mode=='dropout-fixture' and (snapshot_version!=2 or dimension<33): raise ProtocolError('dropout fixture requires v2 and multiple chunks')
    if mode in ('fixture','scale-fixture') and rounds!=3: raise ProtocolError('fixture requires three rounds')
    if mode=='tiny-fmnist': dimension=DIMENSION
    if mode=='fmnist-lenet5': dimension=LENET_DIMENSION
    if not 2<=dimension<=61706 or mode=='scale-fixture' and dimension<256: raise ProtocolError('invalid dimension')
    if type(timeout) is not int or not 180<=timeout<=3600: raise ProtocolError('invalid timeout')
    if fault not in (None,'uncertified-model'): raise ProtocolError('invalid test fault')
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    workspace=output/'mpc'; workspace.mkdir()
    installation=installation.resolve(); binary=installation/'rep4-ring-party.x'
    backend_pin=pin_backend(installation)
    if communication_meter and not backend_pin['applied_patches']:
        raise ProtocolError('communication meter requires explicitly pinned observer build')
    policy=SeedMPCPolicy(dimension,4,20000,400000000 if mode=='fixture' else 2500000000,
                         scale=1 if mode in ('fixture','dropout-fixture') else 10000)
    policy.validate_ring(64)
    party_port=free_port_base(4); client_port=free_port_base(4)
    while abs(party_port-client_port)<8: client_port=free_port_base(4)
    config={**asdict(policy),'clients':4,'parties':4,'backend':'rep4','ring_bits':64,
        'backend_prime':1<<64,'domain_modulus':1<<64,'seed_encoding':'packed64','rep4_input_mode':'replicated-triples-v1',
        'output_mode':'native-public','output_length':0,'coordinate_circuit':'chunked','chunk_blocks':4,
        'round_slots':rounds,'widths':policy.widths(),'client_port':client_port,'certified_stream':True,
        'backend_pin_hash':digest(backend_pin),'snapshot_version':snapshot_version,
        'collection_window_ms':collection_window_ms,**({'communication_meter':True} if communication_meter else {})}
    write(workspace/'policy.json',config)
    sources={}; source=workspace/'Programs/Source'; source.mkdir(parents=True)
    for name in ['seed_mpc_chunked_session.mpc','seed_mpc_candidate_primitives.py','seed_mpc_primitives.py']:
        shutil.copyfile(ROOT/'mpc/Programs/Source'/name,source/name); sources[name]=sha(source/name)
    circuits=workspace/'Programs/Circuits'; circuits.mkdir(); (circuits/'aes_128.txt').write_bytes(circuit_bytes(installation))
    started=time.monotonic()
    with (workspace/'compile.log').open('x') as log:
        subprocess.run(['/usr/bin/time','-v','-o',str(workspace/'compile-resource.txt'),
            sys.executable,str(installation/'compile.py'),'-R','64','-Z','4','-M',
            'seed_mpc_chunked_session','policy.json'],cwd=workspace,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
    compile_seconds=round(time.monotonic()-started,3)
    artifacts={str(p.relative_to(workspace/'Programs')):sha(p) for folder in ['Bytecode','Schedules']
               for p in (workspace/'Programs'/folder).rglob('*') if p.is_file()}
    execution_hash=digest({'artifacts':artifacts,'binary':sha(binary),'aes':CIRCUIT_SHA256,'sources':sources,'config':config,
                           'backend_pin':digest(backend_pin)})
    actors=configure_tls(workspace,4,4)
    client_root=output/'clients'; client_root.mkdir(mode=0o700)
    preparation={'session_id':uuid.uuid4().hex,'policy_hash':policy.policy_hash,
        'execution_hash':execution_hash,'installation':str(installation),'snapshot_version':snapshot_version}
    write(output/'client-preparation.json',preparation)
    env={**os.environ,'PYTHONPATH':str(ROOT),'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1'}
    registry={}; registrations=[]
    for i in range(4):
        directory=client_root/f'C{i}'
        command=[sys.executable,'-m','trustlessfl.seed_mpc_client_app','--directory',str(directory),
            '--preparation',str(output/'client-preparation.json'),'--slot',str(i),
            *(['--trusted-test-audit'] if test_audit else [])]
        if role_isolation: command=RoleSandbox(output,f'C{i}').command(command)
        subprocess.run(command,env=env,check=True,timeout=30)
        public=json.loads((directory/'public-registration.json').read_text())
        registry[f'C{i}']=public['public']; registrations.append(public['envelope'])
        (directory/'Player-Data').symlink_to(actors[f'C{i}']/'Player-Data',target_is_directory=True)
    private_aggregators=[]
    for i in range(4):
        identity=Identity.generate(f'A{i}'); registry[identity.name]=identity.public()
        private_aggregators.append({'identity':identity.private(),'actor':str(actors[f'P{i}'])})
    services=[]
    for _ in range(4):
        port=free_port_base(1)
        while f'http://127.0.0.1:{port}' in services or min(abs(port-party_port),abs(port-client_port))<8:
            port=free_port_base(1)
        services.append(f'http://127.0.0.1:{port}')
    training={'mode':mode,'seed':seed,'epochs':1,'batch_size':64,'learning_rate':.05}
    initial_model=[0.0]*dimension
    if mode=='fmnist-lenet5':
        training.update(learning_rate=.01,momentum=.9,weight_decay=.0005,device='cpu',
                        normalization={'mean':.1307,'std':.3081})
        initial_model=initial_lenet(seed).tolist()
        if test_poisoning: training['test_poisoning']={'case':test_poisoning,'malicious_slots':[0]}
    data_records={}
    if mode in ('tiny-fmnist','fmnist-lenet5'):
        data_root=ROOT/'.cache/fashion-mnist'; dataset=prepare(data_root,download=True)
        data=read_dataset(data_root/'FashionMNIST/raw')
        order=np.random.default_rng(seed).permutation(len(data['train_y']))
        for i,indices in enumerate(np.array_split(order,4)):
            selected=indices if mode=='fmnist-lenet5' else indices[:rows]; path=client_root/f'C{i}/train.npz'
            np.savez_compressed(path,x=data['train_x'][selected],y=data['train_y'][selected]); path.chmod(0o600)
            data_records[f'C{i}']={'rows':len(selected),'sha256':sha(path),
                'indices_sha256':hashlib.sha256(selected.astype('<i8').tobytes()).hexdigest(),
                'class_counts':np.bincount(data['train_y'][selected],minlength=10).tolist()}
        test_rows=10000 if mode=='fmnist-lenet5' else 1024
        test=output/'public-test.npz'; np.savez_compressed(test,x=data['test_x'][:test_rows],y=data['test_y'][:test_rows])
        data_records['test']={'rows':test_rows,'sha256':sha(test)}
        write(output/'dataset.json',dataset)
    else: test=None
    deployment={'protocol':'seed-mpc-local-deployment-v1','workspace':str(workspace),'native_binary':str(binary),
        'backend_pin':backend_pin,**({'communication_meter':True} if communication_meter else {}),
        'trusted_test_audit':test_audit,'role_isolation':role_isolation,
        'binary_sha256':sha(binary),'aes_sha256':CIRCUIT_SHA256,'config_sha256':sha(workspace/'policy.json'),
        'artifacts':artifacts,'program':'seed_mpc_chunked_session-policy.json','party_port':party_port,
        'services':services,'timeout':timeout,'rounds':rounds,'training':training,'initial_model':initial_model,
        'test_data':str(test) if test else None,'test_fault':fault,
        'committee':{'policy':asdict(policy),'session_id':preparation['session_id'],'epoch':1,
            'snapshot_version':snapshot_version,'collection_window_ms':collection_window_ms,
            'clients':[f'C{i}' for i in range(4)],'aggregators':[f'A{i}' for i in range(4)],
            'registry':registry,'registrations':registrations,'execution_hash':execution_hash}}
    if mode=='dropout-fixture': deployment['test_dropout_schedule']=dropout_test_schedule()
    write(output/'deployment.json',deployment)
    for i,private in enumerate(private_aggregators):
        private['deployment_sha256']=sha(output/'deployment.json')
        write_private(actors[f'P{i}']/'service-private.json',canonical(private))
    for i in range(4):
        command=[sys.executable,'-m','trustlessfl.seed_mpc_client_app','--directory',str(client_root/f'C{i}'),
            '--pin',str(output/'deployment.json')]
        if role_isolation: command=RoleSandbox(output,f'C{i}').command(command)
        subprocess.run(command,env=env,check=True,timeout=30)
    app=output/'app'; shutil.copytree(ROOT/'trustlessfl',app/'trustlessfl',ignore=shutil.ignore_patterns('__pycache__'))
    flower=tomllib.loads((ROOT/'configs/endpoint/flower-pyproject.toml').read_text())
    flower['project'].update(name='trustlessfl-seed-mpc-local',description='Local certified seed-MPC transport integration')
    flower['project']['dependencies'] += ['cryptography>=46.0.7,<47',f"torch=={importlib.metadata.version('torch')}"]
    flower['tool']['flwr']['app']['components']={'serverapp':'trustlessfl.seed_mpc_server_app:app','clientapp':'trustlessfl.seed_mpc_client_app:app'}
    flower['tool']['flwr']['app']['config']={'deployment-file':str(output/'deployment.json'),
        'output-dir':str(output/'runtime-results'),'num-clients':4,'backend':'numpy','simulation-workers':1,
        'seed-mpc-runtime-guard':True,
        'seed-mpc-runtime-guard-sha256':sha(ROOT/'trustlessfl/seed_mpc_flower_runtime.py'),
        'runtime-cli-timeout':max(900,timeout*rounds+600)}
    (app/'pyproject.toml').write_text(tomli_w.dumps(flower))
    source_files=['trustlessfl/seed_mpc_session.py','trustlessfl/seed_mpc_service.py','trustlessfl/seed_mpc_client_app.py',
        'trustlessfl/seed_mpc_backend.py','trustlessfl/seed_mpc_telemetry_patch.py','trustlessfl/seed_mpc_meter.py','trustlessfl/seed_mpc_isolation.py',
        'trustlessfl/seed_mpc_dropout.py','trustlessfl/seed_mpc_flower_runtime.py',
        'trustlessfl/seed_mpc_server_app.py','trustlessfl/seed_mpc_training.py','trustlessfl/seed_mpc_committee.py',
        'trustlessfl/seed_mpc_poisoning_fixture.py',
        'trustlessfl/seed_mpc_ledger.py','trustlessfl/seed_mpc_native.py','trustlessfl/seed_mpc_external_client.py',
        'trustlessfl/crypto.py','trustlessfl/seed_mpc_policy.py','trustlessfl/seed_mpc_wire.py','trustlessfl/rep4_external.py',
        'trustlessfl/seed_mpc_resources.py','trustlessfl/fmnist.py',
        'experiments/run_seed_mpc_flower.py','experiments/run_endpoint_flower.py']
    source_archive=output/'sources'
    for relative in source_files:
        target=source_archive/relative; target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/relative,target)
    write(output/'provenance.json',{'source_sha256':{p:sha(ROOT/p) for p in source_files},'mpc_source_sha256':sources,
        'compile_seconds':compile_seconds,'compile_invocations':1,'data':data_records,
        'compile_resources':read_resources(workspace/'compile-resource.txt'),
        'versions':{p:importlib.metadata.version(p) for p in ('flwr','ray','numpy','torch','cryptography')},
        'scope':('local bubblewrap role filesystem/PID isolation; client seed provisioning in own namespace; trusted host bootstrap/admin; no composition proof'
                 if role_isolation else 'single WSL host/Unix UID, trusted local test bootstrap and post-run raw-update oracle; no operator isolation'),
        'model':('LeNet5 FMNIST, 61706 parameters, full IID training/test dataset' if mode=='fmnist-lenet5' else
                 '16-feature, 10-class FMNIST linear classifier, 170 parameters' if mode=='tiny-fmnist' else 'public adversarial synthetic fixture')})
    return deployment


def run(output):
    deployment,committee=load_deployment(output/'deployment.json'); processes=[]; logs=[]
    harness_started=time.monotonic()
    environment={**os.environ,'PYTHONPATH':str(ROOT),'TRUSTLESSFL_SEED_CLIENT_ROOT':str(output/'clients'),
                 'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1'}
    try:
        for i in range(4):
            actor=Path(deployment['workspace'])/f'P{i}'; log=(actor/'service.log').open('x'); logs.append(log)
            processes.append(subprocess.Popen([sys.executable,'-m','trustlessfl.seed_mpc_service','--deployment',str(output/'deployment.json'),
                '--private',str(actor/'service-private.json'),'--slot',str(i)],cwd=ROOT,env=environment,
                stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        deadline=time.monotonic()+30
        for i,url in enumerate(deployment['services']):
            while True:
                if processes[i].poll() is not None: raise ProtocolError('aggregator startup failed')
                try: rpc(url,'head',timeout=1); break
                except ProtocolError:
                    if time.monotonic()>deadline: raise ProtocolError('aggregator startup timeout')
                    time.sleep(.1)
        old=os.environ.get('TRUSTLESSFL_SEED_CLIENT_ROOT'); os.environ['TRUSTLESSFL_SEED_CLIENT_ROOT']=str(output/'clients')
        try:
            try: flower_run(output)
            except (RuntimeError,subprocess.CalledProcessError):
                if deployment.get('test_fault')!='uncertified-model': raise
                statuses=list(output.glob('attempt-*/run-status.json'))
                if len(statuses)!=1 or json.loads(statuses[0].read_text())['runs'][0]['status']!='finished:failed': raise
            else:
                if deployment.get('test_fault'): raise ProtocolError('injected Flower fault accepted')
        finally:
            if old is None: os.environ.pop('TRUSTLESSFL_SEED_CLIENT_ROOT',None)
            else: os.environ['TRUSTLESSFL_SEED_CLIENT_ROOT']=old
    finally:
        for process in processes:
            if process.poll() is None: os.killpg(process.pid,signal.SIGTERM)
        for process in processes:
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); process.wait()
        for log in logs: log.close()
        # Registration helpers are started by ClientApp. Stop only processes
        # whose current command line names this run's exact private-input file.
        for i in range(4):
            marker=output/f'clients/C{i}/registration-process.json'
            if not marker.exists(): continue
            pid=json.loads(marker.read_text()).get('pid')
            if type(pid) is not int or pid<=1: continue
            try:
                args=(Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0')
                expected=str(output/f'clients/C{i}/seed-input.json').encode()
                if b'trustlessfl.seed_mpc_external_client' in args and expected in args and os.getpgid(pid)==pid:
                    os.killpg(pid,signal.SIGTERM)
            except (FileNotFoundError,ProcessLookupError): pass
        if deployment.get('communication_meter'):
            write(output/'runtime-wall.json',{'scope':'local harness service startup + official Flower CLI run + owned-process cleanup; excludes stage/compile and post-run oracle',
                                             'seconds':time.monotonic()-harness_started})


def verify_collection_receipts(committee,records,collections):
    """Independently bind each public receipt QC to the complete selected input."""
    if committee.snapshot_version==1:
        if collections: raise ProtocolError('v1 has unexpected collection receipts')
        return 0
    if not isinstance(collections,list) or len(collections)!=len(records):
        raise ProtocolError('incomplete collection receipt sequence')
    verified=0
    for record,entry in zip(records,collections,strict=True):
        manifest=record['manifest']; context=committee.check_manifest(manifest)
        if (not isinstance(entry,dict) or set(entry)!= {'round','certificates'}
                or type(entry['round']) is not int or entry['round']!=context.round_id):
            raise ProtocolError('receipt round differs')
        present=[name for name,flag in zip(committee.clients,manifest['presence'],strict=True) if flag]
        proofs=entry['certificates']
        if not isinstance(proofs,list) or len(proofs)!=len(present):
            raise ProtocolError('receipt certificate missing or duplicated')
        for name,proof in zip(present,proofs,strict=True):
            packets=[p for p in manifest['inputs'] if p['sender']==name]
            submission=committee.submission(context,manifest['parent_decision'],name,packets)
            committee.check_receipt_certificate(submission,proof); verified+=1
    return verified


def verify_communication(output,deployment,body):
    workspace=Path(deployment['workspace'])
    native=global_partition([native_partition((workspace/f'P{i}/native.log').read_text(),deployment['rounds'])
                             for i in range(4)])
    if body.get('communication',{}).get('native')!=native:
        raise ProtocolError('saved native counters differ from locally owned process logs')
    application=body['communication']['application']
    # Recompute totals, then cross-check RPC body counts at the other endpoint.
    from trustlessfl.seed_mpc_meter import ApplicationMeter
    recomputed=ApplicationMeter()
    for event in application['events']:
        if set(event)-{'channel','direction','kind','scope','bytes','objects'}:
            raise ProtocolError('unexpected data in public meter')
        recomputed.record(event['channel'],event['direction'],event['kind'],event['bytes'],
                          scope=event['scope'],objects=event.get('objects'))
    if recomputed.report()!=application: raise ProtocolError('application meter totals differ')
    server_events=[]
    for i in range(4):
        server_events.extend(json.loads((workspace/f'P{i}/rpc-communication.json').read_text())['events'])
    def totals(events,server=False):
        result={}
        for event in events:
            if event['channel']!='aggregator-rpc-json' or event['kind']=='head': continue
            direction=({'sent':'received','received':'sent'}[event['direction']] if server else event['direction'])
            key=(event['scope'],direction,event['kind'])
            result[key]=result.get(key,0)+event['bytes']
        return result
    if totals(application['events'])!=totals(server_events,True):
        raise ProtocolError('RPC counters differ between coordinator and service endpoints')
    external=[]; timings={}
    for i in range(4):
        directory=output/f'clients/C{i}'
        external.append(json.loads((directory/'registration-communication.json').read_text()))
        timings[f'C{i}']=[json.loads(p.read_text()) for p in sorted(directory.glob('timing-round-*.json'))]
    return {'native':native,'application':application,
            'rpc_endpoint_counts_exact':True,'rpc_service_events':server_events,
            'external_seed_input':{'definition':'one client endpoint per connection; octetStream payload + 4-byte framing; includes pre-TLS client identifier; excludes TLS/TCP headers/handshake',
                'clients':external,'sent_bytes':sum(s['sent_bytes'] for c in external for s in c.values()),
                'received_bytes':sum(s['received_bytes'] for c in external for s in c.values()),
                'seed_inputs_per_client':1},
            'timing':{'compile_seconds':json.loads((output/'provenance.json').read_text())['compile_seconds'],
                'serverapp_wall_seconds':body['wall_seconds'],'native_session_wall_seconds':body['native_session_wall_seconds'],
                'harness_wall':json.loads((output/'runtime-wall.json').read_text()) if (output/'runtime-wall.json').exists() else None,
                'flower_status_elapsed_seconds':[json.loads(p.read_text())['runs'][0]['elapsed'] for p in output.glob('attempt-*/run-status.json')],
                'client_work':timings}}


def verify_runtime_guard(output, expected_hash):
    files=list(output.glob('attempt-*/runtime-bootstrap/guards/*.json'))
    if not files: raise ProtocolError('Flower runtime guard startup evidence missing')
    for path in files:
        item=json.loads(path.read_text())
        if item!={'installed':True,'source_sha256':expected_hash}:
            raise ProtocolError('Flower runtime guard startup artifact differs')
    return {'installed':True,'source_sha256':expected_hash,'startup_processes':len(files)}


def verify_run(output):
    deployment,committee=load_deployment(output/'deployment.json')
    provenance=json.loads((output/'provenance.json').read_text())
    workspace=Path(deployment['workspace'])
    if (sha(deployment['native_binary'])!=deployment['binary_sha256']
            or sha(workspace/'policy.json')!=deployment['config_sha256']
            or sha(workspace/'Programs/Circuits/aes_128.txt')!=deployment['aes_sha256']):
        raise ProtocolError('native deployment artifact changed')
    for relative,expected in deployment['artifacts'].items():
        if sha(workspace/'Programs'/relative)!=expected: raise ProtocolError('native bytecode changed')
    for name,expected in provenance['mpc_source_sha256'].items():
        if sha(workspace/'Programs/Source'/name)!=expected: raise ProtocolError('compiled source changed')
    for relative,expected in provenance['source_sha256'].items():
        path=output/'app'/relative if relative.startswith('trustlessfl/') else output/'sources'/relative
        if sha(path)!=expected: raise ProtocolError('application source changed')
    if deployment.get('test_fault'):
        failures=list((output/'runtime-results').glob('run-*/failed.json'))
        if len(failures)!=1: raise ProtocolError('missing Flower failure artifact')
        failure=json.loads(failures[0].read_text())
        if failure['completed_rounds']!=0 or failure['model_hash']!=digest(deployment['initial_model']): raise ProtocolError('invalid model applied')
        for i in range(4):
            if (output/f'clients/C{i}/audit').exists(): raise ProtocolError('client trained uncertified model')
            text=(Path(deployment['workspace'])/f'P{i}/native.log').read_text()
            if 'SEED_MPC_CHECKED ' in text or 'SEED_MPC_PUBLIC ' in text: raise ProtocolError('unexpected native output')
        result={'passed':True,'fault':deployment['test_fault'],'status':'Flower finished:failed as expected',
                'model_updates':0,'training_calls':0,'plaintext_fallback':False}
    else:
        results=list((output/'runtime-results').glob('run-*/results.json'))
        if len(results)!=1: raise ProtocolError('missing official Flower result')
        body=json.loads(results[0].read_text()); model=list(deployment['initial_model']); checks=[]
        if (body['rounds']!=deployment['rounds'] or len(body['records'])!=deployment['rounds']
                or len(body['models'])!=deployment['rounds']+1 or body['models'][0]!=model):
            raise ProtocolError('incomplete Flower round/model sequence')
        if body.get('snapshot_version',1)!=committee.snapshot_version:
            raise ProtocolError('Flower snapshot version differs')
        receipt_count=verify_collection_receipts(committee,body['records'],body.get('collection_receipts',[]))
        learning_mode=deployment['training']['mode'] in ('tiny-fmnist','fmnist-lenet5')
        full_lenet=deployment['training']['mode']=='fmnist-lenet5'
        evaluator=evaluate_lenet if full_lenet else evaluate
        if learning_mode:
            test_path=Path(deployment['test_data'])
            if 'test' in provenance['data'] and sha(test_path)!=provenance['data']['test']['sha256']:
                raise ProtocolError('evaluation shard changed')
            with np.load(test_path,allow_pickle=False) as data: test_x,test_y=data['x'],data['y']
            if body['metrics'][0]!=evaluator(np.asarray(model,dtype=np.float64),test_x,test_y): raise ProtocolError('initial metrics differ')
        for r,record in enumerate(body['records'],1):
            updates=[]
            presence=record['manifest'].get('presence',[1]*4)
            if deployment['training']['mode']=='dropout-fixture':
                schedule=deployment['test_dropout_schedule'].get(str(r),{})
                expected_presence=[int(schedule.get(f'C{i}',{}).get('train') not in ('drop-before','timeout-before','partial')) for i in range(4)]
                if presence!=expected_presence: raise ProtocolError('dropout presence differs from fixed schedule')
            if full_lenet:
                from trustlessfl.fmnist import FmnistTrainer
                reference_path=output/f'oracle-public-model-round-{r}.npz'
                if reference_path.exists():
                    with np.load(reference_path,allow_pickle=False) as saved:
                        if not np.array_equal(saved['weights'],np.asarray(model,dtype=np.float64)):
                            raise ProtocolError('oracle public reference changed')
                else: np.savez_compressed(reference_path,weights=np.asarray(model,dtype=np.float64))
            for i in range(4):
                client=output/f'clients/C{i}'; audit_path=client/f'audit/round-{r}.json'
                if deployment['training']['mode']=='dropout-fixture':
                    injected=schedule.get(f'C{i}',{}).get('train')
                    if injected in ('drop-before','timeout-before') and audit_path.exists():
                        raise ProtocolError('unavailable client unexpectedly trained')
                    if injected=='partial' and not audit_path.exists(): raise ProtocolError('partial upload was not generated')
                if not audit_path.exists():
                    if presence[i]: raise ProtocolError('submitted client has no oracle audit')
                    updates.append(None); continue
                audit=json.loads(audit_path.read_text())
                if audit['model_hash']!=digest(model): raise ProtocolError('client trained wrong reference model')
                if deployment['training']['mode'] in ('fixture','scale-fixture','dropout-fixture'):
                    oracle={'fixture':fixture_update,'scale-fixture':scale_fixture_update,'dropout-fixture':dropout_fixture_update}[deployment['training']['mode']]
                    if audit['update']!=oracle(i,r,committee.policy.dimension): raise ProtocolError('synthetic fixture changed')
                if learning_mode:
                    if sha(client/'train.npz')!=provenance['data'][f'C{i}']['sha256']: raise ProtocolError('training shard changed')
                    cfg=deployment['training']
                    if full_lenet:
                        oracle_train=client/'train.npz'
                        if cfg.get('test_poisoning') and i in cfg['test_poisoning']['malicious_slots'] and cfg['test_poisoning']['case']=='label-flip':
                            from trustlessfl.seed_mpc_poisoning_fixture import flip_labels
                            oracle_train=output/f'oracle-trusted-label-flip-C{i}.npz'
                            with np.load(client/'train.npz',allow_pickle=False) as saved:
                                np.savez_compressed(oracle_train,x=saved['x'],y=flip_labels(saved['y']))
                            oracle_train.chmod(0o600)
                        oracle=FmnistTrainer(oracle_train,reference_path,seed=cfg['seed'],epochs=cfg['epochs'],
                            batch_size=cfg['batch_size'],momentum=cfg['momentum'],weight_decay=cfg['weight_decay'],device='cpu')
                        delta=oracle(np.zeros(committee.policy.dimension,dtype=np.float64),i,cfg['learning_rate'],r)
                        metadata=oracle.meta
                        if any(audit['training'][key]!=metadata[key] for key in ('rows','optimizer_steps','device','epochs','batch_size')):
                            raise ProtocolError('training workload counters differ')
                    else:
                        with np.load(client/'train.npz',allow_pickle=False) as data:
                            delta=train(np.asarray(model,dtype=np.float64),data['x'],data['y'],seed=cfg['seed'],slot=i,
                                round_id=r,epochs=cfg['epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'])
                    reference_update=quantize(delta,committee.policy)
                    if cfg.get('test_poisoning') and i in cfg['test_poisoning']['malicious_slots']:
                        from trustlessfl.seed_mpc_poisoning_fixture import attack
                        reference_update=attack(np.asarray(reference_update,dtype=np.int64),cfg['test_poisoning']['case'],committee.policy).tolist()
                    if reference_update!=audit['update']: raise ProtocolError('independent retraining differs')
                updates.append(audit['update'])
            selected=[bool(p) and u is not None and all(abs(v)<=committee.policy.coordinate_cap for v in u) and sum(v*v for v in u)<=committee.policy.squared_threshold
                      for p,u in zip(presence,updates,strict=True)]
            count=sum(selected)
            expected={'status':'abort'} if count<committee.policy.minimum_accepted else {'status':'ok','count':count,
                'sum':[sum(u[j] for u,keep in zip(updates,selected,strict=True) if keep) for j in range(committee.policy.dimension)]}
            rc=record['result_certificate']; committee.check_certificate(record['input_certificate'],committee.input_body(record['manifest']))
            committee.check_certificate(rc,committee.result_body(record['manifest'],expected,model))
            if rc['body']['result']!=expected: raise ProtocolError('native integer SUM/count differs')
            model=committee.next_model(model,expected)
            if body['models'][r]!=model: raise ProtocolError('certified public model differs')
            if learning_mode and body['metrics'][r]!=evaluator(np.asarray(model,dtype=np.float64),test_x,test_y):
                raise ProtocolError('recomputed FMNIST metrics differ')
            checks.append({'round':r,'status':expected['status'],'integer_sum_exact':True,'model_exact':True,
                           'presence':presence,'accepted_count':count,'independent_retraining_exact':True if learning_mode else None})
        client_heads={}; sync_traces={}
        for i in range(4):
            client=output/f'clients/C{i}'; submitted=json.loads((client/'registration-submitted.json').read_text())
            if submitted['private_seed_inputs']!=1: raise ProtocolError('seed re-registered')
            state=CoordinatorState(committee,client/'model.sqlite',deployment['initial_model'])
            try:
                head=state.head(); client_heads[f'C{i}']=head['round']
                if committee.snapshot_version==1:
                    if head!=body['final_head']: raise ProtocolError('client final certified state differs')
                else:
                    if not 0<=head['round']<=body['rounds'] or head['model']!=body['models'][head['round']]:
                        raise ProtocolError('client state is not a certified prefix')
                    expected_decision=digest({'genesis':committee.contract}) if head['round']==0 else digest(body['records'][head['round']-1]['result_certificate']['body'])
                    if head['decision']!=expected_decision: raise ProtocolError('client prefix parent differs')
                    trace_path=client/'sync-public.jsonl'
                    traces=[json.loads(line) for line in trace_path.read_text().splitlines()] if trace_path.exists() else []
                    for trace in traces:
                        if (not 0<=trace['from_round']<=trace['to_round']<=body['rounds']
                                or trace['model_hash']!=digest(body['models'][trace['to_round']])):
                            raise ProtocolError('client sync trace differs')
                    sync_traces[f'C{i}']=traces
            finally: state.ledger.close()
        workload_ok=learning_workload_completed(checks,4) if learning_mode else None
        result={'passed':workload_ok if learning_mode else True,
            'protocol_correctness_passed':True,'learning_workload_completed':workload_ok,
            'runtime':body['runtime'],'mode':body['mode'],'dimension':body['dimension'],
            'snapshot_version':committee.snapshot_version,'verified_receipt_certificates':receipt_count,
            'rounds':body['rounds'],'round_checks':checks,'compile_invocations':1,'compile_seconds':provenance['compile_seconds'],
            'seed_inputs_per_client':1,'internal_mb':body['internal_mb'],'metrics':body['metrics'],
            'masked_application_json_bytes':body['masked_application_json_bytes'],'wall_seconds':body['wall_seconds'],
            'native_resources':body.get('native_resources'),'compile_resources':provenance.get('compile_resources'),
            'round_timings':body.get('round_timings'),
            'client_ack_required':body.get('client_ack_required',True),'client_certified_rounds':client_heads,
            'client_sync_traces':sync_traces,'submission_status':body.get('submission_status'),
            'raw_delta_in_flower_reply':False,'client_duplicate_commit_applied':False,
            'scope':provenance['scope']}
        if deployment.get('communication_meter'):
            result['communication']=verify_communication(output,deployment,body)
        guard_hash=provenance['source_sha256'].get('trustlessfl/seed_mpc_flower_runtime.py')
        if guard_hash and not deployment.get('role_isolation'):
            result['runtime_guard']=verify_runtime_guard(output,guard_hash)
        if deployment['training']['mode']=='dropout-fixture':
            if body.get('client_ack_required') is not False: raise ProtocolError('dropout path still requires client ACK')
            # Compare known offline heads against actual durable client traces;
            # certificates/audits above independently bind every trained model.
            required={'C3':[(4,2),(8,3),(10,1)],'C1':[(5,1),(6,1),(8,1),(10,1)],
                      'C0':[(6,1),(10,1)],'C2':[(4,1),(6,1),(8,1),(10,1)]}
            for name,requirements in required.items():
                for r,minimum in requirements:
                    if r<=body['rounds'] and not any(t['action']=='train' and t['round']==r
                        and t['applied_decisions']>=minimum and t['to_round']==r-1 for t in sync_traces[name]):
                        raise ProtocolError('returning client did not verify the missing decision suffix')
            if body['rounds']>=6:
                missing={e['client_id'] for e in body['commit_notifications'] if e['round']==5 and e['status']=='missing'}
                if missing!=set(committee.clients): raise ProtocolError('all-client ACK absence not observed')
            result['dropout_and_catchup_exact']=True
            result['all_client_ack_absence_progress']=body['rounds']>=6
        if full_lenet:
            result['training_workload']={'rows_per_client':[provenance['data'][f'C{i}']['rows'] for i in range(4)],
                'test_rows':provenance['data']['test']['rows'],'contract':deployment['training'],
                'reference_oracle':'existing FmnistTrainer, CPU, exact quantized update comparison'}
    result['verification_source_sha256']=sha(Path(__file__))
    target=output/'verification.json'
    if target.exists(): target=output/f'verification-{uuid.uuid4().hex[:8]}.json'
    write(target,result); print(json.dumps(result,indent=2),flush=True)
    if not result['passed']:
        raise ProtocolError('protocol checks passed but intended all-present learning workload was incomplete')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mp-spdz-dir',type=Path,default=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3')
    parser.add_argument('--mode',choices=['fixture','scale-fixture','dropout-fixture','tiny-fmnist','fmnist-lenet5'],default='tiny-fmnist')
    parser.add_argument('--dimension',type=int,default=65)
    parser.add_argument('--rounds',type=int,default=3)
    parser.add_argument('--rows-per-client',type=int,default=256,help='tiny-fmnist only; fmnist-lenet5 uses all 15000 rows/client')
    parser.add_argument('--fault',choices=['uncertified-model'])
    parser.add_argument('--timeout',type=int,default=180)
    parser.add_argument('--phase',choices=['all','prepare','run','verify'],default='all')
    parser.add_argument('--snapshot-version',type=int,choices=(1,2),default=1)
    parser.add_argument('--collection-window-ms',type=int,default=60000)
    parser.add_argument('--communication-meter',action='store_true',help='requires the explicitly approved separate observer build')
    parser.add_argument('--test-poisoning',choices=['clean','out-of-bound','sign-flip','bounded-50','bounded-100','label-flip'])
    args=parser.parse_args(); output=args.output.resolve()
    if args.phase in ('all','prepare'): stage(output,args.mp_spdz_dir,mode=args.mode,dimension=args.dimension,
        rounds=args.rounds,rows=args.rows_per_client,fault=args.fault,timeout=args.timeout,
        snapshot_version=args.snapshot_version,collection_window_ms=args.collection_window_ms,
        communication_meter=args.communication_meter,test_poisoning=args.test_poisoning)
    if args.phase in ('all','run'): run(output)
    if args.phase in ('all','run','verify'): verify_run(output)


if __name__=='__main__': main()
