"""Local Docker network validation; role secrets are generated inside each role.

One trusted Docker host is not four independent physical administrators. Only
public enrollments/ciphertexts leave containers. Oracle data is reproducible
synthetic data and is never read from a client container.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

import numpy as np

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from trustlessfl.crypto import canonical, digest

BACKEND='/home/operator/backend/mp-spdz-0.4.3-checked-source-v1'
ROLE='/home/operator/workspace/role'


def synthetic(slot,kind='mlp'):
    teacher=np.random.default_rng(42).normal(size=(6,3))
    rng=np.random.default_rng(np.random.SeedSequence([42,slot]))
    count=96 if slot==100 else 64
    if kind=='cnn':
        y=rng.integers(0,3,size=count,dtype=np.int64)
        x=rng.integers(0,64,size=(count,28,28),dtype=np.uint8)
        for i,label in enumerate(y): x[i,4+int(label)*7:9+int(label)*7,:]+=160
        return x,y
    x=rng.normal(size=(count,6)).astype(np.float32)
    return x,(x@teacher).argmax(1).astype(np.int64)


def run(output,image,clients=4,dropout=False,*,client_image=None,model_kind="mlp",hidden=5):
    output=Path(output).resolve(); output.mkdir(parents=True,exist_ok=False)
    exchange=output/'exchange'; exchange.mkdir()
    if model_kind not in ('mlp','cnn'): raise ValueError('unsupported validation model')
    model_file='classifier.py' if model_kind=='mlp' else 'fmnist_small_cnn.py'
    shutil.copyfile(ROOT/'examples/seed_mpc_custom'/model_file,exchange/'model.py')
    (exchange/'model.json').write_bytes(canonical({'plugin':'model.py','kwargs':{'hidden':hidden} if model_kind=='mlp' else {'classes':3},
        'training':{'epochs':1,'batch_size':16,'learning_rate':.05},
        'policy':{'coordinate_cap':20000,'squared_threshold':2500000000,'scale':10000,'minimum_accepted':2}}))
    token='tfl-'+uuid.uuid4().hex[:10]; network=token+'-net'; names=[]; processes=[]; handles=[]
    def docker(*args,timeout=120):
        return subprocess.run(['docker',*map(str,args)],capture_output=True,text=True,check=True,timeout=timeout)
    def execute(name,code,*,timeout=120):
        return docker('exec',name,'python','-c',code,timeout=timeout).stdout
    def cli(name,*args,timeout=300):
        result=docker('exec',name,'python','-m','trustlessfl.seed_mpc_distributed',*args,timeout=timeout)
        # Each successful command's last stdout line is JSON; native compiler logs go to files.
        return json.loads(result.stdout.strip().splitlines()[-1])
    def start(name,*args,label):
        log=(output/(label+'.log')).open('x'); handles.append(log)
        p=subprocess.Popen(['docker','exec',name,'python','-m','trustlessfl.seed_mpc_distributed',*map(str,args)],
            stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        processes.append(p); return p
    def get(name,source,destination):
        docker('cp',name+':'+source,destination)
    started=time.monotonic()
    total_rounds=3 if dropout else 2
    try:
        docker('network','create',network)
        for role in [*(f'A{i}' for i in range(4)),*(f'C{i}' for i in range(clients))]:
            store=output/role; store.mkdir()
            name=token+'-'+role.lower(); names.append(name)
            docker('run','-d','--name',name,'--network',network,'--network-alias',role.lower(),
                '--cap-drop','ALL','--security-opt','no-new-privileges',
                '-v',str(store)+':/home/operator/workspace',
                '-v',str(exchange)+':/exchange:ro',client_image if role.startswith('C') and client_image else image)
        aggs=names[:4]; nodes=names[4:]
        for slot,name in enumerate(aggs):
            cli(name,'init-aggregator','--directory',ROLE,'--slot',slot,'--host',f'a{slot}')
            get(name,ROLE+'/public.json',exchange/f'A{slot}.json')
        plan=cli(aggs[0],'plan','--output','/home/operator/workspace/bundle','--mp-spdz-dir',BACKEND,
            '--model-config','/exchange/model.json','--peers',*[f'/exchange/A{i}.json' for i in range(4)],
            '--clients',clients,'--rounds',total_rounds,'--collection-window-ms',60000 if dropout else 120000)
        get(aggs[0],'/home/operator/workspace/bundle',exchange/'bundle')
        contract=plan['contract_hash']
        print('DISTRIBUTED public plan compiled; independent approvals',flush=True)
        for slot,name in enumerate(aggs):
            cli(name,'approve','--directory',ROLE,'--bundle','/exchange/bundle','--expected-contract-hash',contract,'--mp-spdz-dir',BACKEND)
            get(name,ROLE+'/approval.json',exchange/f'A{slot}-approval.json')
        # Generate each private training shard locally, with no host data upload.
        import inspect
        code="import numpy as np\n"+inspect.getsource(synthetic)+"\nx,y=synthetic(SLOT,"+repr(model_kind)+")\nnp.savez('/home/operator/data.npz',x=x,y=y)\n"
        for slot,name in enumerate(nodes):
            execute(name,code.replace('SLOT',str(slot)))
            cli(name,'client-prepare','--directory',ROLE,'--bundle','/exchange/bundle','--expected-contract-hash',contract,
                '--slot',slot,'--train-data','/home/operator/data.npz','--model-plugin','/exchange/model.py')
            get(name,ROLE+'/enrollment.json',exchange/f'C{slot}.json')
            for party in range(4): get(name,ROLE+f'/component-packets/A{party}.json',exchange/f'C{slot}-A{party}.json')
        # Assert client image has no backend/compiler/Ray in lightweight tests.
        client_environment=[]
        if client_image:
            probe="import json,shutil,importlib.util; from pathlib import Path; print(json.dumps({'native_backend_present':Path('/home/operator/backend').exists(),'compiler_present':shutil.which('g++') is not None,'ray_present':importlib.util.find_spec('ray') is not None,'installed_package':str(Path(__import__('trustlessfl').__file__).resolve())}))"
            for name in nodes:
                entry=json.loads(execute(name,probe)); client_environment.append(entry)
                assert not entry['native_backend_present'] and not entry['compiler_present'] and not entry['ray_present']
        # Finalize using only signed public enrollment and approvals.
        result=cli(aggs[0],'finalize','--bundle','/home/operator/workspace/bundle','--expected-contract-hash',contract,
            '--approvals',*[f'/exchange/A{i}-approval.json' for i in range(4)],
            '--enrollments',*[f'/exchange/C{i}.json' for i in range(clients)])
        get(aggs[0],'/home/operator/workspace/bundle/deployment-public.json',exchange/'bundle/deployment-public.json')
        enrollment=result['public_deployment_hash']
        execute(aggs[0],code.replace('SLOT','100'))
        for slot,name in enumerate(aggs):
            cli(name,'bind','--directory',ROLE,'--bundle','/exchange/bundle','--expected-contract-hash',contract,
                '--expected-deployment-hash',enrollment,'--seed-packets',*[f'/exchange/C{i}-A{slot}.json' for i in range(clients)],
                *(['--test-data','/home/operator/data.npz'] if slot==0 else []))
        for name in nodes:
            cli(name,'bind','--directory',ROLE,'--bundle','/exchange/bundle','--expected-contract-hash',contract,'--expected-deployment-hash',enrollment)
        # Probe mounted filesystem boundaries and key inventory without reading key bytes.
        inventories=[]
        probe=f'''import json,os
from pathlib import Path
r=Path({ROLE!r})
print(json.dumps({{'native_private_keys':sorted(p.name for p in (r/'Player-Data').glob('*.key')),
 'client_private_present':(r/'client.json').exists(),'aggregator_private_present':(r/'identity.json').exists(),
 'docker_socket_accessible':Path('/var/run/docker.sock').exists(),
 'other_host_workspace_accessible':Path({str(output)!r}).exists()}}))'''
        for role,name in zip([*(f'A{i}' for i in range(4)),*(f'C{i}' for i in range(clients))],names):
            report=json.loads(execute(name,probe)); inventories.append({'role':role,**report})
            assert report['native_private_keys']==[('P'+role[1:] if role.startswith('A') else role)+'.key']
            assert not report['docker_socket_accessible'] and not report['other_host_workspace_accessible']
            assert report['client_private_present']==role.startswith('C')
            assert report['aggregator_private_present']==role.startswith('A')
        for slot,name in enumerate(aggs): start(name,'aggregator','--directory',ROLE,label=f'aggregator-{slot}')
        ready_script=f'''from trustlessfl.seed_mpc_session import load_deployment,rpc
d,_=load_deployment({ROLE+'/deployment.json'!r})
for url in d['services']: rpc(url,'head',timeout=2,transport=d['rpc_transport'])
print('ok')'''
        deadline=time.monotonic()+60
        while True:
            if any(p.poll() is not None for p in processes): raise RuntimeError('aggregator exited during startup')
            try: execute(aggs[0],ready_script,timeout=15); break
            except subprocess.CalledProcessError:
                if time.monotonic()>deadline: raise
                time.sleep(.2)
        # An enrolled non-A0 aggregator has a trusted TLS leaf but no coordinator RPC authority.
        denied=f'''from trustlessfl.seed_mpc_session import load_deployment,rpc
from trustlessfl.crypto import ProtocolError
d,_=load_deployment({ROLE+'/deployment.json'!r})
try: rpc(d['services'][2],'head',timeout=3,transport=d['rpc_transport'])
except ProtocolError: print('denied')
else: raise RuntimeError('unauthorized aggregator admitted')'''
        assert execute(aggs[1],denied).strip()=='denied'
        start(aggs[0],'superlink','--directory',ROLE,label='superlink')
        for slot,name in enumerate(nodes): start(name,'client','--directory',ROLE,label=f'client-{slot}')
        time.sleep(5)
        print('DISTRIBUTED four aggregators and clients running on separate networks',flush=True)
        runner=start(aggs[0],'flower-run','--directory',ROLE,label='flower')
        if dropout:
            # Stop after the first round's submitted inputs have been computed,
            # before the following training response. Restart after round 2's
            # native checkpoint; C(last) must verify missed decisions on rejoin.
            deadline=time.monotonic()+500; paused=False; resumed=False
            log=output/'A0/role/native.log'
            while runner.poll() is None:
                text=log.read_text() if log.exists() else ''
                if not paused and 'SEED_MPC_PUBLIC ' in text:
                    docker('stop','--time','0',nodes[-1]); paused=True
                    print('DISTRIBUTED client stopped after round 1 upload',flush=True)
                if paused and 'SEED_MPC_CHECKED 2 ' in text:
                    docker('start',nodes[-1]); start(nodes[-1],'client','--directory',ROLE,label=f'client-{clients-1}-rejoin'); resumed=True
                    print('DISTRIBUTED client resumed before round 3',flush=True); break
                if time.monotonic()>deadline: raise TimeoutError('dropout checkpoints not reached')
                time.sleep(.02)
            if not paused or not resumed: raise RuntimeError('dropout scenario did not complete')
        if runner.wait(timeout=1100)!=0: raise RuntimeError('distributed Flower run failed')
        files=list((output/'A0/role/runtime-results').glob('run-*/results.json'))
        if len(files)!=1: raise RuntimeError('missing actual Flower result')
        record=json.loads(files[0].read_text())
        assert record['rounds']==total_rounds
        # Public transcript replay and a separate synthetic retraining oracle.
        from trustlessfl.seed_mpc_model import train_custom,evaluate_custom
        from trustlessfl.seed_mpc_training import quantize
        from trustlessfl.seed_mpc_policy import SeedMPCPolicy
        from trustlessfl.seed_mpc_committee import CoordinatorState,SeedCommittee
        local_plan=json.loads((exchange/'bundle/plan.json').read_text())
        spec={**local_plan['model_adapter'],'plugin':str(exchange/'bundle/model.py')}
        policy=SeedMPCPolicy(**json.loads((exchange/'bundle/deployment-public.json').read_text())['committee']['policy'])
        model=np.asarray(local_plan['initial_model'],dtype=np.float64); checks=[]
        public=json.loads((exchange/'bundle/deployment-public.json').read_text()); c=public['committee']
        committee=SeedCommittee(policy,c['session_id'],c['epoch'],c['clients'],c['aggregators'],c['registry'],c['registrations'],
            c['execution_hash'],public['initial_model'],snapshot_version=2,collection_window_ms=c['collection_window_ms'])
        state=CoordinatorState(committee,output/'public-replay.sqlite',public['initial_model'],create=True)
        for round_id,decision in enumerate(record['records'],1):
            updates=[]
            presence=[int(not (dropout and round_id==2 and slot==clients-1)) for slot in range(clients)]
            assert decision['manifest']['presence']==presence
            assert state.apply(decision['manifest'],decision['input_certificate'],decision['result_certificate'])
            assert state.head()['model']==record['models'][round_id]
            context=committee.check_manifest(decision['manifest'])
            proofs=record['collection_receipts'][round_id-1]['certificates']
            present=[name for name,flag in zip(committee.clients,presence,strict=True) if flag]
            for name,proof in zip(present,proofs,strict=True):
                packets=[p for p in decision['manifest']['inputs'] if p['sender']==name]
                committee.check_receipt_certificate(committee.submission(context,decision['manifest']['parent_decision'],name,packets),proof)
            for slot in range(clients):
                if not presence[slot]: continue
                x,y=synthetic(slot,model_kind)
                delta,_=train_custom(spec,model,x,y,slot=slot,round_id=round_id,training=local_plan['training'])
                updates.append(quantize(delta,policy))
            total=np.asarray(updates,dtype=np.int64).sum(axis=0).tolist()
            result=decision['result_certificate']['body']['result']
            count=sum(presence)
            assert result=={'status':'ok','count':count,'sum':total}
            model=model+np.asarray(total,dtype=np.float64)/(policy.scale*count)
            assert model.tolist()==record['models'][round_id]
            checks.append({'round':round_id,'sum_exact':True,'model_exact':True,'accepted':count,'presence':presence,'certificates_valid':True})
        assert state.head()==record['final_head']; state.ledger.close()
        assert not list(output.glob('*/role/audit'))
        summary={'protocol':'seed-mpc-independent-network-validation-v1','completed':True,'clients':clients,
            'aggregators':4,'dimension':policy.dimension,'model_kind':model_kind,'client_environment':client_environment,'rounds':checks,'raw_audit_files':0,
            'non_coordinator_rpc_rejected':True,'filesystem_inventory':inventories,'metrics':record['metrics'],
            'contract_hash':contract,'public_deployment_hash':enrollment,
            'dropout_rejoin_verified':dropout,'client_confirmed_rounds_at_shutdown':record['client_confirmed_rounds'],
            'client_code_guard_enforced':True,
            'scope':'distinct Docker filesystem and network namespaces; one trusted Docker administrator; not physical multi-operator deployment',
            'wall_seconds':round(time.monotonic()-started,3)}
        (output/'verification.json').write_bytes(canonical(summary))
        print(json.dumps(summary,ensure_ascii=False),flush=True)
        return summary
    finally:
        for name in names:
            subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=30)
        subprocess.run(['docker','network','rm',network],capture_output=True,timeout=30)
        for process in processes:
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: os.killpg(process.pid,15); process.wait(timeout=10)
        for handle in handles: handle.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--image',default='trustlessfl-distributed-validation:local-v1'); parser.add_argument('--clients',type=int,default=4)
    parser.add_argument('--dropout',action='store_true')
    parser.add_argument('--client-image'); parser.add_argument('--model-kind',choices=['mlp','cnn'],default='mlp');parser.add_argument('--hidden',type=int,default=5)
    args=parser.parse_args(); run(args.output,args.image,args.clients,args.dropout,client_image=args.client_image,model_kind=args.model_kind,hidden=args.hidden)
