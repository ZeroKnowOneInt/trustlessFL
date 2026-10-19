"""Local signed-input/ledger/native-checkpoint pipeline; no Flower transport."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time
import uuid

from experiments.run_private_bound_mpc import configure_tls,free_port_base,write_private
from experiments.run_seed_mpc_probe import ROOT,build_fixture,circuit_bytes,CIRCUIT_SHA256
from trustlessfl.crypto import Identity,ProtocolError,canonical,digest
from trustlessfl.seed_mpc_committee import SeedCommittee,AggregatorGuard,CoordinatorState,digest_words
from trustlessfl.seed_mpc_native import NativeCheckpointReader
from trustlessfl.seed_mpc_wire import RoundContext
from trustlessfl.seed_mpc_wire import mask_words,reference_aggregate
from trustlessfl.seed_mpc_backend import pin_backend,native_command


def participation_fixture(dimension):
    policy,keys,_,_,_=build_fixture('multi-round',dimension)
    pad=lambda values:values+[0]*(dimension-len(values))
    schedules=[]
    for pattern in range(16):
        presence=[(pattern>>i)&1 for i in range(4)]
        updates=[pad([(-1 if i%2 else 1)*20000,0]) for i in range(4)]
        schedules.append((presence,updates))
    schedules.append(([1]*4,[pad([0,0]) for _ in range(4)]))
    updates=[pad([0,0]) for _ in range(4)]
    updates[0][0]=updates[0][-1]=15000  # global norm > T across chunks when D>32
    updates[1][-1]=20001
    updates[2][-1]=-20000; updates[3][-1]=20000
    schedules.append(([1]*4,updates))
    for value in (20000,-20000):
        schedules.append(([1]*4,[pad([value,0]) for _ in range(4)]))
    schedules.append(([1]*4,[pad([20000,1]) for _ in range(4)]))
    rounds=[]; expected=[]
    for r,(presence,updates) in enumerate(schedules,1):
        wire=[[(u+m)%policy.modulus for u,m in zip(row,mask_words(key,r,dimension),strict=True)]
              for key,row in zip(keys,updates,strict=True)]
        rounds.append({'round_id':r,'wire':wire,'presence':presence})
        expected.append(reference_aggregate(policy,[k for k,p in zip(keys,presence) if p],r,
                                           [row for row,p in zip(wire,presence) if p]))
    return policy,keys,rounds,expected


def pipe_write(fd,values,timeout=120):
    data=('\n'.join(map(str,values))+'\n').encode()
    deadline=time.monotonic()+timeout
    while data:
        remaining=deadline-time.monotonic()
        if remaining<=0: raise ProtocolError('native input pipe timeout')
        if not select.select([], [fd], [], min(remaining,.2))[1]: continue
        try:
            sent=os.write(fd,data); data=data[sent:]
        except BlockingIOError: continue


def run(installation,dimension=2,*,fault=None,timeout=120,snapshot_version=1,participation=False,collection_window_ms=1000,native_attack=None):
    if type(dimension) is not int or not 2<=dimension<=4096: raise ProtocolError('dimension must be 2..4096')
    presence_faults={'presence-disagreement','presence-nonboolean','presence-highbit','absence-wire','snapshot-version'}
    if fault not in {None,'registration-bind','input-tag',*presence_faults}: raise ProtocolError('unknown fault')
    if native_attack not in (None,'arithmetic-mul','binary-mul','opening-wire','round-abort') or native_attack and fault:
        raise ProtocolError('invalid native test attack')
    if type(snapshot_version) is not int or snapshot_version not in (1,2): raise ProtocolError('unknown snapshot version')
    if type(collection_window_ms) is not int or not 1<=collection_window_ms<=3600000: raise ProtocolError('invalid collection window')
    if (participation or fault in presence_faults) and snapshot_version!=2: raise ProtocolError('v2 required')
    installation=Path(installation).resolve()
    binary=installation/'rep4-ring-party.x'
    if not binary.is_file(): raise ProtocolError('pinned Rep4 binary missing')
    backend_pin=pin_backend(installation)
    attacker_build=None
    if native_attack:
        if not backend_pin['applied_patches']: raise ProtocolError('test attack requires approved observer timer boundaries')
        attacker_dir=ROOT/'.cache/private-bound-mpc/mp-spdz-0.4.3-adversary-test'
        attacker_build=json.loads((attacker_dir/'adversary-build.json').read_text())
        for name,key in [('rep4-ring-party.x','binary_sha256'),('libSPDZ.so','library_sha256')]:
            if hashlib.sha256((attacker_dir/name).read_bytes()).hexdigest()!=attacker_build[key]:
                raise ProtocolError('test attacker build changed')
    if participation:
        policy,keys,rounds,expected=participation_fixture(dimension)
    else:
        policy,keys,rounds,expected,_=build_fixture('multi-round',dimension)
    workspace=ROOT/'.cache/seed-mpc/certified'/uuid.uuid4().hex
    workspace.mkdir(parents=True,mode=0o700)
    port=free_port_base(4); client_port=free_port_base(4)
    while abs(port-client_port)<8: client_port=free_port_base(4)
    config={**asdict(policy),'clients':4,'parties':4,'backend':'rep4','ring_bits':64,
            'backend_prime':1<<64,'domain_modulus':1<<64,'seed_encoding':'packed64',
            'rep4_input_mode':'replicated-triples-v1','output_mode':'native-public','output_length':0,
            'coordinate_circuit':'chunked','chunk_blocks':4,'round_slots':len(rounds),
            'snapshot_version':snapshot_version,'backend_pin_hash':digest(backend_pin),
            'collection_window_ms':collection_window_ms,
            'widths':policy.widths(),'client_port':client_port,'certified_stream':True}
    if native_attack: config['communication_meter']=True
    (workspace/'policy.json').write_text(json.dumps(config))
    src=workspace/'Programs/Source'; src.mkdir(parents=True)
    sources={}
    for name in ['seed_mpc_chunked_session.mpc','seed_mpc_candidate_primitives.py','seed_mpc_primitives.py']:
        data=(ROOT/'mpc/Programs/Source'/name).read_bytes()
        (src/name).write_bytes(data); sources[name]=hashlib.sha256(data).hexdigest()
    circuits=workspace/'Programs/Circuits'; circuits.mkdir()
    (circuits/'aes_128.txt').write_bytes(circuit_bytes(installation))
    started=time.monotonic()
    with (workspace/'compile.log').open('w') as log:
        code=subprocess.run([sys.executable,str(installation/'compile.py'),'-R','64','-Z','4','-M',
                             'seed_mpc_chunked_session','policy.json'],cwd=workspace,stdout=log,
                            stderr=subprocess.STDOUT,timeout=timeout).returncode
    if code: raise ProtocolError(f'compile failed: {workspace}/compile.log')
    compile_seconds=time.monotonic()-started
    program='seed_mpc_chunked_session-policy.json'
    artifacts={str(p.relative_to(workspace/'Programs')):hashlib.sha256(p.read_bytes()).hexdigest()
               for folder in ['Bytecode','Schedules'] for p in (workspace/'Programs'/folder).rglob('*') if p.is_file()}
    execution_hash=digest({'artifacts':artifacts,'binary':hashlib.sha256(binary.read_bytes()).hexdigest(),
                           'aes':CIRCUIT_SHA256,'sources':sources,'config':config,'backend_pin':digest(backend_pin)})
    (workspace/'backend-pin.json').write_text(json.dumps(backend_pin,indent=2))
    actors=configure_tls(workspace,4,4)
    identities={name:Identity.generate(name) for name in [*(f'C{i}' for i in range(4)),*(f'A{i}' for i in range(4))]}
    registry={name:identity.public() for name,identity in identities.items()}
    registrations=[]
    for i in range(4):
        name=f'C{i}'
        registrations.append(identities[name].sign({'protocol':f'seed-mpc-registration-v{snapshot_version}','session_id':workspace.name,
            'committee_epoch':1,'client_id':name,'slot':i,'key_handle':uuid.uuid4().hex,
            'policy_hash':policy.policy_hash,'execution_hash':execution_hash}))
    initial=[0.0]*dimension
    committee=SeedCommittee(policy,workspace.name,1,[f'C{i}' for i in range(4)],
                            [f'A{i}' for i in range(4)],registry,registrations,execution_hash,initial,
                            snapshot_version=snapshot_version,collection_window_ms=collection_window_ms)
    guards=[AggregatorGuard(committee,identities[f'A{i}'],actors[f'P{i}']/'rounds.sqlite',initial,create=True) for i in range(4)]
    coordinator=CoordinatorState(committee,workspace/'coordinator.sqlite',initial,create=True)
    fds=[]; handles=[]; processes=[]; records=[]
    (workspace/'public-contract.json').write_text(json.dumps(committee.contract,indent=2))
    try:
        for i in range(4):
            programs=actors[f'P{i}']/'Programs'; programs.unlink(); programs.mkdir()
            for folder in ['Bytecode','Schedules','Circuits']:
                (programs/folder).symlink_to(workspace/'Programs'/folder,target_is_directory=True)
            public=programs/'Public-Input'; public.mkdir()
            fifo=public/program; os.mkfifo(fifo,0o600)
            # O_RDWR keeps the pipe open while waiting between authenticated rounds.
            fds.append(os.open(fifo,os.O_RDWR|os.O_NONBLOCK))
            log=(actors[f'P{i}']/'native.log').open('w'); handles.append(log)
            party_binary=attacker_dir/'rep4-ring-party.x' if native_attack and i==0 else binary
            party_env={k:v for k,v in os.environ.items() if not k.startswith('SEED_TEST_NATIVE_')}
            if native_attack and i==0: party_env['SEED_TEST_NATIVE_ATTACK']=native_attack
            processes.append(subprocess.Popen(native_command(party_binary,port,i,program),cwd=actors[f'P{i}'],env=party_env,
                                              stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        tags=[word for packet in registrations for word in digest_words(digest(packet['body']))]
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda fd:pipe_write(fd,tags,timeout),fds))
        for i,key in enumerate(keys):
            actor=actors[f'C{i}']; private=actor/'fixture-input.json'
            registration_digest=digest(registrations[i]['body'])
            if fault=='registration-bind' and i==2: registration_digest=digest({'wrong-handle':True})
            write_private(private,canonical({'client_id':i,'fixture_key':key.hex(),'registration_digest':registration_digest}))
            log=(actor/'client.log').open('w'); handles.append(log)
            env={**os.environ,'PYTHONPATH':str(ROOT),'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1'}
            processes.append(subprocess.Popen([sys.executable,'-m','trustlessfl.seed_mpc_external_client',
                '--mp-spdz-dir',str(installation),'--private-input',str(private),'--config',str(workspace/'policy.json'),
                '--output',str(actor/'pending-output.json')],cwd=actor,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True))
        readers=[NativeCheckpointReader(guard,processes[i],actors[f'P{i}']/'native.log') for i,guard in enumerate(guards)]
        native_started=time.monotonic()
        for reader in readers: reader.wait_registration(timeout)
        if fault=='registration-bind': raise ProtocolError('bad registration binding accepted')
        for r,round_spec in enumerate(rounds):
            head=coordinator.head()
            context=RoundContext(workspace.name,1,round_spec['round_id'],digest(head['model']),policy.policy_hash)
            packets=[]
            presence=round_spec.get('presence',[1]*4)
            for i,row in enumerate(round_spec['wire']):
                if not presence[i]: continue
                for offset in range(0,dimension,32):
                    body=context.payload(policy,client_id=f'C{i}',key_handle=committee.handles[i],
                                         values=row[offset:offset+32],offset=offset)
                    packets.append(identities[f'C{i}'].sign(body))
            kwargs={'presence':presence} if snapshot_version==2 else {}
            manifest=committee.manifest(context,head['decision'],packets,**kwargs)
            receipts=None
            if snapshot_version==2:
                opened=[guard.open_collection(context,head['decision']) for guard in guards]
                receipts=[]
                for client in committee.clients:
                    inputs=[p for p in packets if p['sender']==client]
                    if not inputs: continue
                    submission=committee.submission(context,head['decision'],client,inputs)
                    certificate=committee.receipt_certificate(submission,[guard.receive(submission) for guard in guards])
                    receipts.append(certificate)
                    for guard in guards:
                        fetched=guard.fetch_submission(submission['collection_hash'],client)
                        if fetched['submission']!=submission: raise ProtocolError('stored submission differs')
                if not all(presence):
                    delay=max(item['deadline_ms'] for item in opened)/1000-time.time()
                    if delay>0: time.sleep(delay+.002)
            input_votes=[guard.prepare(manifest,receipts) for guard in guards]
            input_certificate=committee.certificate(committee.input_body(manifest),input_votes)
            for guard in guards: guard.reserve(manifest,input_certificate)
            # Each honest adapter builds its stream from the verified snapshot.
            with ThreadPoolExecutor(max_workers=4) as pool:
                streams=[committee.runtime_round(manifest) for _ in fds]
                if fault=='input-tag' and r==0:
                    # Fault injection only: corrupt the top bit of one party's
                    # SHA-256 header, after durable execution reservation.
                    streams[1][2 if snapshot_version==2 else 1]^=1<<63
                if fault in presence_faults and r==0:
                    if fault in ('presence-disagreement','presence-highbit'):
                        streams[1][6]^=1 if fault=='presence-disagreement' else 1<<32
                    elif fault=='presence-nonboolean':
                        for stream in streams: stream[6]=2
                    elif fault=='absence-wire':
                        if presence[0]!=0: raise ProtocolError('absence fault needs participation fixture')
                        for stream in streams: stream[10]=1
                    elif fault=='snapshot-version':
                        for stream in streams: stream[0]=1
                futures=[pool.submit(pipe_write,fd,stream,timeout) for fd,stream in zip(fds,streams,strict=True)]
                for future in futures: future.result(timeout=timeout)
            votes=[reader.vote(manifest,timeout) for reader in readers]
            result_certificate=committee.certificate(votes[0]['body'],votes)
            if result_certificate['body']['result']!=expected[r]: raise ProtocolError('certified native/oracle disagreement')
            if not coordinator.apply(manifest,input_certificate,result_certificate): raise ProtocolError('first apply rejected')
            for guard in guards:
                if not guard.accept(manifest,result_certificate): raise ProtocolError('first committee decision rejected')
            if coordinator.apply(manifest,input_certificate,result_certificate): raise ProtocolError('duplicate model apply allowed')
            # Close and reopen durable coordinator state; replay remains idempotent.
            coordinator.ledger.close()
            coordinator=CoordinatorState(committee,workspace/'coordinator.sqlite',initial)
            if coordinator.apply(manifest,input_certificate,result_certificate): raise ProtocolError('restart replay allowed')
            if any(guard.head()!=coordinator.head() for guard in guards): raise ProtocolError('committee/coordinator durable state differs')
            records.append({'manifest':manifest,'input_certificate':input_certificate,'result_certificate':result_certificate,
                            'receipt_certificates':receipts,
                            'duplicate_apply':False,'restart_duplicate_apply':False,'public_model_hash':digest(coordinator.head()['model'])})
        for process in processes:
            if process.wait(timeout=timeout)!=0: raise ProtocolError(f'native/client failed: {workspace}')
        p0=(actors['P0']/'native.log').read_text()
        match=re.search(r'Global data sent = ([0-9.]+) MB',p0)
        result={'passed':True,'scope':'local synthetic signed-input/SQLite/native-checkpoint pipeline; no Flower or full BFT liveness',
                'dimension':dimension,'rounds':len(rounds),'snapshot_version':snapshot_version,
                'participation_patterns':16 if participation else None,
                'seed_inputs_per_client':1,'native_sessions':1,'compile_invocations':1,
                'compile_seconds':round(compile_seconds,3),'native_seconds':round(time.monotonic()-native_started,3),
                'internal_mb':float(match[1]) if match else None,'execution_hash':execution_hash,'source_sha256':sources,
                'backend_pin':backend_pin,'rounds_records':records,'final_model':coordinator.head()['model'],'workspace':str(workspace)}
        if fault is not None or native_attack: raise ProtocolError('injected native fault accepted')
    except ProtocolError:
        if fault is None and native_attack is None: raise
        for process in processes:
            if process.poll() is None: os.killpg(process.pid,signal.SIGTERM)
        for process in processes: process.wait(timeout=10)
        text='\n'.join((actors[f'P{i}']/'native.log').read_text() for i in range(4))
        if native_attack:
            marker=f'SEED_TEST_ATTACK {native_attack}'
            if marker not in (actors['P0']/'native.log').read_text(): raise ProtocolError('native attack did not activate')
            if any(marker in (actors[f'P{i}']/'native.log').read_text() for i in range(1,4)):
                raise ProtocolError('honest native party had attack enabled')
            if 'SEED_MPC_CHECKED ' in text or records: raise ProtocolError('native attack produced certified result')
            error=None
        else:
            error={'registration-bind':'registration handle binding differs',
               'presence-nonboolean':'noncanonical presence bit','absence-wire':'absent slot has nonzero wire',
               'snapshot-version':'snapshot stream version differs'}.get(fault,'inconsistent public chunk')
        if error is not None and (error not in text or 'SEED_MPC_PUBLIC ' in text or 'SEED_MPC_CHECKED ' in text):
            raise ProtocolError('unexpected native fault failure')
        if fault=='registration-bind' and 'SEED_MPC_REG_CHECKED' in text:
            raise ProtocolError('bad registration passed checkpoint')
        if any(guard.head()['round']!=0 for guard in guards) or coordinator.head()['round']!=0:
            raise ProtocolError('rejected registration updated public model')
        if fault!='registration-bind':
            for i,guard in enumerate(guards):
                recovered=AggregatorGuard(committee,identities[f'A{i}'],actors[f'P{i}']/'rounds.sqlite',initial)
                try:
                    if recovered.ledger.row(1)['phase']!='running': raise ProtocolError('lost execution reservation')
                    try: recovered.reserve(manifest,input_certificate)
                    except ProtocolError: pass
                    else: raise ProtocolError('uncertain execution retried after recovery')
                finally: recovered.ledger.close()
        result={'passed':True,'fault':fault,'status':'registration-abort' if fault=='registration-bind' else 'input-abort',
                'dimension':dimension,'snapshot_version':snapshot_version,'model_updates':0,'retry_rejected':fault!='registration-bind',
                'result_certificates':0,'execution_hash':execution_hash,'backend_pin':backend_pin,'source_sha256':sources,'workspace':str(workspace)}
        if native_attack:
            result.update(native_attack=native_attack,status='observed-native-abort',attacker_build=attacker_build,
                honest_parties_approved=True,scope='test-only custom P0 against three pinned honest parties; observed abort, not composition/privacy proof',
                honest_error_lines=[line for i in range(1,4) for line in (actors[f'P{i}']/'native.log').read_text().splitlines()
                    if any(word in line.lower() for word in ('hash','check failed','mac fail','mismatch','inconsisten','error','terminate','closed'))])
    finally:
        for process in processes:
            if process.poll() is None: os.killpg(process.pid,signal.SIGTERM)
        for process in processes:
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); process.wait()
        for fd in fds: os.close(fd)
        for handle in handles: handle.close()
        for guard in guards: guard.ledger.close()
        coordinator.ledger.close()
    (workspace/'result.json').write_text(json.dumps(result,indent=2))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mp-spdz-dir',type=Path,required=True)
    parser.add_argument('--dimension',type=int,default=2)
    parser.add_argument('--fault',choices=['registration-bind','input-tag','presence-disagreement','presence-nonboolean',
                                        'presence-highbit','absence-wire','snapshot-version'])
    parser.add_argument('--snapshot-version',type=int,choices=(1,2),default=1)
    parser.add_argument('--participation',action='store_true')
    parser.add_argument('--collection-window-ms',type=int,default=1000)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--native-attack',choices=['arithmetic-mul','binary-mul','opening-wire','round-abort'])
    args=parser.parse_args()
    result=run(args.mp_spdz_dir,args.dimension,fault=args.fault,snapshot_version=args.snapshot_version,
               participation=args.participation,collection_window_ms=args.collection_window_ms,native_attack=args.native_attack)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as stream: json.dump(result,stream,indent=2)
    print(json.dumps({key:value for key,value in result.items() if key not in ['rounds_records','final_model','backend_pin']},indent=2))


if __name__=='__main__': main()
