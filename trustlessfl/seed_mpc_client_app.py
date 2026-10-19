"""Flower client: local seed registration, certified models, signed masked Y.

Private files belong to the client. The local simulation shares a Unix UID and
does not enforce operator isolation. Raw audit updates are test-only files.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time

import numpy as np
from flwr.app import ConfigRecord, Context, Error, Message, RecordDict
from flwr.clientapp import ClientApp

from .crypto import Identity, ProtocolError, canonical, digest
from .seed_mpc_committee import CoordinatorState
from .seed_mpc_session import load_deployment
from .seed_mpc_training import fixture_update,scale_fixture_update,dropout_fixture_update,quantize,train,train_lenet
from .seed_mpc_wire import RoundContext,encode_update,mask_words
from .seed_mpc_dropout import synchronize
from .seed_mpc_prss import MASK_MODE, LEGACY_MASK_MODE, combined_mask, seed_packet, require_mask_implementation

app=ClientApp()


def write_private(path,body):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(canonical(body))


def local(context):
    if context.node_config.get('client-config'):
        from .seed_mpc_user import check_client_config
        raw_role=json.loads(Path(context.node_config['client-config']).read_text())
        if raw_role.get('distributed_session'):
            from .seed_mpc_distributed import check_client_role
            role=check_client_role(context.node_config['client-config'])
        else: role=check_client_config(context.node_config['client-config'])
        slot=role['slot']; directory=Path(role['client-directory'])
        if 'partition-id' in context.node_config and int(context.node_config['partition-id'])!=slot:
            raise ProtocolError('client partition/config differs')
    else:
        slot=int(context.node_config['partition-id'])
        partitions=int(context.node_config['num-partitions'])
        if partitions<1 or not 0<=slot<partitions: raise ProtocolError('invalid client partition')
        directory=Path(os.environ['TRUSTLESSFL_SEED_CLIENT_ROOT'])/f'C{slot}'
        if os.environ.get('TRUSTLESSFL_SEED_USER_MODE')=='1':
            from .seed_mpc_user import check_client_config
            check_client_config(directory/'role.json')
    private=json.loads((directory/'client.json').read_text())
    deployment_file=Path(private['deployment'])
    if hashlib.sha256(deployment_file.read_bytes()).hexdigest()!=private['deployment_sha256']:
        raise ProtocolError('client deployment changed')
    deployment,committee=load_deployment(deployment_file)
    if (not 0<=slot<len(committee.clients) or 'num-partitions' in context.node_config
            and int(context.node_config['num-partitions'])!=len(committee.clients)):
        raise ProtocolError('client partition/registered roster differs')
    if deployment.get('mask_mode',LEGACY_MASK_MODE)==MASK_MODE:
        require_mask_implementation(deployment.get('mask_source_sha256'))
    if private.get('mask_mode',LEGACY_MASK_MODE)!=deployment.get('mask_mode',LEGACY_MASK_MODE):
        raise ProtocolError('client/mask mode differs')
    if deployment.get('user_session'):
        from .seed_mpc_user import checked_user_deployment
        checked_user_deployment(deployment_file)
        if private.get('test_audit') is not False:
            raise ProtocolError('user client raw audit must be disabled')
    identity=Identity.from_private(private['identity'])
    if identity.name!=committee.clients[slot] or identity.public()!=committee.registry[identity.name]:
        raise ProtocolError('client identity not pinned')
    return slot,directory,private,deployment,committee,identity


def client_state(directory,committee,initial):
    path=directory/'model.sqlite'
    return CoordinatorState(committee,path,initial)  # Created only during local provisioning.


class TrainingCalls:
    """Durable client mask-reuse prevention; retries return the exact cached wire."""
    def __init__(self,path,*,create=False):
        path=Path(path)
        if not path.exists() and not create: raise ProtocolError('client calls state missing; fresh session required')
        self.db=sqlite3.connect(path,isolation_level=None)
        self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS calls (round INTEGER PRIMARY KEY, context TEXT, reply TEXT)')

    def reserve(self,round_id,context_hash):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT context,reply FROM calls WHERE round=?',(round_id,)).fetchone()
            if row:
                if row[0]!=context_hash or row[1] is None: raise ProtocolError('client round changed or training uncertain')
                reply=json.loads(row[1])
            else:
                self.db.execute('INSERT INTO calls VALUES (?,?,NULL)',(round_id,context_hash)); reply=None
            self.db.execute('COMMIT'); return reply
        except BaseException: self.db.execute('ROLLBACK'); raise

    def cache(self,round_id,context_hash,reply):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT context,reply FROM calls WHERE round=?',(round_id,)).fetchone()
            if not row or row[0]!=context_hash or row[1] is not None: raise ProtocolError('client reply already fixed')
            self.db.execute('UPDATE calls SET reply=? WHERE round=?',(canonical(reply).decode(),round_id))
            self.db.execute('COMMIT')
        except BaseException: self.db.execute('ROLLBACK'); raise

    def close(self): self.db.close()


def require_certified_model(model,head,round_id):
    if (model.dtype!=np.float64 or model.shape!=(len(head['model']),) or not np.isfinite(model).all()
            or digest(model.tolist())!=digest(head['model']) or type(round_id) is not int
            or round_id!=head['round']+1):
        raise ProtocolError('uncertified model or wrong client round')


def accept_decision(state,decision,model):
    if not isinstance(decision,dict) or set(decision)!= {'manifest','input_certificate','result_certificate'}:
        raise ProtocolError('malformed client decision')
    try: next_hash=decision['result_certificate']['body']['next_model_hash']
    except (KeyError,TypeError) as exc: raise ProtocolError('malformed client result certificate') from exc
    if (model.dtype!=np.float64 or model.shape!=(state.committee.policy.dimension,)
            or not np.isfinite(model).all() or digest(model.tolist())!=next_hash):
        raise ProtocolError('commit model differs from certificate')
    # Validate the supplied model before any durable transition, and validate
    # the quorum/context inside apply before accepting the certified model.
    return state.apply(decision['manifest'],decision['input_certificate'],decision['result_certificate'])


def sync_trace(directory,private,action,round_id,before,after,applied):
    if not private.get('test_audit'): return
    trace={'action':action,'round':round_id,'from_round':before['round'],'to_round':after['round'],
           'model_hash':digest(after['model']),'applied_decisions':applied}
    fd=os.open(directory/'sync-public.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try: os.write(fd,canonical(trace)+b'\n')
    finally: os.close(fd)


@app.query('identity')
def identity_message(message:Message,context:Context):
    slot,_,_,_,committee,identity=local(context)
    registration={'envelope':canonical(committee.registrations[slot]).decode()}
    if message.content:
        if set(message.content)!={'challenge'}: raise ProtocolError('invalid identity challenge')
        challenge=message.content['challenge']
        if (set(challenge)!={'nonce','session_id'} or challenge['session_id']!=committee.session_id
                or not isinstance(challenge['nonce'],str) or len(challenge['nonce'])!=64):
            raise ProtocolError('identity challenge context differs')
        registration['proof']=canonical(identity.sign({'protocol':'seed-mpc-node-binding-v1',
            'session_id':committee.session_id,'client_id':identity.name,'node_id':context.node_id,
            'nonce':challenge['nonce']})).decode()
    return Message(RecordDict({'registration':ConfigRecord(registration)}),reply_to=message)


@app.query('register')
def register(message:Message,context:Context):
    slot,directory,private,deployment,committee,_=local(context)
    marker=directory/'registration-started'
    if not marker.exists():
        # The durable one-shot marker precedes starting the private channel.
        write_private(marker,{'session':committee.session_id,'slot':slot})
        log=(directory/'client.log').open('x')
        try:
            from .seed_mpc_registration import TRANSPORT
            packaged=deployment.get('distributed_session') and private.get('registration_transport')==TRANSPORT
            if deployment.get('distributed_session') and not packaged:
                raise ProtocolError('distributed client requires packaged registration transport')
            process=subprocess.Popen([sys.executable,'-m',
                'trustlessfl.seed_mpc_registration' if packaged else 'trustlessfl.seed_mpc_external_client',
                *([] if packaged else ['--mp-spdz-dir',private['installation']]),'--private-input',str(directory/'seed-input.json'),
                '--config',str(directory/'registration-config.json' if deployment.get('distributed_session') else Path(deployment['workspace'])/'policy.json'),
                '--output',str(directory/'registration-submitted.json'),
                *(['--communication-output',str(directory/'registration-communication.json')]
                  if deployment.get('communication_meter') else [])],cwd=directory,
                env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1])},
                stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            write_private(directory/'registration-process.json',{'pid':process.pid})
        finally: log.close()
    # Do not wait here: native registration first accepts the registered client roster,
    # and the Flower runtime can schedule them through a single Ray worker.
    return Message(RecordDict({'registration':ConfigRecord({'client_id':f'C{slot}','launched':True})}),reply_to=message)


@app.train()
def train_message(message:Message,context:Context):
    slot,directory,private,deployment,committee,identity=local(context)
    expected={'model','config','chain'} if committee.snapshot_version==2 else {'model','config'}
    if set(message.content)!=expected: raise ProtocolError('invalid train request')
    arrays=message.content['model'].to_numpy_ndarrays()
    if len(arrays)!=1: raise ProtocolError('one canonical model array required')
    model=arrays[0]; round_id=message.content['config']['round']
    if type(round_id) is not int or not 1<=round_id<=deployment['rounds']: raise ProtocolError('invalid train round')
    fault=deployment.get('test_dropout_schedule',{}).get(str(round_id),{}).get(identity.name,{}).get('train')
    if fault in ('drop-before','timeout-before'):
        if fault=='timeout-before': time.sleep(committee.collection_window_ms/1000+.2)
        return Message(error=Error(900,'test client unavailable before upload'),reply_to=message)
    state=client_state(directory,committee,deployment['initial_model'])
    try:
        before=state.head()
        applied=synchronize(state,json.loads(message.content['chain']['json']),model,round_id-1) if committee.snapshot_version==2 else 0
        head=state.head(); require_certified_model(model,head,round_id)
        if committee.snapshot_version==2: sync_trace(directory,private,'train',round_id,before,head,applied)
    finally: state.ledger.close()
    rc=RoundContext(committee.session_id,committee.epoch,round_id,digest(head['model']),committee.policy.policy_hash)
    calls=TrainingCalls(directory/'calls.sqlite')
    try:
        context_hash=digest({'context':rc.__dict__,'parent':head['decision'],'training':deployment['training']})
        packets=calls.reserve(round_id,context_hash)
        if packets is None:
            cfg=deployment['training']
            training_started=time.monotonic()
            training_meta=None
            if cfg['mode']=='fixture': update=fixture_update(slot,round_id,committee.policy.dimension)
            elif cfg['mode']=='scale-fixture': update=scale_fixture_update(slot,round_id,committee.policy.dimension)
            elif cfg['mode']=='dropout-fixture': update=dropout_fixture_update(slot,round_id,committee.policy.dimension)
            elif cfg['mode']=='tiny-fmnist':
                with np.load(directory/'train.npz',allow_pickle=False) as data:
                    delta=train(model,data['x'],data['y'],seed=cfg['seed'],slot=slot,round_id=round_id,
                        epochs=cfg['epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'])
                update=quantize(delta,committee.policy)
            elif cfg['mode']=='custom-model':
                from .seed_mpc_model import train_custom
                with np.load(directory/'train.npz',allow_pickle=False) as data:
                    delta,training_meta=train_custom(deployment['model_adapter'],model,data['x'],data['y'],slot=slot,round_id=round_id,training=cfg)
                update=quantize(delta,committee.policy)
            elif cfg['mode']=='fmnist-lenet5':
                with np.load(directory/'train.npz',allow_pickle=False) as data:
                    labels=data['y']
                    if cfg.get('test_poisoning') and slot in cfg['test_poisoning']['malicious_slots'] and cfg['test_poisoning']['case']=='label-flip':
                        from .seed_mpc_poisoning_fixture import flip_labels
                        labels=flip_labels(labels)
                    delta,training_meta=train_lenet(model,data['x'],labels,seed=cfg['seed'],slot=slot,round_id=round_id,
                        epochs=cfg['epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'],
                        momentum=cfg['momentum'],weight_decay=cfg['weight_decay'])
                update=quantize(delta,committee.policy)
                if cfg.get('test_poisoning') and slot in cfg['test_poisoning']['malicious_slots']:
                    from .seed_mpc_poisoning_fixture import attack
                    update=attack(np.asarray(update,dtype=np.int64),cfg['test_poisoning']['case'],committee.policy).tolist()
            else: raise ProtocolError('unsupported training workload')
            training_seconds=time.monotonic()-training_started
            masking_started=time.monotonic()
            if deployment.get('mask_mode', LEGACY_MASK_MODE) == MASK_MODE:
                masks=combined_mask([bytes.fromhex(seed) for seed in private['component_seeds']],
                    committee.registrations[slot]['body'], round_id, committee.policy.dimension, committee.policy.word_bits)
                if cfg['mode'] not in ('fixture','scale-fixture','dropout-fixture') and not cfg.get('test_poisoning'):
                    committee.policy.validate_update(update)
                wire=[(v+m)%committee.policy.modulus for v,m in zip(update,masks,strict=True)]
            else:
                key=bytes.fromhex(private['seed_key'])
            if deployment.get('mask_mode', LEGACY_MASK_MODE) != MASK_MODE and (cfg['mode'] in ('fixture','scale-fixture','dropout-fixture') or cfg.get('test_poisoning')):
                # Deliberately adversarial public fixture may exceed B/norm.
                wire=[(v+m)%committee.policy.modulus for v,m in zip(update,mask_words(key,round_id,committee.policy.dimension),strict=True)]
            elif deployment.get('mask_mode', LEGACY_MASK_MODE) != MASK_MODE:
                wire=encode_update(committee.policy,key,round_id,update)
            packets=[]
            for offset in range(0,committee.policy.dimension,32):
                packets.append(identity.sign(rc.payload(committee.policy,client_id=identity.name,
                    key_handle=committee.handles[slot],values=list(wire[offset:offset+32]),offset=offset)))
            # Test-only local audit, never sent via Flower or aggregator RPC.
            if private.get('test_audit'):
                audit=directory/'audit'; audit.mkdir(exist_ok=True)
                body={'update':update,'model_hash':rc.model_hash}
                if training_meta is not None: body['training']=training_meta
                write_private(audit/f'round-{round_id}.json',body)
                if deployment.get('communication_meter'):
                    write_private(directory/f'timing-round-{round_id}.json',
                        {'round':round_id,'training_and_quantization_seconds':training_seconds,
                         'masking_and_signing_seconds':time.monotonic()-masking_started,
                         'scope':'trusted local test counter; includes data load; excludes dropout wait/synchronization'})
            calls.cache(round_id,context_hash,packets)
    finally: calls.close()
    if fault=='partial': packets=packets[:-1]
    return Message(RecordDict({'wire':ConfigRecord({'envelopes':canonical(packets).decode()})}),reply_to=message)


@app.query('commit')
def commit(message:Message,context:Context):
    slot,directory,private,deployment,committee,identity=local(context)
    expected={'chain','model'} if committee.snapshot_version==2 else {'decision','model'}
    if set(message.content)!=expected: raise ProtocolError('invalid commit request')
    if committee.snapshot_version==2:
        round_id=message.content['chain']['round']
        if deployment.get('test_dropout_schedule',{}).get(str(round_id),{}).get(identity.name,{}).get('commit')=='drop':
            return Message(error=Error(901,'test client unavailable after upload'),reply_to=message)
    else: decision=json.loads(message.content['decision']['json'])
    state=client_state(directory,committee,deployment['initial_model'])
    try:
        model=message.content['model'].to_numpy_ndarrays()
        if len(model)!=1: raise ProtocolError('one commit model array required')
        if committee.snapshot_version==2:
            before=state.head(); applied=synchronize(state,json.loads(message.content['chain']['json']),model[0],round_id)
            sync_trace(directory,private,'commit',round_id,before,state.head(),applied)
        else: applied=accept_decision(state,decision,model[0])
        ack_body={'protocol':'seed-mpc-client-head-v2' if committee.snapshot_version==2 else 'seed-mpc-client-commit-v1','session_id':committee.session_id,
            'round_id':state.head()['round'],'decision':state.head()['decision'],'model_hash':digest(state.head()['model']),
        }
        if committee.snapshot_version==1: ack_body['applied']=applied
        ack=identity.sign(ack_body)
    finally: state.ledger.close()
    return Message(RecordDict({'ack':ConfigRecord({'envelope':canonical(ack).decode()})}),reply_to=message)


@app.query('head')
def head_message(message:Message,context:Context):
    _,directory,_,deployment,committee,identity=local(context)
    if committee.snapshot_version!=2 or set(message.content)!={'challenge'}:
        raise ProtocolError('invalid head query')
    challenge=message.content['challenge']
    if (set(challenge)!={'session_id','nonce'} or challenge['session_id']!=committee.session_id
            or type(challenge['nonce']) is not str or len(challenge['nonce'])!=64
            or any(c not in '0123456789abcdef' for c in challenge['nonce'])):
        raise ProtocolError('head query context differs')
    state=client_state(directory,committee,deployment['initial_model'])
    try:
        head=state.head()
        body={'protocol':'seed-mpc-client-head-proof-v1','session_id':committee.session_id,
              'node_id':context.node_id,'nonce':challenge['nonce'],'round_id':head['round'],
              'decision':head['decision'],'model_hash':digest(head['model'])}
        packet=identity.sign(body)
    finally: state.ledger.close()
    return Message(RecordDict({'ack':ConfigRecord({'envelope':canonical(packet).decode()})}),reply_to=message)


def provision(directory,preparation,slot,*,test_audit=False):
    """Called by local bootstrap in a CLIENT subprocess, never by ServerApp."""
    if type(test_audit) is not bool: raise ProtocolError('invalid trusted audit mode')
    client_count=preparation.get('client_count',4)
    if type(client_count) is not int or client_count<1 or type(slot) is not int or not 0<=slot<client_count:
        raise ProtocolError('client provisioning slot outside roster')
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    if any(directory.iterdir()): raise ProtocolError('client provisioning requires empty directory')
    identity=Identity.generate(f'C{slot}'); key=secrets.token_bytes(16)
    version=preparation.get('snapshot_version',1)
    if type(version) is not int or version not in (1,2): raise ProtocolError('invalid registration version')
    body={'protocol':f'seed-mpc-registration-v{version}','session_id':preparation['session_id'],'committee_epoch':1,
          'client_id':identity.name,'slot':slot,'key_handle':secrets.token_hex(16),
          'policy_hash':preparation['policy_hash'],'execution_hash':preparation['execution_hash']}
    mask_mode=preparation.get('mask_mode', LEGACY_MASK_MODE)
    if mask_mode not in (MASK_MODE, LEGACY_MASK_MODE): raise ProtocolError('unknown mask mode')
    secret={'identity':identity.private(),'installation':preparation['installation'],'test_audit':test_audit,
            'mask_mode':mask_mode}
    if preparation.get('registration_transport'):
        secret['registration_transport']=preparation['registration_transport']
    seed_input={'client_id':slot,'registration_digest':digest(body)}
    if mask_mode==MASK_MODE:
        seeds=[secrets.token_bytes(16) for _ in range(4)]
        secret['component_seeds']=seed_input['component_seeds']=[seed.hex() for seed in seeds]
        packets=directory/'component-packets'; packets.mkdir(mode=0o700)
        for party in range(4):
            packet=seed_packet(identity,seeds,body,party,preparation['aggregator_public'][f'A{party}'])
            write_private(packets/f'A{party}.json',packet)
    else:
        secret['seed_key']=seed_input['seed_key']=key.hex()
    write_private(directory/'client.json',secret)
    write_private(directory/'seed-input.json',seed_input)
    (directory/'public-registration.json').write_bytes(canonical({'public':identity.public(),'envelope':identity.sign(body)}))


def pin(directory,deployment_file):
    deployment,committee=load_deployment(deployment_file)
    private=json.loads((directory/'client.json').read_text()); identity=Identity.from_private(private['identity'])
    if identity.public()!=committee.registry[identity.name]: raise ProtocolError('pin identity mismatch')
    state=CoordinatorState(committee,directory/'model.sqlite',deployment['initial_model'],create=True); state.ledger.close()
    calls=TrainingCalls(directory/'calls.sqlite',create=True); calls.close()
    private.update(deployment=str(deployment_file),deployment_sha256=hashlib.sha256(deployment_file.read_bytes()).hexdigest())
    # Replace only this client's private bootstrap file; retain mode 0600.
    temporary=directory/'client-pinned.json'; write_private(temporary,private); os.replace(temporary,directory/'client.json')


def main():
    parser=argparse.ArgumentParser(description='Local client-only provisioning')
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--preparation',type=Path)
    parser.add_argument('--slot',type=int)
    parser.add_argument('--pin',type=Path)
    parser.add_argument('--trusted-test-audit',action='store_true',help='explicit local test oracle only; off by default')
    args=parser.parse_args()
    if args.pin: pin(args.directory,args.pin)
    else:
        if args.preparation is None or args.slot is None: parser.error('preparation and slot required')
        provision(args.directory,json.loads(args.preparation.read_text()),args.slot,test_audit=args.trusted_test_audit)


if __name__=='__main__': main()
