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

import numpy as np
from flwr.app import ConfigRecord, Context, Message, RecordDict
from flwr.clientapp import ClientApp

from .crypto import Identity, ProtocolError, canonical, digest
from .seed_mpc_committee import CoordinatorState
from .seed_mpc_session import load_deployment
from .seed_mpc_training import fixture_update,scale_fixture_update,quantize,train
from .seed_mpc_wire import RoundContext,encode_update,mask_words

app=ClientApp()


def write_private(path,body):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream: stream.write(canonical(body))


def local(context):
    slot=int(context.node_config['partition-id'])
    if int(context.node_config['num-partitions'])!=4 or not 0<=slot<4: raise ProtocolError('invalid client partition')
    directory=Path(os.environ['TRUSTLESSFL_SEED_CLIENT_ROOT'])/f'C{slot}'
    private=json.loads((directory/'client.json').read_text())
    deployment_file=Path(private['deployment'])
    if hashlib.sha256(deployment_file.read_bytes()).hexdigest()!=private['deployment_sha256']:
        raise ProtocolError('client deployment changed')
    deployment,committee=load_deployment(deployment_file)
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


@app.query('identity')
def identity_message(message:Message,context:Context):
    slot,_,_,_,committee,_=local(context)
    return Message(RecordDict({'registration':ConfigRecord({'envelope':canonical(committee.registrations[slot]).decode()})}),reply_to=message)


@app.query('register')
def register(message:Message,context:Context):
    slot,directory,private,deployment,committee,_=local(context)
    marker=directory/'registration-started'
    if not marker.exists():
        # The durable one-shot marker precedes starting the private channel.
        write_private(marker,{'session':committee.session_id,'slot':slot})
        log=(directory/'client.log').open('x')
        try:
            process=subprocess.Popen([sys.executable,'-m','trustlessfl.seed_mpc_external_client',
                '--mp-spdz-dir',private['installation'],'--private-input',str(directory/'seed-input.json'),
                '--config',str(Path(deployment['workspace'])/'policy.json'),
                '--output',str(directory/'registration-submitted.json')],cwd=directory,
                env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1])},
                stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            write_private(directory/'registration-process.json',{'pid':process.pid})
        finally: log.close()
    # Do not wait here: native registration first accepts all four clients,
    # and the Flower runtime can schedule them through a single Ray worker.
    return Message(RecordDict({'registration':ConfigRecord({'client_id':f'C{slot}','launched':True})}),reply_to=message)


@app.train()
def train_message(message:Message,context:Context):
    slot,directory,private,deployment,committee,identity=local(context)
    if set(message.content)!= {'model','config'}: raise ProtocolError('invalid train request')
    arrays=message.content['model'].to_numpy_ndarrays()
    if len(arrays)!=1: raise ProtocolError('one canonical model array required')
    model=arrays[0]; round_id=message.content['config']['round']
    state=client_state(directory,committee,deployment['initial_model'])
    try: head=state.head(); require_certified_model(model,head,round_id)
    finally: state.ledger.close()
    rc=RoundContext(committee.session_id,committee.epoch,round_id,digest(head['model']),committee.policy.policy_hash)
    calls=TrainingCalls(directory/'calls.sqlite')
    try:
        context_hash=digest({'context':rc.__dict__,'parent':head['decision'],'training':deployment['training']})
        packets=calls.reserve(round_id,context_hash)
        if packets is None:
            cfg=deployment['training']
            if cfg['mode']=='fixture': update=fixture_update(slot,round_id,committee.policy.dimension)
            elif cfg['mode']=='scale-fixture': update=scale_fixture_update(slot,round_id,committee.policy.dimension)
            elif cfg['mode']=='tiny-fmnist':
                with np.load(directory/'train.npz',allow_pickle=False) as data:
                    delta=train(model,data['x'],data['y'],seed=cfg['seed'],slot=slot,round_id=round_id,
                        epochs=cfg['epochs'],batch_size=cfg['batch_size'],learning_rate=cfg['learning_rate'])
                update=quantize(delta,committee.policy)
            else: raise ProtocolError('unsupported training workload')
            key=bytes.fromhex(private['seed_key'])
            if cfg['mode'] in ('fixture','scale-fixture'):
                # Deliberately adversarial public fixture may exceed B/norm.
                wire=[(v+m)%committee.policy.modulus for v,m in zip(update,mask_words(key,round_id,committee.policy.dimension),strict=True)]
            else: wire=encode_update(committee.policy,key,round_id,update)
            packets=[]
            for offset in range(0,committee.policy.dimension,32):
                packets.append(identity.sign(rc.payload(committee.policy,client_id=identity.name,
                    key_handle=committee.handles[slot],values=list(wire[offset:offset+32]),offset=offset)))
            # Test-only local audit, never sent via Flower or aggregator RPC.
            if private.get('test_audit'):
                audit=directory/'audit'; audit.mkdir(exist_ok=True)
                write_private(audit/f'round-{round_id}.json',{'update':update,'model_hash':rc.model_hash})
            calls.cache(round_id,context_hash,packets)
    finally: calls.close()
    return Message(RecordDict({'wire':ConfigRecord({'envelopes':canonical(packets).decode()})}),reply_to=message)


@app.query('commit')
def commit(message:Message,context:Context):
    slot,directory,_,deployment,committee,identity=local(context)
    if set(message.content)!= {'decision','model'}: raise ProtocolError('invalid commit request')
    decision=json.loads(message.content['decision']['json'])
    state=client_state(directory,committee,deployment['initial_model'])
    try:
        model=message.content['model'].to_numpy_ndarrays()
        if len(model)!=1: raise ProtocolError('one commit model array required')
        applied=accept_decision(state,decision,model[0])
        ack=identity.sign({'protocol':'seed-mpc-client-commit-v1','session_id':committee.session_id,
            'round_id':state.head()['round'],'decision':state.head()['decision'],'model_hash':digest(state.head()['model']),
            'applied':applied})
    finally: state.ledger.close()
    return Message(RecordDict({'ack':ConfigRecord({'envelope':canonical(ack).decode()})}),reply_to=message)


def provision(directory,preparation,slot):
    """Called by local bootstrap in a CLIENT subprocess, never by ServerApp."""
    directory.mkdir(parents=True,exist_ok=False,mode=0o700)
    identity=Identity.generate(f'C{slot}'); key=secrets.token_bytes(16)
    body={'protocol':'seed-mpc-registration-v1','session_id':preparation['session_id'],'committee_epoch':1,
          'client_id':identity.name,'slot':slot,'key_handle':secrets.token_hex(16),
          'policy_hash':preparation['policy_hash'],'execution_hash':preparation['execution_hash']}
    write_private(directory/'client.json',{'identity':identity.private(),'seed_key':key.hex(),
        'installation':preparation['installation'],'test_audit':True})
    write_private(directory/'seed-input.json',{'client_id':slot,'seed_key':key.hex(),'registration_digest':digest(body)})
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
    parser.add_argument('--slot',type=int,choices=range(4))
    parser.add_argument('--pin',type=Path)
    args=parser.parse_args()
    if args.pin: pin(args.directory,args.pin)
    else:
        if args.preparation is None or args.slot is None: parser.error('preparation and slot required')
        provision(args.directory,json.loads(args.preparation.read_text()),args.slot)


if __name__=='__main__': main()
