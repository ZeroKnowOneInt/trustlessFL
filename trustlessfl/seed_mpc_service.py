"""One local aggregator: own signing key, ledger, FIFO and native process.

Local functional deployment only. No remote log/checked flag is an RPC input.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from itertools import islice

from .crypto import Identity, ProtocolError, canonical, digest
from .seed_mpc_committee import AggregatorGuard, digest_words,require_hash
from .seed_mpc_native import NativeCheckpointReader
from .seed_mpc_session import load_deployment
from .seed_mpc_resources import read_resources
from .seed_mpc_backend import native_command,validate_pin
from .seed_mpc_wire import RoundContext
from .seed_mpc_prss import MASK_MODE, LEGACY_MASK_MODE, open_seed_packet, private_round_words, require_mask_implementation, registration_words
from .seed_mpc_meter import native_partition,ApplicationMeter


def pipe_write(fd,values,timeout):
    iterator=iter(values);deadline=time.monotonic()+timeout
    while True:
        batch=list(islice(iterator,4096))
        if not batch:return
        data=memoryview(('\n'.join(map(str,batch))+'\n').encode());offset=0
        while offset<len(data):
            remaining=deadline-time.monotonic()
            if remaining<=0: raise ProtocolError('native pipe timeout')
            if not select.select([], [fd], [], min(remaining,.2))[1]: continue
            try:offset+=os.write(fd,data[offset:])
            except BlockingIOError:continue


def prepared_manifest(guard,round_id,input_hash):
    """Resolve ONLY this party's durable, previously validated input material."""
    if type(round_id) is not int or round_id<1:raise ProtocolError('invalid material round')
    require_hash(input_hash)
    row=guard.ledger.row(round_id)
    if not row or row['input_hash']!=input_hash:raise ProtocolError('unknown/conflicting prepared material')
    manifest=json.loads(row['manifest'])
    if digest(manifest)!=input_hash or guard.committee.check_manifest(manifest).round_id!=round_id:
        raise ProtocolError('stored material integrity differs')
    return manifest


class LocalAggregator:
    def __init__(self,deployment_file,private_file,slot):
        self.deployment,self.committee=load_deployment(deployment_file)
        self.slot=slot; d=self.deployment
        self.meter=ApplicationMeter() if d.get('communication_meter') else None
        private=json.loads(Path(private_file).read_text())
        if hashlib.sha256(Path(deployment_file).read_bytes()).hexdigest()!=private['deployment_sha256']:
            raise ProtocolError('aggregator deployment changed')
        self.actor=Path(private['actor']); self.actor.mkdir(exist_ok=True)
        identity=Identity.from_private(private['identity'])
        if identity.name!=self.committee.aggregators[slot]: raise ProtocolError('service slot differs')
        workspace=Path(d['workspace']); binary=Path(d['native_binary'])
        config=json.loads((workspace/'policy.json').read_text())
        if config.get('snapshot_version',1)!=self.committee.snapshot_version:
            raise ProtocolError('native/snapshot version differs')
        if config.get('collection_window_ms',60000)!=self.committee.collection_window_ms:
            raise ProtocolError('native/collection window differs')
        if config.get('communication_meter',False)!=d.get('communication_meter',False):
            raise ProtocolError('native/communication meter differs')
        if self.committee.snapshot_version==2 or 'backend_pin' in d:
            if 'backend_pin' not in d: raise ProtocolError('v2 backend pin missing')
            validate_pin(binary.parent,d['backend_pin'])
            if config.get('backend_pin_hash')!=(d.get('backend_contract_hash') if d.get('distributed_session') else digest(d['backend_pin'])):
                raise ProtocolError('native/backend pin binding differs')
        if (hashlib.sha256((workspace/'Programs/Circuits/aes_128.txt').read_bytes()).hexdigest()!=d['aes_sha256']
                or hashlib.sha256((workspace/'policy.json').read_bytes()).hexdigest()!=d['config_sha256']):
            raise ProtocolError('native circuit/config changed')
        if hashlib.sha256(binary.read_bytes()).hexdigest()!=d['binary_sha256']:
            raise ProtocolError('native binary changed')
        for relative,expected in d['artifacts'].items():
            if hashlib.sha256((workspace/'Programs'/relative).read_bytes()).hexdigest()!=expected:
                raise ProtocolError('compiled artifact changed')
        self.guard=AggregatorGuard(self.committee,identity,self.actor/'rounds.sqlite',d['initial_model'],create=True)
        self.public_chunk_blocks=config['chunk_blocks']
        self.program=d['program']; programs=self.actor/'Programs'
        programs.unlink(); programs.mkdir()
        for folder in ['Bytecode','Schedules','Circuits']:
            (programs/folder).symlink_to(workspace/'Programs'/folder,target_is_directory=True)
        public=programs/'Public-Input'; public.mkdir(); fifo=public/self.program; os.mkfifo(fifo,0o600)
        self.fd=os.open(fifo,os.O_RDWR|os.O_NONBLOCK)
        self.component_fd=None
        self.component_pool=None
        if d.get('mask_mode',LEGACY_MASK_MODE) not in (MASK_MODE,LEGACY_MASK_MODE):
            raise ProtocolError('unknown mask mode')
        self.component_mode=d.get('mask_mode',LEGACY_MASK_MODE)==MASK_MODE
        if config.get('mask_mode',LEGACY_MASK_MODE)!=d.get('mask_mode',LEGACY_MASK_MODE):
            raise ProtocolError('native/mask mode differs')
        if self.component_mode:
            require_mask_implementation(config.get('mask_source_sha256'))
            if config['mask_source_sha256']!=d.get('mask_source_sha256'):
                raise ProtocolError('native/local mask binding differs')
            self.component_config=config
            self.component_seeds=[open_seed_packet(json.loads((self.actor/'seed-packets'/f'{name}.json').read_text()),
                identity,self.committee.registry,registration['body'],slot)
                for name,registration in zip(self.committee.clients,self.committee.registrations,strict=True)]
            path=self.actor/'Player-Data'/f'Input-P{slot}-0'
            os.mkfifo(path,0o600)
            self.component_fd=os.open(path,os.O_RDWR|os.O_NONBLOCK)
            pipe_write(self.component_fd,registration_words(self.component_seeds,slot),d['timeout'])
            self.component_pool=ThreadPoolExecutor(max_workers=1,thread_name_prefix='local-mask-input')
        self.log=(self.actor/'native.log').open('x')
        self.started=time.monotonic()
        self.process=subprocess.Popen(['/usr/bin/time','-v','-o',str(self.actor/'native-resource.txt'),
            *native_command(binary,d['party_port'],slot,self.program,**({'ip_file':self.actor/'party-hosts.txt'} if d.get('distributed_session') else {}))],cwd=self.actor,
            stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
        self.reader=NativeCheckpointReader(self.guard,self.process,self.actor/'native.log')
        tags=[v for packet in self.committee.registrations for v in digest_words(digest(packet['body']))]
        pipe_write(self.fd,([config['client_port']] if config.get('runtime_client_port') else [])+tags,d['timeout'])

    def action(self,action,body):
        if action=='head': return self.guard.head()
        if action=='ready':
            if not self.reader.registration_checked: self.reader.wait_registration(self.deployment['timeout'])
            return {'registration_checked':True,'aggregator':self.guard.identity.name}
        if not self.reader.registration_checked: raise ProtocolError('registration not checked')
        if action in ('execute-reference','decide-reference'):
            certificate='input_certificate' if action=='execute-reference' else 'result_certificate'
            if set(body)!={'round_id','input_hash',certificate}:raise ProtocolError('invalid material reference')
            manifest=prepared_manifest(self.guard,body['round_id'],body['input_hash'])
            body={'manifest':manifest,certificate:body[certificate]}
            action='execute' if action=='execute-reference' else 'decide'
        if action=='collect-open':
            if set(body)!={'context','parent_decision'}: raise ProtocolError('invalid collection request')
            return self.guard.open_collection(RoundContext(**body['context']),body['parent_decision'])
        if action=='collect':
            if set(body)!={'submission'}: raise ProtocolError('invalid submission request')
            return self.guard.receive(body['submission'])
        if action in ('submission','receipt'):
            if set(body)!={'collection_hash','client_id'}: raise ProtocolError('invalid receipt query')
            stored=self.guard.fetch_submission(body['collection_hash'],body['client_id'])
            return stored if action=='submission' or stored is None else stored['receipt']
        if action=='prepare': return self.guard.prepare(body['manifest'],body.get('receipt_certificates'))
        if action=='execute':
            manifest=body['manifest']; self.guard.reserve(manifest,body['input_certificate'])
            task=None
            if self.component_mode:
                values=private_round_words(self.component_seeds,[r['body'] for r in self.committee.registrations],
                    self.slot,manifest['context']['round_id'],self.committee.policy.dimension,
                    self.component_config['chunk_blocks'],self.committee.policy.word_bits)
                task=self.component_pool.submit(pipe_write,self.component_fd,values,self.deployment['timeout'])
            pipe_write(self.fd,self.committee.runtime_round(manifest,chunk_blocks=self.public_chunk_blocks),self.deployment['timeout'])
            if task: task.result(timeout=self.deployment['timeout'])
            return self.reader.vote(manifest,self.deployment['timeout'])
        if action=='decide': return self.guard.accept(body['manifest'],body['result_certificate'])
        if action=='finish':
            if self.guard.head()['round']!=self.deployment['rounds']: raise ProtocolError('incomplete session')
            if self.process.wait(timeout=30)!=0: raise ProtocolError('native exit failed')
            text=(self.actor/'native.log').read_text()
            sent=re.search(r'Global data sent = ([0-9.]+) MB',text)
            return {'head':self.guard.head(),'native_exit':0,'internal_mb':float(sent[1]) if sent else None,
                    **({'communication':native_partition(text,self.deployment['rounds'])} if self.deployment.get('communication_meter') else {}),
                    'resources':read_resources(self.actor/'native-resource.txt'),
                    'session_wall_seconds':round(time.monotonic()-self.started,3)}
        raise ProtocolError('unknown aggregator action')

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid,signal.SIGTERM)
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: os.killpg(self.process.pid,signal.SIGKILL); self.process.wait()
        if self.component_fd is not None:
            os.close(self.component_fd)
            self.component_pool.shutdown(wait=True,cancel_futures=True)
        os.close(self.fd); self.log.close(); self.guard.ledger.close()
        if self.meter:
            (self.actor/'rpc-communication.json').write_bytes(canonical(self.meter.report()))


def request_size_limit(policy):
    """Budget for the registered model/roster's signed JSON, never unbounded.

    Default 32-coordinate frames need roughly 24 bytes per coordinate including
    signatures/context. Leave headroom for receipts and escaping, cap at 512 MiB.
    This is a transport budget, not a relaxation of any input/QC/MPC check.
    """
    return min(512*1024*1024,max(16*1024*1024,
        128*1024+policy.max_clients*(policy.dimension*64+8192)))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment',type=Path,required=True)
    parser.add_argument('--private',type=Path,required=True)
    parser.add_argument('--slot',type=int,choices=range(4),required=True)
    args=parser.parse_args()
    deployment,committee=load_deployment(args.deployment)
    request_limit=request_size_limit(committee.policy)
    owner=None
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            action=self.path.lstrip('/')
            if deployment.get('distributed_session'):
                from .seed_mpc_distributed import authorize_rpc_peer
                if not authorize_rpc_peer(self.connection,deployment):
                    self.send_error(403); return
            scope=('bootstrap' if action=='head' else 'setup' if action=='ready' else
                   'shutdown' if action=='finish' else f'round-{owner.guard.head()["round"]+1}')
            try:
                length=int(self.headers.get('Content-Length',0))
                if not 0<length<=request_limit: raise ProtocolError('invalid request size')
                raw=self.rfile.read(length)
                if owner.meter: owner.meter.record('aggregator-rpc-json','received',action,len(raw),scope=scope)
                body=json.loads(raw); result=owner.action(action,body)
                data=canonical({'result':result}); self.send_response(200)
            except Exception:
                # Do not echo client inputs, keys, pending outputs or exception values.
                data=canonical({'error':'protocol rejected'}); self.send_response(409)
            self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data)))
            self.end_headers(); self.wfile.write(data)
            if owner.meter: owner.meter.record('aggregator-rpc-json','sent',action,len(data),scope=scope)
        def log_message(self,*args): pass
    port=int(deployment['services'][args.slot].rsplit(':',1)[1])
    if deployment.get('distributed_session'):
        from .seed_mpc_distributed import server_tls,DistributedHTTPServer
        server=DistributedHTTPServer((deployment.get('rpc_bind','0.0.0.0'),port),Handler,server_tls(deployment,args.slot))
    else:
        server=HTTPServer(('127.0.0.1',port),Handler)
    def stop(*_): raise KeyboardInterrupt
    try:
        # Reserve RPC before native connections can claim an ephemeral port.
        # A bind failure must not launch an orphan native process.
        owner=LocalAggregator(args.deployment,args.private,args.slot)
        signal.signal(signal.SIGTERM,stop)
        server.serve_forever(poll_interval=.1)
    except KeyboardInterrupt: pass
    finally:
        server.server_close()
        if owner is not None:owner.close()


if __name__=='__main__': main()
